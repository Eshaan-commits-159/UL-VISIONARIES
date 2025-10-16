#!/usr/bin/env python3
"""
Bank Transfer System
====================
Secure bank transfer simulation with safe JSON storage and schema validation.

Usage: python bank_transfer.py
"""

import hashlib
import hmac
import json
import os
import subprocess
import time
import secrets
import threading
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from jsonschema import validate, ValidationError

# money precision
getcontext().prec = 28

DATA_DIR = "data"  # all saves/loads confined here
ALLOWED_EXT = ".json"
SESSION_TTL_SECONDS = 3600  # 1 hour session TTL


# --- PIN hashing helpers ---
def make_pin_hash(pin, iterations=100_000):
    """Return (salt_hex, dk_hex) using pbkdf2_hmac."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations)
    return salt.hex(), dk.hex()


def verify_pin(pin, salt_hex, dk_hex, iterations=100_000):
    """Verify pin against stored hex salt/hash using constant-time compare."""
    try:
        salt = bytes.fromhex(salt_hex)
        stored_dk = bytes.fromhex(dk_hex)
    except Exception:
        return False
    cand = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations)
    return hmac.compare_digest(cand, stored_dk)


# --- JSON Schema ---
account_schema = {
    "type": "object",
    "properties": {
        "balance": {"type": "string"},  # Decimal stored as string
        "pin_salt": {"type": "string"},
        "pin_hash": {"type": "string"},
        "role": {"type": "string"}
    },
    "required": ["balance", "pin_salt", "pin_hash", "role"]
}

transaction_schema = {
    "type": "object",
    "properties": {
        "from": {"type": "string"},
        "to": {"type": "string"},
        "amount": {"type": "string"},
        "timestamp": {"type": "string"},
        "tx_id": {"type": "string"}
    },
    "required": ["from", "to", "amount", "timestamp", "tx_id"]
}

state_schema = {
    "type": "object",
    "properties": {
        "accounts": {"type": "object", "additionalProperties": account_schema},
        "transactions": {"type": "array", "items": transaction_schema}
    },
    "required": ["accounts", "transactions"]
}


class BankTransferSystem:
    def __init__(self):
        # store balances as Decimal, store pin_salt & pin_hash as hex strings
        self.accounts = {}
        initial = {
            "alice": {"balance": "1000.00", "pin": "1234"},
            "bob": {"balance": "500.00", "pin": "5678"},
            "charlie": {"balance": "2000.00", "pin": "9999"},
            "admin": {"balance": "1000000.00", "pin": "0000"}
        }
        for name, info in initial.items():
            salt_hex, dk_hex = make_pin_hash(info["pin"])
            self.accounts[name] = {
                "balance": Decimal(info["balance"]).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN),
                "pin_salt": salt_hex,
                "pin_hash": dk_hex,
                "role": "admin" if name == "admin" else "user"
            }

        self.logged_in_user = None
        self.session_token = None
        self.session_expiry = None
        self.transaction_log = []
        self._lock = threading.Lock()  # protects balance updates and transaction_log

    # small helper to check current session (presence + expiry)
    def check_session(self):
        if self.logged_in_user is None or self.session_token is None or self.session_expiry is None:
            return False
        if datetime.utcnow() > self.session_expiry:
            # expire session
            self.logged_in_user = None
            self.session_token = None
            self.session_expiry = None
            return False
        return True

    def authenticate(self, username, pin):
        """Authenticate user; sets session_token and expiry on success."""
        # constant small delay to reduce timing leaks
        time.sleep(0.05)
        if username not in self.accounts:
            return False
        acc = self.accounts[username]
        if verify_pin(pin, acc.get("pin_salt", ""), acc.get("pin_hash", "")):
            self.logged_in_user = username
            self.session_token = secrets.token_hex(32)
            self.session_expiry = datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)
            return True
        return False

    def _valid_session_token(self, token):
        """Check provided token matches current session token and session not expired."""
        if not self.check_session():
            return False
        if token is None:
            return False
        return hmac.compare_digest(token, self.session_token)

    def transfer_money(self, from_account, to_account, amount, auth_token=None):
        """
        Performs an authenticated, authorized transfer.
        """
        # validate accounts early
        if from_account not in self.accounts or to_account not in self.accounts:
            return False, "Invalid account"

        # session & token validation
        if not self._valid_session_token(auth_token):
            return False, "Invalid or expired session token"

        caller = self.logged_in_user
        caller_role = self.accounts.get(caller, {}).get("role", "user")
        if caller_role != "admin" and caller != from_account:
            return False, "Not authorized to withdraw from this account"

        # convert amount to Decimal safely
        try:
            dec_amount = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        except Exception:
            return False, "Invalid amount format"

        if dec_amount <= Decimal("0.00"):
            return False, "Invalid Transfer Amount"

        # atomic update with lock
        with self._lock:
            from_bal = self.accounts[from_account]["balance"]
            if from_bal < dec_amount:
                return False, "Insufficient funds"

            self.accounts[from_account]["balance"] = (from_bal - dec_amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
            to_bal = self.accounts[to_account]["balance"]
            self.accounts[to_account]["balance"] = (to_bal + dec_amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)

            transaction = {
                "from": from_account,
                "to": to_account,
                "amount": str(dec_amount),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tx_id": secrets.token_hex(10)
            }
            self.transaction_log.append(transaction)

        return True, "Transfer successful"

    # PATCHED METHOD: Requires auth_token validation
    def get_balance(self, username, auth_token=None):
        """Get balance of a user's account, requires a valid session token."""
        # Check if a session exists AND if the provided token is valid
        if not self._valid_session_token(auth_token):
            return "Please log in with a valid session token"
        
        # Authorization check: must be the user themselves or an admin
        if self.logged_in_user != username and self.logged_in_user != "admin":
            return "Access denied"
            
        if username not in self.accounts:
            return "Account not found"
            
        return self.accounts[username]["balance"]

    # --- safer save/load with jsonschema ---
    def _sanitize_filename(self, filename):
        if not filename or filename.strip() == "":
            raise ValueError("Empty filename")
        # disallow path separators and parent refs
        if os.path.sep in filename or (os.path.altsep and os.path.altsep in filename):
            raise ValueError("Invalid filename (contains path separators)")
        if ".." in filename:
            raise ValueError("Invalid filename")
        base, ext = os.path.splitext(filename)
        if ext.lower() != ALLOWED_EXT:
            raise ValueError(f"Only {ALLOWED_EXT} files allowed")
        return os.path.basename(base + ext)

    def _ensure_data_dir(self):
        os.makedirs(DATA_DIR, exist_ok=True)

    def save_state(self, filename):
        try:
            safe_name = self._sanitize_filename(filename)
        except ValueError as e:
            return False, f"Invalid filename: {e}"

        self._ensure_data_dir()
        path = os.path.abspath(os.path.join(DATA_DIR, safe_name))
        data_dir_abs = os.path.abspath(DATA_DIR) + os.path.sep
        if not path.startswith(data_dir_abs):
            return False, "Invalid path"

        serial_accounts = {}
        for name, acc in self.accounts.items():
            serial_accounts[name] = {
                "balance": str(acc["balance"]),
                "pin_salt": acc["pin_salt"],
                "pin_hash": acc["pin_hash"],
                "role": acc.get("role", "user")
            }

        data = {
            "accounts": serial_accounts,
            "transactions": self.transaction_log
        }

        # validate before saving
        try:
            validate(instance=data, schema=state_schema)
        except ValidationError as e:
            return False, f"Data schema validation failed: {e.message}"

        try:
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            return True, f"State saved to {path}"
        except Exception as e:
            return False, f"Save failed: {e}"

    def load_state(self, filename):
        try:
            safe_name = self._sanitize_filename(filename)
        except ValueError as e:
            return False, f"Invalid filename: {e}"

        self._ensure_data_dir()
        path = os.path.abspath(os.path.join(DATA_DIR, safe_name))
        data_dir_abs = os.path.abspath(DATA_DIR) + os.path.sep
        if not path.startswith(data_dir_abs):
            return False, "Invalid path"

        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            return False, "File not found"
        except json.JSONDecodeError:
            return False, "Invalid JSON file"
        except Exception as e:
            return False, f"Load failed: {e}"

        # validate JSON schema
        try:
            validate(instance=data, schema=state_schema)
        except ValidationError as e:
            return False, f"JSON schema validation failed: {e.message}"

        # Convert balances to Decimal
        new_accounts = {}
        for name, acc in data["accounts"].items():
            try:
                bal = Decimal(acc["balance"]).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
            except Exception:
                return False, f"Invalid balance for account {name}"
            new_accounts[name] = {
                "balance": bal,
                "pin_salt": acc["pin_salt"],
                "pin_hash": acc["pin_hash"],
                "role": acc.get("role", "user")
            }

        self.accounts = new_accounts
        self.transaction_log = data["transactions"]
        return True, f"State loaded from {path}"

    # PATCHED METHOD: Hardened against Command Injection
    def admin_command(self, command):
        """Executes a strictly whitelisted command for admin only."""
        allowed_cmds = {"ls", "whoami", "date"} 
        
        if not self.check_session() or self.logged_in_user != "admin":
            return "Access denied"

        # Split the command into arguments (e.g., 'ls -l' -> ['ls', '-l'])
        args = command.strip().split()
        if not args:
            return "❌ Empty command"
            
        cmd_name = args[0] # The base command is the first argument
        
        if cmd_name not in allowed_cmds:
            return "❌ Command not allowed"
            
        # Specific argument handling for whitelisted commands
        if cmd_name == "ls":
            # For 'ls', specifically enforce listing only the DATA_DIR 
            # and allow only the '-l' option.
            if len(args) > 1 and args[1] not in ('-l', DATA_DIR):
                 return "❌ 'ls' only allows the '-l' option for data directory listing."
            
            # Construct the safe command list explicitly
            safe_args = [cmd_name]
            if '-l' in args:
                 safe_args.append('-l')
            safe_args.append(DATA_DIR) # Force the command to operate on the data directory
            args = safe_args
        
        elif cmd_name in {"whoami", "date"}:
             # These commands must not have arguments
             if len(args) > 1:
                 return f"❌ '{cmd_name}' does not allow arguments"
             args = [cmd_name] # Reset args to ensure no potential shell remnants are run
        
        try:
            # subprocess.run with a list of arguments is the secure way to call external commands
            # It avoids shell interpretation of the arguments.
            result = subprocess.run(args, capture_output=True, text=True, check=True)
            return result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            return f"Command failed with exit code {e.returncode}: {e.stderr}"
        except FileNotFoundError:
            return f"Command not found: {cmd_name}"
        except Exception as e:
            return f"Command failed: {e}"


# --- CLI Interface ---
def main():
    print("=" * 50)
    print("🏦 BANK TRANSFER SYSTEM v3.1 (SECURED) 🏦")
    print("=" * 50)

    bank = BankTransferSystem()

    while True:
        print("=" * 30)
        print("MAIN MENU")
        print("=" * 30)
        print("1. Login")
        print("2. Check Balance")
        print("3. Transfer Money")
        print("4. View Transaction Log")
        print("5. Save Bank State")
        print("6. Load Bank State")
        print("7. Admin Commands")
        print("8. Exit")

        choice = input("Select option (1-8): ").strip()

        if choice == "1":
            username = input("Username: ").strip()
            pin = input("PIN: ").strip()
            if bank.authenticate(username, pin):
                print(f"✅ Welcome {username}! Session token: {bank.session_token}")
            else:
                print("❌ Invalid credentials")

        elif choice == "2":
            # PATCHED: Now requires auth token
            if not bank.logged_in_user:
                print("❌ Please log in first.")
                continue

            auth_token = input("Auth token: ").strip()
            if not auth_token:
                print("❌ Auth token required")
                continue
                
            # Pass auth_token to get_balance
            balance = bank.get_balance(bank.logged_in_user, auth_token) 
            
            try:
                # Assuming success returns a Decimal, and failure returns a string
                if isinstance(balance, Decimal):
                    print(f"Current balance: ${float(balance):.2f}")
                else:
                    print(balance) # Print the error message
            except Exception:
                # Catch case where get_balance returns a string error but is not caught by isinstance
                print(balance)

        elif choice == "3":
            from_acc = input("From account: ").strip()
            to_acc = input("To account: ").strip()
            try:
                amount = float(input("Amount: $").strip())
                auth_token = input("Auth token: ").strip()
                if not auth_token:
                    print("❌ Auth token required")
                    continue

                success, message = bank.transfer_money(from_acc, to_acc, amount, auth_token)
                print(("✅ " if success else "❌ ") + message)
            except ValueError:
                print("❌ Invalid amount")

        elif choice == "4":
            print("--- TRANSACTION LOG ---")
            if not bank.transaction_log:
                print("No transactions found")
            else:
                for i, tx in enumerate(bank.transaction_log, 1):
                    try:
                        amt = float(tx['amount'])
                    except Exception:
                        amt = tx.get('amount', 'N/A')
                    print(f"{i}. {tx['from']} → {tx['to']}: ${amt:.2f} at {tx['timestamp']}")

        elif choice == "5":
            filename = input("Enter filename (must end with .json): ").strip()
            if filename:
                ok, msg = bank.save_state(filename)
                print(("✅ " if ok else "❌ ") + msg)

        elif choice == "6":
            filename = input("Enter filename (must end with .json): ").strip()
            if filename:
                ok, msg = bank.load_state(filename)
                print(("✅ " if ok else "❌ ") + msg)

        elif choice == "7":
            if not bank.check_session() or bank.logged_in_user != "admin":
                print("❌ Admin access required")
                continue

            command = input("Enter command: ").strip()
            if command:
                result = bank.admin_command(command)
                print(f"Command output: \n{result}")

        elif choice == "8":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option. Please choose 1-8.")


if __name__ == "__main__":
    main()

