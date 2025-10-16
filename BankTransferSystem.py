#!/usr/bin/env python3
"""
Bank Transfer System
====================
Simple bank transfer simulation.

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

# money precision
getcontext().prec = 28

DATA_DIR = "data"  # all saves/loads confined here
ALLOWED_EXT = ".json"
SESSION_TTL_SECONDS = 3600  # 1 hour session TTL


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

    def hash_pin(self, pin):
        # kept for compatibility but not used for storage; returns sha256 hex
        return hashlib.sha256(pin.encode()).hexdigest()

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
        - auth_token must match current session token
        - caller must be logged-in and either owner of from_account or admin
        - amount must be positive Decimal
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

            # do update
            self.accounts[from_account]["balance"] = (from_bal - dec_amount).quantize(Decimal("0.01"),
                                                                                      rounding=ROUND_HALF_EVEN)
            to_bal = self.accounts[to_account]["balance"]
            self.accounts[to_account]["balance"] = (to_bal + dec_amount).quantize(Decimal("0.01"),
                                                                                    rounding=ROUND_HALF_EVEN)

            transaction = {
                "from": from_account,
                "to": to_account,
                # store amount as string so JSON preserves exact decimal
                "amount": str(dec_amount),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tx_id": secrets.token_hex(10)
            }
            self.transaction_log.append(transaction)

        return True, "Transfer successful"

    def get_balance(self, username):
        if not self.check_session():
            return "Please log in first"
        if self.logged_in_user != username and self.logged_in_user != "admin":
            return "Access denied"
        return self.accounts[username]["balance"]

    # --- safer save/load (sanitization + simple validation) ---
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

        # prepare serializable accounts: balances -> str, keep pin hex strings
        serial_accounts = {}
        for name, acc in self.accounts.items():
            serial_accounts[name] = {
                "balance": str(acc["balance"]),
                "pin_salt": acc.get("pin_salt"),
                "pin_hash": acc.get("pin_hash"),
                "role": acc.get("role", "user")
            }
        data = {
            "accounts": serial_accounts,
            "transactions": self.transaction_log
        }
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

        # basic validation of structure
        if not isinstance(data, dict) or "accounts" not in data:
            return False, "Invalid state file structure"

        loaded_accounts = data.get("accounts", {})
        # validate accounts format and convert balances back to Decimal
        new_accounts = {}
        for name, acc in loaded_accounts.items():
            if not isinstance(acc, dict) or "balance" not in acc:
                return False, f"Invalid account format for {name}"
            try:
                bal = Decimal(str(acc["balance"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
            except Exception:
                return False, f"Invalid balance for account {name}"
            # ensure pin_salt and pin_hash are present (keep as hex strings)
            pin_salt = acc.get("pin_salt")
            pin_hash = acc.get("pin_hash")
            if not pin_salt or not pin_hash:
                return False, f"Missing pin data for {name}"
            new_accounts[name] = {
                "balance": bal,
                "pin_salt": pin_salt,
                "pin_hash": pin_hash,
                "role": acc.get("role", "user")
            }

        # sanitize transactions: ensure list of dicts with required keys
        txs = data.get("transactions", [])
        if not isinstance(txs, list):
            return False, "Invalid transactions in file"
        for tx in txs:
            if not isinstance(tx, dict) or not {"from", "to", "amount", "timestamp"}.issubset(tx.keys()):
                return False, "Invalid transaction entry"

        # all checks passed; apply loaded state
        self.accounts = new_accounts
        self.transaction_log = txs
        return True, f"State loaded from {path}"

    # --- safer admin command (minimal) ---
    def admin_command(self, command):
        # small whitelist of allowed admin commands (first token)
        allowed_cmds = {"ls", "whoami", "date"}
        if not self.check_session():
            return "Access denied"
        if self.logged_in_user != "admin":
            return "Access denied"

        cmd_name = command.strip().split()[0] if command.strip() else ""
        if cmd_name not in allowed_cmds:
            return "❌ Command not allowed"
        args = command.strip().split()
        try:
            result = subprocess.run(args, capture_output=True, text=True)
            return result.stdout + result.stderr
        except Exception as e:
            return f"Command failed: {e}"


def main():
    print("=" * 50)
    print("🏦 BANK TRANSFER SYSTEM v2.1 🏦")
    print("=" * 50)

    bank = BankTransferSystem()

    while True:
        print("" + "=" * 30)
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
            print("--- LOGIN ---")
            username = input("Username: ").strip()
            pin = input("PIN: ").strip()

            if bank.authenticate(username, pin):
                # NOTE: session token is sensitive — printing is convenient for this demo app
                print(f"✅ Welcome {username}! Session token: {bank.session_token}")
            else:
                print("❌ Invalid credentials")

        elif choice == "2":
            if not bank.check_session():
                print("❌ Please login first")
                continue

            print(f"--- BALANCE FOR {bank.logged_in_user.upper()} ---")
            balance = bank.get_balance(bank.logged_in_user)
            # print safely (handle error messages)
            try:
                print(f"Current balance: ${float(balance):.2f}")
            except Exception:
                print(balance)

        elif choice == "3":
            print("--- MONEY TRANSFER ---")
            from_acc = input("From account: ").strip()
            to_acc = input("To account: ").strip()

            try:
                amount = float(input("Amount: $").strip())
                auth_token = input("Auth token: ").strip()
                if not auth_token:
                    print("❌ Auth token required")
                    continue

                success, message = bank.transfer_money(from_acc, to_acc, amount, auth_token)
                if success:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")
            except ValueError:
                print("❌ Invalid amount")

        elif choice == "4":
            print("--- TRANSACTION LOG ---")
            if not bank.transaction_log:
                print("No transactions found")
            else:
                for i, tx in enumerate(bank.transaction_log, 1):
                    # ensure amount prints correctly (tx['amount'] stored as string)
                    try:
                        amt = float(tx['amount'])
                    except Exception:
                        amt = tx.get('amount', 'N/A')
                    print(f"{i}. {tx['from']} → {tx['to']}: ${amt:.2f} at {tx['timestamp']}")

        elif choice == "5":
            print("--- SAVE STATE ---")
            filename = input("Enter filename (must end with .json): ").strip()
            if filename:
                ok, msg = bank.save_state(filename)
                print(("✅ " if ok else "❌ ") + msg)

        elif choice == "6":
            print("--- LOAD STATE ---")
            filename = input("Enter filename (must end with .json): ").strip()
            if filename:
                ok, msg = bank.load_state(filename)
                print(("✅ " if ok else "❌ ") + msg)

        elif choice == "7":
            print("--- ADMIN COMMANDS ---")
            if not bank.check_session() or bank.logged_in_user != "admin":
                print("❌ Admin access required")
                continue

            command = input("Enter command: ").strip()
            if command:
                result = bank.admin_command(command)
                print(f"Command output: {result}")

        elif choice == "8":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option. Please choose 1-8.")


if __name__ == "__main__":
    main()
