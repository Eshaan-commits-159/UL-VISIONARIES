#!/usr/bin/env python3
"""
Bank Transfer System
====================
Simple bank transfer simulation.

Usage: python bank_transfer.py
"""

import hashlib
import json
import os
import subprocess
import time
import random
import secrets
from datetime import datetime

DATA_DIR = "data"  # all saves/loads confined here
ALLOWED_EXT = ".json"


class BankTransferSystem:
    def __init__(self):
        self.accounts = {
            "alice": {"balance": 1000.0, "pin": "1234"},
            "bob": {"balance": 500.0, "pin": "5678"},
            "charlie": {"balance": 2000.0, "pin": "9999"},
            "admin": {"balance": 1000000.0, "pin": "0000"}
        }
        self.logged_in_user = None
        self.session_token = None
        self.transaction_log = []

    def hash_pin(self, pin):
        return hashlib.sha256(pin.encode()).hexdigest()

    def authenticate(self, username, pin):
        if username in self.accounts:
            stored_pin = self.accounts[username]["pin"]
            # use hashed comparison (still simple, minimal change)
            if self.hash_pin(pin) == self.hash_pin(stored_pin):
                # small constant sleep for processing simulation (avoid timing leaks)
                time.sleep(0.05)
                self.logged_in_user = username
                self.session_token = secrets.token_hex(16)
                return True
            else:
                time.sleep(0.05)
                return False
        # unknown user: do a small constant sleep to avoid easy enumeration by timing
        time.sleep(0.05)
        return False

    def check_session(self):
        return self.logged_in_user is not None and self.session_token is not None

    def transfer_money(self, from_account, to_account, amount, auth_token=None):
        # require active session and that caller matches from_account
        if not self.check_session() or self.logged_in_user != from_account:
            return False, "Unauthorized action"

        # require valid auth token matching session
        if auth_token is None or auth_token != self.session_token:
            return False, "Invalid auth token"

        if from_account not in self.accounts or to_account not in self.accounts:
            return False, "Invalid account"

        # prevent negative or zero transfers
        if amount <= 0:
            return False, "Invalid Transfer Amount"

        if self.accounts[from_account]["balance"] >= amount:
            # small constant sleep for processing simulation
            time.sleep(0.05)
            self.accounts[from_account]["balance"] -= amount
            self.accounts[to_account]["balance"] += amount

            transaction = {
                "from": from_account,
                "to": to_account,
                "amount": amount,
                "timestamp": datetime.now().isoformat(),
            }
            self.transaction_log.append(transaction)
            return True, "Transfer successful"
        else:
            return False, "Insufficient funds"

    def get_balance(self, username):
        if not self.check_session():
            return "Please log in first"
        if self.logged_in_user != username and self.logged_in_user != "admin":
            return "Access denied"
        return self.accounts[username]["balance"]

    # --- safer save/load (minimal changes) ---
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
        # return a safe basename
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

        data = {
            "accounts": self.accounts,
            "transactions": self.transaction_log
        }
        try:
            with open(path, 'w') as f:
                json.dump(data, f)
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
                # minimal normalization: ensure transactions exist
                self.accounts = data.get("accounts", self.accounts)
                self.transaction_log = data.get("transactions", [])
            return True, f"State loaded from {path}"
        except FileNotFoundError:
            return False, "File not found"
        except json.JSONDecodeError:
            return False, "Invalid JSON file"
        except Exception as e:
            return False, f"Load failed: {e}"

    # --- safer admin_command (minimal) ---
    def admin_command(self, command):
        # small whitelist of allowed admin commands (first token)
        allowed_cmds = ["ls", "whoami", "date"]
        if self.logged_in_user == "admin":
            cmd_name = command.strip().split()[0] if command.strip() else ""
            if cmd_name not in allowed_cmds:
                return "❌ Command not allowed"
            # run without shell and pass args safely
            args = command.strip().split()
            try:
                result = subprocess.run(args, capture_output=True, text=True)
                return result.stdout + result.stderr
            except Exception as e:
                return f"Command failed: {e}"
        return "Access denied"


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
                    # ensure amount prints correctly whether it's string or number
                    try:
                        amt = float(tx['amount'])
                    except Exception:
                        amt = tx['amount']
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
            if bank.logged_in_user != "admin":
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
