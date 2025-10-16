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
            if self.hash_pin(pin) == self.hash_pin(stored_pin):
                time.sleep(0.1)
                self.logged_in_user = username
                self.session_token = secrets.token_hex(16)
                return True
            else:
                time.sleep(0.05)
                return False
        return False

    def check_session(self):
        return self.logged_in_user is not None

    def transfer_money(self, from_account, to_account, amount, auth_token=None):
        if not self.check_session() or self.logged_in_user != from_account:
            return False, "Unauthorized action"
        if from_account not in self.accounts or to_account not in self.accounts:
            return False, "Invalid account"
        if amount<=0:
            return False,"Invalid Transfer Amount"

        if self.accounts[from_account]["balance"] >= amount:
            time.sleep(0.1)
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
        if self.logged_in_user !=username and self.logged_in_user != "admin:
            return "Access denied
        return self.accounts[username]["balance]
        

    def save_state(self, filename):
        data = {
            "accounts": self.accounts,
            "transactions": self.transaction_log
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    def load_state(self, filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.accounts = data.get("accounts", self.accounts)
                self.transaction_log = data.get("transactions", [])
        except FileNotFoundError:
            pass

    def admin_command(self, command):
        if self.logged_in_user == "admin":
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout + result.stderr
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
            print(f"Current balance: ${balance:.2f}")

        elif choice == "3":
            print("--- MONEY TRANSFER ---")
            from_acc = input("From account: ").strip()
            to_acc = input("To account: ").strip()

            try:
                amount = float(input("Amount: $").strip())
                auth_token = input("Auth token (optional): ").strip() or None

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
                    print(f"{i}. {tx['from']} → {tx['to']}: ${tx['amount']:.2f} at {tx['timestamp']}")

        elif choice == "5":
            print("--- SAVE STATE ---")
            filename = input("Enter filename: ").strip()
            if filename:
                bank.save_state(filename)
                print(f"✅ State saved to {filename}")

        elif choice == "6":
            print("--- LOAD STATE ---")
            filename = input("Enter filename: ").strip()
            if filename:
                bank.load_state(filename)
                print(f"✅ State loaded from {filename}")

        elif choice == "7":
            print("--- ADMIN COMMANDS ---")
            if bank.logged_in_user != "admin":
                print("❌ Admin access required")
                continue

            command = input("Enter command: ").strip()
            if command:
                result = bank.admin_command(command)
                print(f"Command output:{result}")

        elif choice == "8":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option. Please choose 1-8.")

if __name__ == "__main__":
    main()
