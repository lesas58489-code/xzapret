#!/usr/bin/env python3
"""
XZAP Key Manager — add/remove/list users.

Usage:
    python3 manage_keys.py list
    python3 manage_keys.py add <username>
    python3 manage_keys.py remove <username>
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from xzap.keystore import KeyStore


def main():
    if len(sys.argv) < 2:
        print("Usage: manage_keys.py <list|add|remove> [username]")
        return

    store = KeyStore("keys.json")
    cmd = sys.argv[1]

    if cmd == "list":
        users = store.list_users()
        print(f"\n{len(users)} users:")
        for u in users:
            print(f"  {u}")
        print()

    elif cmd == "add":
        if len(sys.argv) < 3:
            print("Usage: manage_keys.py add <username>")
            return
        username = sys.argv[2]
        key_b64 = store.add_user(username)
        print(f"\nUser '{username}' added.")
        print(f"Key: {key_b64}")
        print(f"\nClient config:")
        print(f"  XZAP_KEY={key_b64}")
        print()

    elif cmd == "remove":
        if len(sys.argv) < 3:
            print("Usage: manage_keys.py remove <username>")
            return
        username = sys.argv[2]
        if store.remove_user(username):
            print(f"User '{username}' removed.")
        else:
            print(f"User '{username}' not found.")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
