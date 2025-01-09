from dnslib import RCODE
from nacl.public import PrivateKey, Box, PublicKey
import base64
import hashlib
import sys
import os

from commands import CommandMeta, get, ls
from dns import send_dns_query, exchange_keys, validate_challenge
def handle_cli(session_data, server_address):
    COMMANDS = ["ls", "get"]

    while True:
        command = input("dftp> ").strip()
            
        if command == "exit":
            print("Exiting client.")
            break

        parts = command.split(maxsplit=1)
        if parts[0] not in COMMANDS:
            print("Error: Unknown command.")
            continue

        box = Box(session_data["client_private_key"], PublicKey(base64.b64decode(session_data["server_public_key"])))
        encrypted = box.encrypt(command.encode('utf-8'))
        b64_command = base64.b64encode(encrypted).decode('utf-8')

        send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)

        chunk_size = 63
        for i in range(0, len(b64_command), chunk_size):
            chunk = b64_command[i:i+chunk_size]
            send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)

        response = send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)
        if response is None or response.header.rcode == RCODE.SERVFAIL:
            print("Error: Invalid query or no response from server.")
            continue

        meta = CommandMeta(response, server_address, session_data, box)
        if parts[0] == "ls":
            ls(meta, parts[1:])
        elif parts[0] == "get" and len(parts) >= 2:
            get(meta, parts[1:])
            

def main():
    if len(sys.argv) > 1:
        try:
            server_ip, port = sys.argv[1].split(':')
            SERVER_ADDRESS = (server_ip, int(port))
        except:
            SERVER_ADDRESS = ("127.0.0.1", 5500)
    else:
        SERVER_ADDRESS = ("127.0.0.1", 5500)

    client_private_key = PrivateKey.generate()

    session_data = exchange_keys(client_private_key, SERVER_ADDRESS)

    print("Client key exchange completed.")
    print(f"Session ID: {session_data['session_id']}")
    print(f"Challenge: {session_data['challenge']}")

    if validate_challenge(session_data, SERVER_ADDRESS):
        print("Challenge validation successful.")
    else:
        print("Challenge validation failed.")
        return

    handle_cli(session_data, SERVER_ADDRESS)

if __name__ == "__main__":
    main()
