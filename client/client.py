from dnslib import RCODE
from nacl.public import PrivateKey, Box, PublicKey
import base64
import sys

from commands import CommandMeta, execute, COMMANDS
from dns import send_dns_query, exchange_keys, validate_challenge, CHUNK_SIZE


def handle_cli(session_data, server_address):
    while True:
        user_input = input("dftp> ").strip()

        if user_input == "exit":
            print("Exiting client.")
            break

        command, *args = user_input.split(maxsplit=1)
        if command not in COMMANDS:
            print("Error: Unknown command.")
            continue

        box = Box(session_data["client_private_key"], PublicKey(base64.b64decode(session_data["server_public_key"])))
        encrypted = box.encrypt(user_input.encode('utf-8'))
        b64_command = base64.b64encode(encrypted).decode('utf-8')

        send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)

        for i in range(0, len(b64_command), CHUNK_SIZE):
            chunk = b64_command[i:i+CHUNK_SIZE]
            send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)

        response = send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)
        if response is None or response.header.rcode == RCODE.SERVFAIL:
            print("Error: Invalid query or no response from server.")
            continue

        meta = CommandMeta(response, server_address, session_data, box)
        execute(command, meta, args)


def main():
    SERVER_ADDRESS = ("127.0.0.1", 5500)
    if len(sys.argv) > 1:
        try:
            server_ip, port = sys.argv[1].split(':')
            SERVER_ADDRESS = (server_ip, int(port))
        except:
            print("Error: Can't parse server address.")
            print("Using default:", SERVER_ADDRESS)
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
