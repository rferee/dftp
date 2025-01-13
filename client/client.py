from dnslib import RCODE
from nacl.public import PrivateKey, Box, PublicKey
import base64
import sys

from commands import CommandMeta, execute, COMMANDS, context
from dns import send_dns_query, exchange_keys, CHUNK_SIZE


def handle_cli(session_data, server_address):
    while True:
        current_dir = context['current_dir']
        prompt = f"/{current_dir}/ dftp> " if current_dir else "/ dftp> "
        user_input = input(prompt).strip()

        if user_input == "exit":
            print("Exiting client.")
            break

        command, *args = user_input.split(maxsplit=1)
        if command not in COMMANDS:
            print("Error: Unknown command.")
            continue

        box = Box(session_data["client_private_key"], PublicKey(base64.b64decode(session_data["server_public_key"])))
        meta = CommandMeta(server_address=server_address, session_data=session_data, box=box)
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
     
    client_private_key = PrivateKey.generate()

    session_data = exchange_keys(client_private_key, SERVER_ADDRESS)

    print("Client key exchange completed.")
    print(f"Session ID: {session_data['session_id']}")
    print(f"Challenge: {session_data['challenge']}")

    handle_cli(session_data, SERVER_ADDRESS)

if __name__ == "__main__":
    main()
