from dnslib import RCODE
from nacl.public import PrivateKey, Box, PublicKey
import base64
import hashlib
import sys
import os

from commands import CommandMeta, confirm, get
from dns import send_dns_query, exchange_keys, validate_challenge, bytes_to_human_readable
from utils import combine_chunks, parse_dns_response

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
            for rr in response.rr:
                encrypted_entry_b64 = str(rr.rdata)
                encrypted_entry = base64.b64decode(encrypted_entry_b64)
                entry = box.decrypt(encrypted_entry).decode('utf-8')
                entry_parts = entry.split(':')
                if entry_parts[0] == "F" and len(entry_parts) == 4:
                    _, size_bytes, filename, md5_hash = entry_parts
                    size_hr = bytes_to_human_readable(int(size_bytes))
                    print(f"{filename:<30} {size_hr:>10} {md5_hash:>32}")
                elif entry_parts[0] == "D" and len(entry_parts) == 2:
                    _, dirname = entry_parts
                    print(f"{dirname + '/':<30} {'-':>10} {'-':>32}")

            md5_hash, access_key, num_chunks = parse_dns_response(response, box)
            if not md5_hash or not access_key or not num_chunks:
                print("Error: Incomplete response from server.")
                continue

            print(f"Retrieving ls listing. Have to collect {num_chunks} chunks. Expected MD5: {md5_hash}")

            combined_b64 = combine_chunks(access_key, server_address, num_chunks)

            try:
                encrypted_data = base64.b64decode(combined_b64)
                decrypted_data = box.decrypt(encrypted_data).decode('utf-8')
            except Exception as e:
                print(f"Error during decryption: {e}")
                continue

            actual_md5 = hashlib.md5(decrypted_data.encode('utf-8')).hexdigest()

            if actual_md5 != md5_hash:
                print("Error: MD5 checksum mismatch. Listing data may be corrupt.")
                continue
            print()
            filename_header = "Filename"
            size_header = "Size"
            filename_width = max(len(filename_header), max(len(line.split(':')[2]) for line in decrypted_data.split('\n') if line.startswith("F:")))
            size_width = max(len(size_header), 10)
            total_width = filename_width + size_width + 1

            print(f"{filename_header:<{filename_width}} {size_header:>{size_width}}")
            print("-" * total_width)
            for line in decrypted_data.split('\n'):
                if line.startswith("F:"):
                    _, size_bytes, filename, _ = line.split(':')
                    size_hr = bytes_to_human_readable(int(size_bytes))
                    print(f"{filename:<{filename_width}} {size_hr:>{size_width}}")
                elif line.startswith("D:"):
                    _, dirname = line.split(':')
                    print(f"{dirname + '/':<{filename_width}} {'-':>{size_width}}")

            confirm_response = confirm(access_key, server_address, session_data, box)
            if confirm_response is None or confirm_response.header.rcode == RCODE.SERVFAIL:
                print("Error: Failed to send confirm command.")
                continue
            print("\nDirectory listing transfer confirmed with server.")

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
