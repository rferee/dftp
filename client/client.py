from dnslib import DNSRecord, QTYPE, RCODE
import socket
from nacl.public import PrivateKey, Box, PublicKey
from tqdm import tqdm
import base64
import hashlib
import math
import sys
import os

def send_dns_query(query_name, server_address, timeout=120):
    query = DNSRecord.question(query_name, qtype="TXT")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query.pack(), server_address)
            response, _ = sock.recvfrom(512)
            response_record = DNSRecord.parse(response)
            return response_record
        except socket.timeout:
            return None

def sanitize_dns_label(label):
    return label.replace('"', '').replace("'", '')

def exchange_keys(client_private_key, server_address):
    client_public_key = client_private_key.public_key
    client_public_key_b64 = base64.b64encode(client_public_key.encode()).decode('utf-8')

    server_pubkey_response = send_dns_query("_dftp.pubkey.", server_address)
    server_public_key_b64 = str(server_pubkey_response.rr[0].rdata)
    server_public_key = base64.b64decode(server_public_key_b64)

    exchange_response = send_dns_query(f"{client_public_key_b64}._dftp.exchange.", server_address)
    encrypted_challenge_b64 = str(exchange_response.rr[0].rdata).split(':')[1]
    session_id = sanitize_dns_label(str(exchange_response.rr[1].rdata).split(':')[1])

    encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
    box = Box(client_private_key, PublicKey(server_public_key))
    challenge = box.decrypt(encrypted_challenge).decode('utf-8')

    return {
        "client_public_key": client_public_key_b64,
        "server_public_key": server_public_key_b64,
        "session_id": session_id,
        "challenge": challenge,
        "client_private_key": client_private_key
    }

def validate_challenge(session_data, server_address):
    challenge = session_data["challenge"]
    session_id = session_data["session_id"]

    validation_response = send_dns_query(f"{sanitize_dns_label(challenge)}.{session_id}._dftp.validate.", server_address)

    return validation_response.header.rcode == RCODE.NOERROR

def bytes_to_human_readable(num_bytes):
    """Convert bytes to a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"

def handle_cli(session_data, server_address):
    while True:
        command = input("dftp> ")

        if command.startswith("get"):
            print("Warning: Priming the file for transfer may take a while. Please be patient.\n")

        if command == "exit":
            print("Exiting client.")
            break
        else:
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

            parts = command.split(maxsplit=1)
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

                md5_hash = ""
                access_key = ""
                num_chunks = 0
                for rr in response.rr:
                    encrypted_val_b64 = str(rr.rdata)
                    decrypted_val = box.decrypt(base64.b64decode(encrypted_val_b64)).decode('utf-8')
                    if decrypted_val.startswith("MD5:"):
                        md5_hash = decrypted_val.split(":", 1)[1]
                    elif decrypted_val.startswith("AK:"):
                        access_key = decrypted_val.split(":", 1)[1]
                    elif decrypted_val.startswith("NOC:"):
                        num_chunks = int(decrypted_val.split(":", 1)[1])

                if not md5_hash or not access_key or not num_chunks:
                    print("Error: Incomplete response from server.")
                    continue

                print(f"Retrieving ls listing. Have to collect {num_chunks} chunks. Expected MD5: {md5_hash}")

                combined_b64_chunks = []
                for chunk_num in tqdm(range(num_chunks)):
                    attempts = 0
                    success = False
                    while attempts < 3 and not success:
                        qr = send_dns_query(f"{chunk_num}.{access_key}._dftp.getchunk.", server_address, timeout=3)
                        if qr is not None:
                            for crr in qr.rr:
                                chunk_enc_b64 = str(crr.rdata)
                                combined_b64_chunks.append(chunk_enc_b64)
                            success = True
                        else:
                            attempts += 1
                            print(f"Timeout retrieving chunk {chunk_num}, retrying ({attempts}/3)...")
                    if not success:
                        print("Error: Failed to retrieve chunk after 3 attempts.")
                        combined_b64_chunks = []
                        break

                if not combined_b64_chunks:
                    print("Error: Failed to retrieve all chunks.")
                    continue

                combined_b64 = ''.join(combined_b64_chunks)

                try:
                    encrypted_data = base64.b64decode(combined_b64)
                    decrypted_data = box.decrypt(encrypted_data).decode('utf-8')
                except Exception as e:
                    print(f"Error during decryption: {e}")
                    continue

                actual_md5 = hashlib.md5(decrypted_data.encode('utf-8')).hexdigest()

                if actual_md5 == md5_hash:
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
                    confirm_cmd = f"confirm {access_key}"
                    enc_cmd = box.encrypt(confirm_cmd.encode('utf-8'))
                    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')
                    send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)
                    for i in range(0, len(b64_cmd), chunk_size):
                        chunk = b64_cmd[i:i+chunk_size]
                        send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)
                    response2 = send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)
                    if response2 is None or response2.header.rcode == RCODE.SERVFAIL:
                        print("Error: Failed to send confirm command.")
                    else:
                        print("\nDirectory listing transfer confirmed with server.")
                else:
                    print("Error: MD5 checksum mismatch. Listing data may be corrupt.")
            elif parts[0] == "get" and len(parts) >= 2:
                filename = parts[1]
                md5_hash = ""
                access_key = ""
                num_chunks = 0
                for rr in response.rr:
                    encrypted_val_b64 = str(rr.rdata)
                    decrypted_val = box.decrypt(base64.b64decode(encrypted_val_b64)).decode('utf-8')
                    if decrypted_val.startswith("MD5:"):
                        md5_hash = decrypted_val.split(":", 1)[1]
                    elif decrypted_val.startswith("AK:"):
                        access_key = decrypted_val.split(":", 1)[1]
                    elif decrypted_val.startswith("NOC:"):
                        num_chunks = int(decrypted_val.split(":", 1)[1])

                if not md5_hash or not access_key or not num_chunks:
                    print("Error: Incomplete response from server.")
                    continue

                print(f"Retrieving file: {filename}. Have to collect {num_chunks} chunks. Expected MD5: {md5_hash}")

                combined_b64_chunks = []
                for chunk_num in tqdm(range(num_chunks)):
                    attempts = 0
                    success = False
                    while attempts < 3 and not success:
                        qr = send_dns_query(f"{chunk_num}.{access_key}._dftp.getchunk.", server_address, timeout=3)
                        if qr is not None:
                            for crr in qr.rr:
                                chunk_enc_b64 = str(crr.rdata)
                                combined_b64_chunks.append(chunk_enc_b64)
                            success = True
                        else:
                            attempts += 1
                            print(f"Timeout retrieving chunk {chunk_num}, retrying ({attempts}/3)...")
                    if not success:
                        print("Error: Failed to retrieve chunk after 3 attempts.")
                        combined_b64_chunks = []
                        break

                if not combined_b64_chunks:
                    print("Error: Failed to retrieve all chunks.")
                    continue

                combined_b64 = ''.join(combined_b64_chunks)

                try:
                    encrypted_data = base64.b64decode(combined_b64)
                    decrypted_data = box.decrypt(encrypted_data)
                except Exception as e:
                    print(f"Error during decryption: {e}")
                    continue

                actual_md5 = hashlib.md5(decrypted_data).hexdigest()
                print(f"Expected MD5: {md5_hash}")
                print(f"Actual MD5: {actual_md5}")

                if actual_md5 == md5_hash:
                    print(f"File '{filename}' retrieved successfully.")
                    os.makedirs(os.path.dirname(filename), exist_ok=True)
                    with open(filename, "wb") as f:
                        f.write(decrypted_data)
                    confirm_cmd = f"confirm {access_key}"
                    enc_cmd = box.encrypt(confirm_cmd.encode('utf-8'))
                    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')
                    send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)
                    for i in range(0, len(b64_cmd), chunk_size):
                        chunk = b64_cmd[i:i+chunk_size]
                        send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)
                    response2 = send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)
                    if response2 is None or response2.header.rcode == RCODE.SERVFAIL:
                        print("Error: Failed to send confirm command.")
                    else:
                        print("File transfer confirmed with server.")
                else:
                    print("Error: MD5 checksum mismatch. File may be corrupt.")
            else:
                print("Error: Unknown command.")

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
