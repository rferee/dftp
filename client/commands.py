from collections import namedtuple
import hashlib
import os

from dns import *
from utils import parse_dns_response, combine_chunks, check_exists_response, execute_exists


CommandMeta = namedtuple("CommandMeta", ["response", "server_address", "session_data","box"])

def confirm(access_key, server_address, session_data, box) -> DNSRecord:
    confirm_cmd = f"confirm {access_key}"
    enc_cmd = box.encrypt(confirm_cmd.encode('utf-8'))
    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')
    send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)
    for i in range(0, len(b64_cmd), CHUNK_SIZE):
        chunk = b64_cmd[i:i+CHUNK_SIZE]
        send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)
    return send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)


def ls(meta: CommandMeta, args: list[str]):
    md5_hash, access_key, num_chunks = parse_dns_response(meta.response, meta.box)
    if not md5_hash or not access_key or not num_chunks:
        print("Error: Incomplete response from server.")
        return

    print(f"Retrieving ls listing. Have to collect {num_chunks} chunks. Expected MD5: {md5_hash}")

    combined_b64 = combine_chunks(access_key, meta.server_address, num_chunks)

    try:
        encrypted_data = base64.b64decode(combined_b64)
        decrypted_data = meta.box.decrypt(encrypted_data).decode('utf-8')
    except Exception as e:
        print(f"Error during decryption: {e}")
        return

    actual_md5 = hashlib.md5(decrypted_data.encode('utf-8')).hexdigest()

    if actual_md5 != md5_hash:
        print("Error: MD5 checksum mismatch. Listing data may be corrupt.")
        return
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

    confirm_response = confirm(access_key, meta.server_address, meta.session_data, meta.box)
    if confirm_response is None or confirm_response.header.rcode == RCODE.SERVFAIL:
        print("Error: Failed to send confirm command.")
        return
    
    print("\nDirectory listing transfer confirmed with server.")


def get(meta: CommandMeta, args: list[str]):
    print("Warning: Priming the file for transfer may take a while. Please be patient.\n")

    filename = args[0]
    md5_hash, access_key, num_chunks = parse_dns_response(meta.response, meta.box)
    if not md5_hash or not access_key or not num_chunks:
        print("Error: Incomplete response from server.")
        return

    print(f"Retrieving file: {filename}. Have to collect {num_chunks} chunks. Expected MD5: {md5_hash}")

    combined_b64 = combine_chunks(access_key, meta.server_address, num_chunks)

    try:
        encrypted_data = base64.b64decode(combined_b64)
        decrypted_data = meta.box.decrypt(encrypted_data)
    except Exception as e:
        print(f"Error during decryption: {e}")
        return

    actual_md5 = hashlib.md5(decrypted_data).hexdigest()
    print(f"Expected MD5: {md5_hash}")
    print(f"Actual MD5: {actual_md5}")

    if actual_md5 != md5_hash:
        print("Error: MD5 checksum mismatch. File may be corrupt.")
        return
    print(f"File '{filename}' retrieved successfully.")
    
    if os.path.dirname(filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, "wb") as f:
        f.write(decrypted_data)

    confirm_response = confirm(access_key, meta.server_address, meta.session_data, meta.box)
    if confirm_response is None or confirm_response.header.rcode == RCODE.SERVFAIL:
        print("Error: Failed to send confirm command.")
        return
    
    print("File transfer confirmed with server.")


def exists(meta: CommandMeta, args: list[str]):
    if len(args) != 1:
        print("Usage: exists <path>")
        return
    
    path = args[0]
    exists = execute_exists(meta, path)
    print("true" if exists else "false")


COMMANDS = {
    "ls": ls,
    "get": get,
    "exists": exists
}


def execute(command: str, meta: CommandMeta, args: list[str]) -> None:
    if command not in COMMANDS:
        print(f"Unknown command: {command}")
        return
    COMMANDS[command](meta, args)