from collections import namedtuple

from tqdm import tqdm

from dns import *

CommandMeta = namedtuple("CommandMeta", ["response", "server_address", "session_data","box"])

def parse_dns_response(response: DNSRecord, box: Box) -> tuple:
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
    return md5_hash, access_key, num_chunks


def check_exists_response(response: DNSRecord, box: Box) -> bool:
    try:
        for rr in response.rr:
            encrypted_val_b64 = str(rr.rdata)
            decrypted_val = box.decrypt(base64.b64decode(encrypted_val_b64)).decode('utf-8')
            status, type_, name = decrypted_val.split(':', 2)
            return status == '1'
    except:
        return False


def combine_chunks(access_key, server_address, chunks_num) -> list[str]:
    combined_b64_chunks = []
    for chunk_num in tqdm(range(chunks_num)):
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
        return

    return ''.join(combined_b64_chunks)


def execute_exists(meta: CommandMeta, path: str) -> bool:
    exists_cmd = f"exists {path}"
    enc_cmd = meta.box.encrypt(exists_cmd.encode('utf-8'))
    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')
    
    send_dns_query(f"{meta.session_data['session_id']}._dftp.begincommand.", meta.server_address)
    for i in range(0, len(b64_cmd), CHUNK_SIZE):
        chunk = b64_cmd[i:i+CHUNK_SIZE]
        send_dns_query(f"{chunk}.{meta.session_data['session_id']}._dftp.command.", meta.server_address)
    response = send_dns_query(f"{meta.session_data['session_id']}._dftp.endcommand.", meta.server_address)
    
    if response is None:
        print("Error: No response from server.")
        return False
    
    exists = check_exists_response(response, meta.box)
    return exists
