from tqdm import tqdm

from dns import *

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
