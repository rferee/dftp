from dnslib import DNSRecord, RCODE
import socket
from nacl.public import Box, PublicKey
import base64

CHUNK_SIZE = 63

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

    # Perform validation with normal command steps
    begin_resp = send_dns_query(f"{session_id}._dftp.begincommand.", server_address)
    validate_cmd = f"validate {challenge}"
    enc_cmd = box.encrypt(validate_cmd.encode('utf-8'))
    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')

    for i in range(0, len(b64_cmd), CHUNK_SIZE):
        chunk = b64_cmd[i:i+CHUNK_SIZE]
        send_dns_query(f"{chunk}.{session_id}._dftp.command.", server_address)

    end_resp = send_dns_query(f"{session_id}._dftp.endcommand.", server_address)
    if end_resp is None or end_resp.header.rcode == 2:
        print("Unable to complete handshake")
        exit(1)

    return {
        "client_public_key": client_public_key_b64,
        "server_public_key": server_public_key_b64,
        "session_id": session_id,
        "challenge": challenge,
        "client_private_key": client_private_key
    }

def bytes_to_human_readable(num_bytes):
    """Convert bytes to a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"