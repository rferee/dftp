from dnslib import DNSRecord, QTYPE, RCODE
import socket
from nacl.public import Box, PublicKey
import base64

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