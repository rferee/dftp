from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, TXT, RCODE
import socketserver
from nacl.public import PrivateKey, PublicKey, Box
import os
import base64
import uuid
import random
import string
import hashlib

SERVER_VERSION = "1.0.0"
FILES_DIRECTORY = "./files"
CHUNKS_DIRECTORY = "./tmp"
client_sessions = {}

def generate_random_string(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_box(private_key, client_pubkey):
    """Create a NaCl Box."""
    return Box(private_key, client_pubkey)

def get_session_or_fail(session_id, reply):
    if session_id in client_sessions:
        return client_sessions[session_id]
    reply.header.rcode = RCODE.SERVFAIL
    return None

def decrypt_payload(private_key, client_pubkey, payload_b64):
    try:
        payload_encrypted = base64.b64decode(payload_b64)
        box = create_box(private_key, client_pubkey)
        return box.decrypt(payload_encrypted).decode('utf-8')
    except:
        return None

def handle_a_query(qname, reply):
    print(f"[DEBUG] handle_a_query called with qname: {qname}")
    reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
    print("[DEBUG] handle_a_query returning A record")

def handle_pubkey_query(qname, reply, public_key):
    print(f"[DEBUG] handle_pubkey_query called with qname: {qname}")
    encoded_key = base64.b64encode(public_key.encode()).decode('utf-8')
    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(encoded_key)))
    print("[DEBUG] handle_pubkey_query completed, sent pubkey")

def handle_version_query(qname, reply):
    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(SERVER_VERSION)))

def handle_exchange_query(qname, reply, private_key):
    print(f"[DEBUG] handle_exchange_query called with qname: {qname}")
    client_pubkey_b64 = qname.split('.')[0]
    client_pubkey = PublicKey(base64.b64decode(client_pubkey_b64))
    session_id = str(uuid.uuid4())[:13]
    challenge = generate_random_string().encode('utf-8')
    box = create_box(private_key, client_pubkey)
    encrypted_challenge = box.encrypt(challenge)
    encrypted_challenge_b64 = base64.b64encode(encrypted_challenge).decode('utf-8')

    client_sessions[session_id] = {
        "client_pubkey": client_pubkey,
        "challenge": challenge,
        "isTrusted": False
    }
    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"C:{encrypted_challenge_b64}")))
    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"SID:{session_id}")))
    print(f"[DEBUG] New session established with session_id: {session_id}")

def handle_command_query(qname, reply, private_key):
    print(f"[DEBUG] handle_command_query called with qname: {qname}")
    parts = qname.split('.')
    payload_b64, session_id = parts[0], parts[1]

    session = get_session_or_fail(session_id, reply)
    if not session:
        print("[DEBUG] Failed to process command")
        return

    payload = decrypt_payload(private_key, session["client_pubkey"], payload_b64)
    if payload:
        print(f"Received command: {payload}")
        reply.header.rcode = RCODE.NOERROR
        print(f"[DEBUG] Command successfully processed: {payload}")
    else:
        reply.header.rcode = RCODE.SERVFAIL
        print("[DEBUG] Failed to process command")

def handle_begincommand_query(qname, reply):
    print(f"[DEBUG] handle_begincommand_query called with qname: {qname}")
    session_id = qname.split('.')[0]
    session = get_session_or_fail(session_id, reply)
    if not session:
        print(f"[DEBUG] begincommand query failed for session {session_id}")
        return

    session["command_chunks_b64"] = []
    reply.header.rcode = RCODE.NOERROR
    print(f"[DEBUG] Began collecting command chunks for session {session_id}")

def handle_command_chunk(qname, reply, private_key):
    print(f"[DEBUG] handle_command_chunk called with qname: {qname}")
    parts = qname.split('.')
    chunk_b64, session_id = parts[0], parts[1]

    session = get_session_or_fail(session_id, reply)
    if not session:
        print(f"[DEBUG] Failed to store chunk for session {session_id}")
        return

    if "command_chunks_b64" not in session:
        session["command_chunks_b64"] = []
    session["command_chunks_b64"].append(chunk_b64)
    reply.header.rcode = RCODE.NOERROR
    print(f"[DEBUG] Stored command chunk for session {session_id}")

def is_safe_path(base_path, target_path):
    return os.path.realpath(target_path).startswith(os.path.realpath(base_path))

def handle_ls_command(session_id, reply, private_key, directory=""):
    print(f"[DEBUG] handle_ls_command called for session {session_id}, directory: {directory}")
    session = get_session_or_fail(session_id, reply)
    if not session:
        print("[DEBUG] Listing files failed")
        return

    client_pubkey = session["client_pubkey"]
    box = create_box(private_key, client_pubkey)
    try:
        target_directory = os.path.join(FILES_DIRECTORY, directory)
        if not is_safe_path(FILES_DIRECTORY, target_directory) or not os.path.exists(target_directory):
            reply.header.rcode = RCODE.SERVFAIL
            print(f"[DEBUG] Directory {target_directory} is not safe or does not exist")
            return

        entries = os.listdir(target_directory)
        lines = []
        for entry in entries:
            entry_path = os.path.join(target_directory, entry)
            if os.path.isfile(entry_path):
                file_size = os.path.getsize(entry_path)
                md5_hash = hashlib.md5(open(entry_path, "rb").read()).hexdigest()
                lines.append(f"F:{file_size}:{entry}:{md5_hash}")
            elif os.path.isdir(entry_path):
                lines.append(f"D:{entry}")

        listing_str = "\n".join(lines)
        encrypted_listing = box.encrypt(listing_str.encode('utf-8'))
        b64_encrypted = base64.b64encode(encrypted_listing).decode('utf-8')
        md5_hash_list = hashlib.md5(listing_str.encode('utf-8')).hexdigest()
        access_key = str(uuid.uuid4())

        if not os.path.exists(CHUNKS_DIRECTORY):
            os.makedirs(CHUNKS_DIRECTORY)

        chunk_size = 252
        chunks = [b64_encrypted[i:i+chunk_size] for i in range(0, len(b64_encrypted), chunk_size)]
        for idx, chunk_data in enumerate(chunks):
            with open(os.path.join(CHUNKS_DIRECTORY, f"{idx}.{access_key}.chunk"), "w") as cf:
                cf.write(chunk_data)

        md5_enc = box.encrypt(f"MD5:{md5_hash_list}".encode('utf-8'))
        ak_enc = box.encrypt(f"AK:{access_key}".encode('utf-8'))
        noc_enc = box.encrypt(f"NOC:{len(chunks)}".encode('utf-8'))

        reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(md5_enc).decode('utf-8'))))
        reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(ak_enc).decode('utf-8'))))
        reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(noc_enc).decode('utf-8'))))

        reply.header.rcode = RCODE.NOERROR
        print("[DEBUG] File listing chunks prepared, access key returned")
    except Exception as e:
        print(f"Error listing files: {e}")
        reply.header.rcode = RCODE.SERVFAIL
        print("[DEBUG] Listing files failed")

def handle_get_command(session_id, reply, private_key, filename):
    print(f"[DEBUG] handle_get_command called for session {session_id}, filename: {filename}")
    session = get_session_or_fail(session_id, reply)
    if not session:
        print(f"[DEBUG] Failed to process get command for {filename}")
        return

    file_path = os.path.join(FILES_DIRECTORY, filename)
    if not is_safe_path(FILES_DIRECTORY, file_path) or not os.path.isfile(file_path):
        reply.header.rcode = RCODE.SERVFAIL
        print(f"[DEBUG] Failed to process get command for {filename}")
        return

    with open(file_path, "rb") as f:
        file_content = f.read()
    box = create_box(private_key, session["client_pubkey"])
    encrypted_content = box.encrypt(file_content)
    b64_encrypted = base64.b64encode(encrypted_content).decode('utf-8')
    md5_hash = hashlib.md5(file_content).hexdigest()

    access_key = str(uuid.uuid4())
    if not os.path.exists(CHUNKS_DIRECTORY):
        os.makedirs(CHUNKS_DIRECTORY)

    chunk_size = 252
    chunks = [b64_encrypted[i:i+chunk_size] for i in range(0, len(b64_encrypted), chunk_size)]
    for idx, chunk_data in enumerate(chunks):
        with open(os.path.join(CHUNKS_DIRECTORY, f"{idx}.{access_key}.chunk"), "w") as cf:
            cf.write(chunk_data)

    md5_enc = box.encrypt(f"MD5:{md5_hash}".encode('utf-8'))
    ak_enc = box.encrypt(f"AK:{access_key}".encode('utf-8'))
    noc_enc = box.encrypt(f"NOC:{len(chunks)}".encode('utf-8'))

    reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(md5_enc).decode('utf-8'))))
    reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(ak_enc).decode('utf-8'))))
    reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(base64.b64encode(noc_enc).decode('utf-8'))))

    reply.header.rcode = RCODE.NOERROR
    print(f"[DEBUG] File {filename} chunks prepared, access key returned")

def handle_getchunk_query(qname, reply, private_key):
    print(f"[DEBUG] handle_getchunk_query called with qname: {qname}")
    parts = qname.split('.')
    chunk_str, access_key = parts[0], parts[1]

    if not chunk_str.isdigit():
        reply.header.rcode = RCODE.SERVFAIL
        print("[DEBUG] Failed to serve chunk")
        return

    chunk_file = os.path.join(CHUNKS_DIRECTORY, f"{chunk_str}.{access_key}.chunk")
    if not os.path.exists(chunk_file):
        reply.header.rcode = RCODE.SERVFAIL
        print("[DEBUG] Failed to serve chunk")
        return

    with open(chunk_file, "r") as cf:
        chunk_data = cf.read()

    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(chunk_data)))
    reply.header.rcode = RCODE.NOERROR
    print(f"[DEBUG] Served chunk {chunk_str} for access_key {access_key}")

def handle_confirm_command(session_id, reply, private_key, access_key):
    print(f"[DEBUG] handle_confirm_command called for session {session_id}, access_key: {access_key}")
    session = get_session_or_fail(session_id, reply)
    if not session:
        return

    for fn in os.listdir(CHUNKS_DIRECTORY):
        if fn.endswith(f"{access_key}.chunk"):
            os.remove(os.path.join(CHUNKS_DIRECTORY, fn))

    reply.header.rcode = RCODE.NOERROR
    print(f"[DEBUG] Confirmed and removed chunks for access_key {access_key}")

def handle_exists_command(session_id, reply, private_key, path):
    box = create_box(private_key, client_sessions[session_id]["client_pubkey"])
    response_lines = []
    
    print(f"[DEBUG] handle_exists_command called for session {session_id}, path: {path}")

    if path.startswith("F:") or path.startswith("f:"):
        file_path = os.path.join(FILES_DIRECTORY, path[2:])
        exists = os.path.isfile(file_path)
        status = "1" if exists else "0"
        response_lines.append(f"{status}:F:{path[2:]}")
    elif path.startswith("D:") or path.startswith("d:"):
        dir_path = os.path.join(FILES_DIRECTORY, path[2:])
        exists = os.path.isdir(dir_path)
        status = "1" if exists else "0"
        response_lines.append(f"{status}:D:{path[2:]}")
    else:
        reply.header.rcode = RCODE.SERVFAIL
        return

    encrypted_responses = [box.encrypt(line.encode('utf-8')) for line in response_lines]
    for enc in encrypted_responses:
        b64_enc = base64.b64encode(enc).decode('utf-8')
        reply.add_answer(RR(session_id, QTYPE.TXT, rdata=TXT(b64_enc)))
    
    reply.header.rcode = RCODE.NOERROR

def handle_endcommand_query(qname, reply, private_key):
    print(f"[DEBUG] handle_endcommand_query called with qname: {qname}")
    session_id = qname.split('.')[0]
    session = get_session_or_fail(session_id, reply)
    if not session or "command_chunks_b64" not in session:
        print("[DEBUG] Command processing failed")
        return

    combined_b64 = "".join(session["command_chunks_b64"])
    client_pubkey = session["client_pubkey"]
    try:
        box = create_box(private_key, client_pubkey)
        payload_encrypted = base64.b64decode(combined_b64)
        full_command = box.decrypt(payload_encrypted).decode('utf-8')
        print(f"Received command: {full_command}")
        parts = full_command.split(maxsplit=1)

        # Reject any command if the session is not trusted and command is not validate
        if not session["isTrusted"] and parts[0] != "validate":
            reply.header.rcode = RCODE.SERVFAIL
            return

        if parts[0] == "validate" and len(parts) == 2:
            if parts[1].encode('utf-8') == session["challenge"]:
                session["isTrusted"] = True
                reply.header.rcode = RCODE.NOERROR
            else:
                del client_sessions[session_id]
                reply.header.rcode = RCODE.SERVFAIL
            return
        elif parts[0] == "ls":
            directory = parts[1] if len(parts) > 1 else ""
            handle_ls_command(session_id, reply, private_key, directory)
        elif parts[0] == "get" and len(parts) >= 2:
            handle_get_command(session_id, reply, private_key, parts[1])
        elif parts[0] == "confirm" and len(parts) == 2:
            handle_confirm_command(session_id, reply, private_key, parts[1])
        elif parts[0] == "exists" and len(parts) == 2:
            handle_exists_command(session_id, reply, private_key, parts[1])
        else:
            reply.header.rcode = RCODE.SERVFAIL
            print(f"Unknown or invalid command: {full_command}")

        session["command_chunks_b64"] = []
        print("[DEBUG] Command processed successfully")
    except Exception as e:
        print(f"Error decrypting command: {e}")
        reply.header.rcode = RCODE.SERVFAIL
        print("[DEBUG] Command processing failed")

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"[DEBUG] DNSHandler received data from {self.client_address}")
        data, sock = self.request
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = QTYPE[request.q.qtype]
            print(f"[DEBUG] Parsed qname: {qname}, qtype: {qtype}")

            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

            if qtype == "A":
                handle_a_query(qname, reply)
            elif qtype == "TXT" and qname == "_dftp.pubkey.":
                handle_pubkey_query(qname, reply, public_key)
            elif qtype == "TXT" and qname == "_dftp.version.":
                handle_version_query(qname, reply)
            elif qtype == "TXT" and qname.endswith("._dftp.exchange."):
                handle_exchange_query(qname, reply, private_key)
            elif qtype == "TXT" and qname.endswith("._dftp.begincommand."):
                handle_begincommand_query(qname, reply)
            elif qtype == "TXT" and qname.endswith("._dftp.command."):
                handle_command_chunk(qname, reply, private_key)
            elif qtype == "TXT" and qname.endswith("._dftp.endcommand."):
                handle_endcommand_query(qname, reply, private_key)
            elif qtype == "TXT" and qname.endswith("._dftp.getchunk."):
                handle_getchunk_query(qname, reply, private_key)

            sock.sendto(reply.pack(), self.client_address)
        except Exception as e:
            print(f"[DEBUG] Error handling request: {e}")

if __name__ == "__main__":
    try:
        with open("25519key", "rb") as f:
            private_key = PrivateKey(base64.b64decode(f.read()))
        with open("25519key.pub", "rb") as f:
            public_key = PublicKey(base64.b64decode(f.read()))
    except FileNotFoundError:
        key = PrivateKey.generate()
        with open("25519key", "wb") as f:
            f.write(base64.b64encode(key.encode()))
        with open("25519key.pub", "wb") as f:
            f.write(base64.b64encode(key.public_key.encode()))
        private_key = key
        public_key = key.public_key

    print("Public key: ", base64.b64encode(public_key.encode()).decode('utf-8'))

    server = socketserver.UDPServer(("0.0.0.0", 5500), DNSHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
