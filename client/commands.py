from dns import *

def confirm(access_key, server_address, session_data, box) -> DNSRecord:
    confirm_cmd = f"confirm {access_key}"
    enc_cmd = box.encrypt(confirm_cmd.encode('utf-8'))
    b64_cmd = base64.b64encode(enc_cmd).decode('utf-8')
    send_dns_query(f"{session_data['session_id']}._dftp.begincommand.", server_address)
    for i in range(0, len(b64_cmd), CHUNK_SIZE):
        chunk = b64_cmd[i:i+CHUNK_SIZE]
        send_dns_query(f"{chunk}.{session_data['session_id']}._dftp.command.", server_address)
    return send_dns_query(f"{session_data['session_id']}._dftp.endcommand.", server_address)


def ls(args: list[str]):
    pass

def get(args: list[str]):
    pass

COMMANDS = {
    "ls": ls,
    "get": get
}

def process(command: str, args: list[str]) -> None:
    if command not in COMMANDS:
        print(f"Unknown command: {command}")
        return
    COMMANDS[command](args)