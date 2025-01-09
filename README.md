# DFTP (DNS File Transfer Protocol) & Python Implementations

## Overview
DFTP is a DNS-based File Transfer Protocol that enables somewhat secure and "efficient" file transfers using DNS queries. It leverages DNS TXT records and public-key cryptography to facilitate data exchange between clients and server.

## Features

- DFTP is conceived by one of the masterminds behind [DoDwHA](https://gitlab.internal.rferee.dev/services/dns-over-dns-2.0) and RFD-V, which sounds cool until you get to know what both of these are.
- Works most of the time, but don't count on that.
- It is not as slow as it can be, but transferring a a 10MB file can take half an hour.
- It's file transfer over DNS, it's a feature in itself mate.

## Installation

### Requirements
- Python 3.13+ (might work on version below that, but that's untested)
- dnslib
- pynacl
- tqdm

### Setup
1. **Clone the Repository**
    ```bash
    git clone https://github.com/rferee/dftp.git
    ```
2. **Navigate to the Project Directory**
    ```bash
    cd dftp
    ```
3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Server

To start the DFTP server:
```bash
python server/server.py --port 5500
```

By default the server will serve `./files` over DFTP and use `./tmp` as storage for chunks of data.

### Client

To use the DFTP client:
```bash
python client/client.py --server 127.0.0.1:5500
```
Once connected, you can use the following commands:
- `ls` : List files and directories on the server.
- `get <filename>` : Download a specific file from the server.
- `exit` : Exit the client application.

## Support

Non-existent.

## Contributing

Before sending PRs, please reconsider your life choices and consider doing something more productive and useful. If you are nearing the point of insanity however, you are more than welcome to contribute. That said, consider that this repository is being mirrored from rferee's GitLab instance and that your PRs might be merged in funny ways, but rest assured that your contribution will be noted.

## License

This project is licensed under GNU AGPLv3. For more information, see the [LICENSE](./LICENSE) file.