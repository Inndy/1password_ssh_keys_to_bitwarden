import base64
import hashlib
import json
import sys
import textwrap
import uuid
import zipfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# OpenSSH fingerprint (IDENTICAL to ssh-keygen)
def openssh_fingerprint(public_key: str) -> str:
    parts = public_key.split()

    if len(parts) < 2:
        raise ValueError("Invalid public key")

    blob = base64.b64decode(parts[1])
    digest = hashlib.sha256(blob).digest()

    fp = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{fp}"


def decode_pem(pem_str: str) -> tuple[str, bytes]:
    lines = pem_str.strip().splitlines()
    pem_type = lines[0].removeprefix('-----BEGIN ').removesuffix('-----')
    assert lines[-1] == f'-----END {pem_type}-----'
    body = ''.join(lines[1:-1])
    return pem_type, base64.b64decode(body)


# Parse PEM encoded ED25519 private key
def load_private_key(private_pem: str):
    pem_type, buf = decode_pem(private_pem)

    # 1Password uses PKCS8v2, which is not supported by serialization.load_pem_private_key
    # manually extract ed25519 private key from ASN.1 buffer
    # Try paste your PEM encoded private key into: https://lapo.it/asn1js/
    if buf[0] == 0x30 and buf[2:16] == bytes.fromhex('020101300506032B657004220420'):
        return Ed25519PrivateKey.from_private_bytes(buf[16:16+32])

    return serialization.load_pem_private_key(
        private_pem.strip().encode(),
        password=None,
    )


# Convert private key to OpenSSH PEM format
def rewrap_pem(pem_str: str, width: int = 70) -> str:
    lines = pem_str.strip().splitlines()
    header = lines[0]
    footer = lines[-1]
    b64 = ''.join(lines[1:-1])
    return '\n'.join([header] + textwrap.wrap(b64, width) + [footer]) + '\n'


def convert_to_openssh(key) -> str:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return rewrap_pem(pem)



def convert(export_data):
    folders = {}
    items = []

    for account in export_data.get("accounts", []):
        for vault in account.get("vaults", []):
            for item in vault.get("items", []):
                sections = item.get("details", {}).get("sections", [])

                ssh_key = None

                for section in sections:
                    if set(section.keys()) == {'title', 'fields', 'hideAddAnotherField'}:
                        if len(section['fields']) > 1:
                            print('Unexpected section found, reason: len(section["fields"]) > 1')
                            sys.exit(1)
                        elif len(section['fields']) == 0:
                            continue

                        if section['fields'][0].get('id') == 'private_key':
                            ssh_key = section['fields'][0].get('value', {}).get('sshKey', {}).get('privateKey')

                if not ssh_key:
                    continue

                default_tag = (item['overview'].get('tags', []) + [None])[0]

                vault_name = default_tag or "Imported SSH Keys"

                if vault_name not in folders:
                    folders[vault_name] = str(uuid.uuid4())

                folder_id = folders[vault_name]

                title = (
                    item.get("overview", {})
                    .get("title", "SSH Key")
                )

                # ---- load + normalize key ----
                key_obj = load_private_key(ssh_key)

                private_openssh = convert_to_openssh(key_obj)
                public_key = key_obj.public_key().public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH,
                ).decode()
                fingerprint = openssh_fingerprint(public_key)

                created = item.get("createdAt", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
                updated = item.get("updatedAt", created)

                bw_item = {
                    "passwordHistory": [],
                    "revisionDate": updated,
                    "creationDate": created,
                    "id": str(uuid.uuid4()),
                    "folderId": folder_id,
                    "type": 5,
                    "reprompt": 0,
                    "name": title,
                    "notes": None,
                    "favorite": False,
                    "fields": [],
                    "sshKey": {
                        "privateKey": private_openssh,
                        "publicKey": public_key,
                        "keyFingerprint": fingerprint,
                    },
                    "collectionIds": None,
                }

                items.append(bw_item)

    bw_json = {
        "encrypted": False,
        "folders": [
            {"id": fid, "name": name}
            for name, fid in folders.items()
        ],
        "items": items,
    }

    return bw_json


def main(infile, outfile):
    with zipfile.ZipFile(infile) as zf, zf.open('export.data') as f:
        export_data = json.load(f)

    result = convert(export_data)
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"\n[+] Exported {len(result['items'])} SSH keys")
    print(f"[+] Output written to: {outfile}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage:\n  python {sys.argv[0]} 1password_archive.1pux bitwarden_export.json")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
