# 1password_ssh_keys_to_bitwarden

## What

This is a tool that parses 1Password exported database (1pux) and extracts SSH keys, then creates a Bitwarden format JSON that you can import into your Bitwarden account.

## Why

Bitwarden import function sucks. When you import 1Password database (1pux) format, all SSH keys become empty notes.

## How

I asked ChatGPT 5.2 to write a script to do the conversion, then I got a broken script. Then I manually fixed the script with the help of Claude Sonnet 4.6 (for the PKCS8v2 parsing).

## Usage

If you don't like [uv](https://docs.astral.sh/uv/getting-started/installation/), you may use `pip` directly.

```
$ uv venv .venv --seed
$ . .venv/bin/activate
$ uv pip install cryptography
$ python convert_1password_ssh_keys_to_bitwarden.py 1PasswordExport-GOODBYE1PASSWORD-20260302-111111.1pux BitwardenExport.json
```

Then goto Bitwarden (Or Vaultwarden) and import output file as `Bitwarden (JSON)` format.

## Limitations

This script assumes all your keys are ED25519 stored in PKCS8v2 PEM format. At least my vault works fine.

## Public Shoutout

I don't like subscription models, especially when you're not delivering any meaningful new value. Also, stroing passwords in the cloud isn't a brilliant idea. GG, 1Password.

Bitwarden — maybe try making the import actually work next time? There are quite a lot of 1Password refugees right now. Go get them all.

## Authors

- Inndy
- ChatGPT 5.2
- Claude Sonnet 4.6
- Claude Opus 4.6

## License

[MIT License](LICENSE)
