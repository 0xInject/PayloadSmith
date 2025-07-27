import base64
import urllib.parse
import codecs

def encode_payload(payload, method):
    method = method.lower()

    if method == "base64":
        return base64.b64encode(payload.encode()).decode()

    elif method == "hex":
        return payload.encode().hex()

    elif method == "rot13":
        return codecs.encode(payload, 'rot_13')

    elif method == "url":
        return urllib.parse.quote(payload)

    else:
        return "[!] Unsupported encoding method."
