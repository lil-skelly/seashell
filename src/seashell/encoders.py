import seashell

import base64
import secrets

def xoru(data: str) -> bytes:
    key = secrets.token_bytes(len(data))
    seashell.logger.info(f"{seashell.CYAN}{seashell.BOLD}[*]{seashell.RESET} XOR key: {key}")
    
    return bytearray(a^b for a, b in zip(*map(bytearray, [data.encode(), key])))

def base64_encode_iter(data: bytes, iterations: int) -> bytes:
    for _ in range(iterations):
        data = base64.b64encode(data)
    
    return data

ENCODER_MAP = {
    "base64": base64_encode_iter,
    "xor": xoru
}
