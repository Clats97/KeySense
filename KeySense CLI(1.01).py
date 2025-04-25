import os, sys, zlib, base64, random, struct, pathlib
from argon2.low_level import hash_secret_raw, Type

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ModuleNotFoundError:
    sys.exit("Missing dependency:  pip install cryptography")

COUNTER_PATH = pathlib.Path.home() / ".cipher_msg_counter"

def load_counter() -> int:
    try:
        return struct.unpack(">I", COUNTER_PATH.read_bytes()[:4])[0]
    except FileNotFoundError:
        return 0
    except Exception as e:
        print(f"Warning: counter file error ({e}); starting at 0.")
        return 0

def save_counter(value: int) -> None:
    try:
        COUNTER_PATH.write_bytes(struct.pack(">I", value & 0xFFFFFFFF))
    except Exception as e:
        print(f"Warning: could not persist counter ({e}).")

MSG_COUNTER = load_counter()         

def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def print_home_screen() -> None:
    red, blue, reset = "\033[31m", "\033[34m", "\033[0m"
    banner = f"""{red}
██╗  ██╗███████╗██╗   ██╗███████╗███████╗███╗   ██╗███████╗███████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
█████╔╝ █████╗   ╚████╔╝ ███████╗█████╗  ██╔██╗ ██║███████╗█████╗  
██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝  
██║  ██╗███████╗   ██║   ███████║███████╗██║ ╚████║███████║███████╗
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
{reset}"""
    print(banner)
    print(blue + "C A S C A D E   T E X T   C I P H E R" + reset)
    print(red  + "Version 1.01" + reset)
    print("By Joshua M Clatney – Ethical Pentesting Enthusiast")
    print("----------------------------------------------------")
    print("1. Encrypt text")
    print("2. Decrypt text")

def pre_encrypt_transform(pt: str) -> bytes:
    data = pt.encode('utf‑8')
    ps, pe = random.randint(0, 255), random.randint(0, 255)
    return bytes([ps, pe]) + os.urandom(ps) + data + os.urandom(pe)


def post_decrypt_transform(buf: bytes) -> str:
    if len(buf) < 2:
        raise ValueError("Buffer too short for header.")
    ps, pe = buf[0], buf[1]
    core = buf[2 + ps: len(buf) - pe] if pe else buf[2 + ps:]
    return core.decode('utf‑8')

BLOCK = 256  

def derive_permutation(seed: bytes) -> list[int]:
    return sorted(range(BLOCK), key=lambda i: (seed[i], i))


def transpose_encrypt(data: bytes, π: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        blk = data[i:i + BLOCK]
        out.extend(blk[j] for j in π) if len(blk) == BLOCK else out.extend(blk)
    return bytes(out)


def transpose_decrypt(data: bytes, π: list[int]) -> bytes:
    inv = [0] * BLOCK
    for i, p in enumerate(π):
        inv[p] = i
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        blk = data[i:i + BLOCK]
        out.extend(blk[inv[j]] for j in range(BLOCK)) if len(blk) == BLOCK else out.extend(blk)
    return bytes(out)

ARGON_MEM  = 192 * 1024             
ARGON_TIME = 3
ARGON_OUT  = 64
NONCE_LEN  = 12

def derive_master(pw: str, nonce: bytes) -> bytes:
    return hash_secret_raw(
        pw.encode('utf‑8'), nonce,
        time_cost=ARGON_TIME, memory_cost=ARGON_MEM,
        parallelism=1, hash_len=ARGON_OUT, type=Type.ID
    )


def kdf(master: bytes, nonce: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=nonce, info=info).derive(master)

def encrypt(pt: str, pw: str) -> str:
    global MSG_COUNTER
    nonce   = os.urandom(NONCE_LEN)
    master  = derive_master(pw, nonce)
    key_enc = kdf(master, nonce, b"enc", 32)
    π       = derive_permutation(kdf(master, nonce, b"perm", BLOCK))

    prepared   = pre_encrypt_transform(pt)
    transposed = transpose_encrypt(prepared, π)
    ct_tag     = ChaCha20Poly1305(key_enc).encrypt(nonce, transposed, None)
    compressed = zlib.compress(ct_tag)

    counter_bytes = struct.pack(">I", MSG_COUNTER & 0xFFFFFFFF)
    MSG_COUNTER += 1
    save_counter(MSG_COUNTER)

    return base64.b64encode(nonce + counter_bytes + compressed).decode('ascii')


def decrypt(ct_b64: str, pw: str) -> str:
    try:
        raw = base64.b64decode(ct_b64)
    except Exception as e:
        return f"Base64 decode error: {e}"

    if len(raw) < NONCE_LEN + 4 + 2:
        return "Error: ciphertext too short."

    nonce, cnt_b, comp = raw[:NONCE_LEN], raw[NONCE_LEN:NONCE_LEN + 4], raw[NONCE_LEN + 4:]
    try:
        ct_tag = zlib.decompress(comp)
    except Exception as e:
        return f"Decompression error: {e}"

    master  = derive_master(pw, nonce)
    key_enc = kdf(master, nonce, b"enc", 32)
    π       = derive_permutation(kdf(master, nonce, b"perm", BLOCK))

    try:
        transposed = ChaCha20Poly1305(key_enc).decrypt(nonce, ct_tag, None)
    except Exception as e:
        return f"Auth failure or corrupt data: {e}"

    try:
        payload = transpose_decrypt(transposed, π)
        return post_decrypt_transform(payload) 
    except Exception as e:
        return f"Padding / transposition error: {e}"

def prompt(label: str) -> str:
    s = input(label).strip()
    if not s:
        print("Error: input may not be empty."); sys.exit(1)
    return s


def process_encrypt():
    print("\nEncrypted text:\n",
          encrypt(prompt("Enter text to encrypt: "), prompt("Enter password: ")))


def process_decrypt():
    print("\nDecrypted text:\n",
          decrypt(prompt("Enter text to decrypt: "), prompt("Enter password: ")))


def main() -> None:
    while True:
        clear_screen(); print_home_screen()
        c = input("Choose an option (1 or 2): ").strip()
        if c == '1':
            process_encrypt()
        elif c == '2':
            process_decrypt()
        else:
            print("Invalid option. Choose 1 or 2.")
        input("\nPress Enter to return to the home screen...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye!")