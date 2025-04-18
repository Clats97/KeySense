#!/usr/bin/env python3
"""
KeySense Cipher (terminal edition) – Version 1.10
=================================================
• Unlimited HMAC‑SHA‑256 keystream (no index overflow on long messages)  
• PBKDF2 cost raised to 1 000 000 iterations  
• Behaviour and I/O otherwise identical to v1.00
"""
import os
import zlib
import hmac
import struct
import hashlib
import random
import string
import base64

# ----------------------------- 0.  ASCII art banner -------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_home_screen():
    red, blue, reset = "\033[31m", "\033[34m", "\033[0m"
    ascii_art = f"""{red}
██╗  ██╗███████╗██╗   ██╗███████╗███████╗███╗   ██╗███████╗███████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
█████╔╝ █████╗   ╚████╔╝ ███████╗█████╗  ██╔██╗ ██║███████╗█████╗  
██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝  
██║  ██╗███████╗   ██║   ███████║███████╗██║ ╚████║███████║███████╗
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                    
             ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗             
            ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗            
            ██║     ██║██████╔╝███████║█████╗  ██████╔╝            
            ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗            
            ╚██████╗██║██║     ██║  ██║███████╗██║  ██║            
             ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝            
{reset}"""
    print(ascii_art)
    print(blue + "E N H A N C E D   A U T O K E Y   C I P H E R" + reset, end=" ")
    print(red + "Version 1.10" + reset)
    print("By Joshua M Clatney – Ethical Pentesting Enthusiast")
    print("-----------------------------------------------------")
    print("Options:")
    print("1. Encrypt text")
    print("2. Decrypt text\n")


# --------------------------- 1.  Hex ↔ A‑P mapping --------------------------
_HEX_TO_ALPHA = {  '0':'A','1':'B','2':'C','3':'D','4':'E','5':'F',
                   '6':'G','7':'H','8':'I','9':'J','A':'K','B':'L',
                   'C':'M','D':'N','E':'O','F':'P' }
_ALPHA_TO_HEX = {v:k for k,v in _HEX_TO_ALPHA.items()}

def hex_to_alpha(s: str) -> str:  return ''.join(_HEX_TO_ALPHA[c] for c in s)
def alpha_to_hex(s: str) -> str: return ''.join(_ALPHA_TO_HEX[c] for c in s)


# --------------------------- 2.  Transform helpers --------------------------
def pre_encrypt_transform(pt: str) -> str:
    compressed = zlib.compress(pt.encode('utf‑8'))
    alpha_core = hex_to_alpha(compressed.hex().upper())

    pad_s = random.randint(5, 10)
    pad_e = random.randint(5, 10)
    head  = f"{pad_s:02d}{pad_e:02d}"
    start = ''.join(random.choices(string.ascii_uppercase, k=pad_s))
    end   = ''.join(random.choices(string.ascii_uppercase, k=pad_e))
    return head + start + alpha_core + end


def post_decrypt_transform(s: str) -> str:
    pad_s, pad_e = int(s[:2]), int(s[2:4])
    core = s[4 + pad_s: -pad_e] if pad_e else s[4 + pad_s:]
    return zlib.decompress(bytes.fromhex(alpha_to_hex(core))).decode('utf‑8')


# --------------------------- 3.  Key derivation -----------------------------
KDF_ITERATIONS = 1_000_000
SUBKEY_LENGTH  = 32
def generate_subkey(keyword: str, iv: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', keyword.encode('utf‑8'),
                               iv + salt, KDF_ITERATIONS, dklen=SUBKEY_LENGTH)


# --------------------------- 4.  Unlimited keystream ------------------------
def keystream_gen(subkey: bytes, iv: bytes):
    ctr = 0
    while True:
        block = hmac.new(subkey, iv + struct.pack('>Q', ctr),
                         hashlib.sha256).digest()
        for b in block:
            yield b % 26
        ctr += 1


# --------------------------- 5.  Autokey (stream) ---------------------------
def autokey_encrypt(plain: str, subkey: bytes, iv: bytes) -> str:
    ks = keystream_gen(subkey, iv)
    out = []
    for ch in plain:
        if ch.isalpha():
            p = ord(ch.upper()) - 65
            c = (p + next(ks)) % 26
            out.append(chr(c + 65))
        else:
            out.append(ch)
    return ''.join(out)


def autokey_decrypt(cipher: str, subkey: bytes, iv: bytes) -> str:
    ks = keystream_gen(subkey, iv)
    out = []
    for ch in cipher:
        if ch.isalpha():
            c = ord(ch.upper()) - 65
            p = (c - next(ks) + 26) % 26
            out.append(chr(p + 65))
        else:
            out.append(ch)
    return ''.join(out)


# --------------------------- 6.  Block‑8 transposition ----------------------
BLOCK_SIZE = 8
def derive_permutation(subkey: bytes, n: int = BLOCK_SIZE):
    idx = list(range(n))
    return sorted(idx, key=lambda i: subkey[i])


def transposition_encrypt(text: str, subkey: bytes) -> str:
    perm = derive_permutation(subkey)
    out  = []
    for i in range(0, len(text), BLOCK_SIZE):
        blk = list(text[i:i+BLOCK_SIZE])
        if len(blk) == BLOCK_SIZE:
            tmp = ['']*BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                tmp[j] = blk[perm[j]]
            out.append(''.join(tmp))
        else:
            out.append(''.join(blk))
    return ''.join(out)


def transposition_decrypt(text: str, subkey: bytes) -> str:
    perm = derive_permutation(subkey)
    inv  = [0]*BLOCK_SIZE
    for i,p in enumerate(perm): inv[p] = i
    out = []
    for i in range(0, len(text), BLOCK_SIZE):
        blk = list(text[i:i+BLOCK_SIZE])
        if len(blk) == BLOCK_SIZE:
            tmp = ['']*BLOCK_SIZE
            for j in range(BLOCK_SIZE):
                tmp[j] = blk[inv[j]]
            out.append(''.join(tmp))
        else:
            out.append(''.join(blk))
    return ''.join(out)


# --------------------------- 7.  High‑level wrappers ------------------------
def full_encrypt(pt: str, keyword: str) -> str:
    iv, salt = os.urandom(8), os.urandom(8)
    sub      = generate_subkey(keyword, iv, salt)
    stage1   = pre_encrypt_transform(pt)
    stage2   = autokey_encrypt(stage1, sub, iv)
    stage3   = transposition_encrypt(stage2, sub)
    return base64.b64encode(iv + salt + stage3.encode('ascii')).decode('ascii')


def full_decrypt(ct: str, keyword: str) -> str:
    try:
        raw = base64.b64decode(ct)
    except Exception as exc:
        return "Error decoding base64: " + str(exc)
    if len(raw) < 16:
        return "Error: Ciphertext too short."

    iv, salt, body = raw[:8], raw[8:16], raw[16:]
    try:
        body_ascii = body.decode('ascii')
    except UnicodeDecodeError as exc:
        return "Error decoding ciphertext bytes: " + str(exc)

    sub      = generate_subkey(keyword, iv, salt)
    stage2   = transposition_decrypt(body_ascii, sub)
    stage1   = autokey_decrypt(stage2, sub, iv)
    try:
        return post_decrypt_transform(stage1)
    except Exception as exc:
        return "Error during decompression/depadding: " + str(exc)


# --------------------------- 8.  CLI helpers --------------------------------
def process_encrypt():
    text = input("Enter text to encrypt: ")
    keyword = input("Enter keyword: ").strip().upper()
    if not text:
        print("Error: Please provide non‑empty text."); return
    if not keyword.isalpha():
        print("Error: Keyword must be alphabetic.");    return
    print("\nEncrypted text:\n", full_encrypt(text, keyword))


def process_decrypt():
    text = input("Enter text to decrypt: ")
    keyword = input("Enter keyword: ").strip().upper()
    if not text:
        print("Error: Please provide non‑empty text."); return
    if not keyword.isalpha():
        print("Error: Keyword must be alphabetic.");    return
    print("\nDecrypted text:\n", full_decrypt(text, keyword))


def main():
    while True:
        clear_screen()
        print_home_screen()
        choice = input("Choose an option (1 or 2): ").strip()
        if   choice == '1': process_encrypt()
        elif choice == '2': process_decrypt()
        else: print("Invalid option. Choose 1 or 2.")
        input("\nPress Enter to return to the home screen...")


if __name__ == "__main__":
    main()