import os
import hashlib
import zlib
import random
import string
import base64

# -----------------------------
# Terminal screen and ASCII art
# -----------------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_home_screen():
    red = "\033[31m"
    blue = "\033[34m"
    black = "\033[30m"
    reset = "\033[0m"
    ascii_art = f"""{red}
██╗   ██╗██╗ ██████╗ ███████╗███╗   ██╗███████╗██████╗ ███████╗     █████╗ ██╗   ██╗████████╗ ██████╗ 
██║   ██║██║██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔══██╗██╔════╝    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
██║   ██║██║██║  ███╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝█████╗      ███████║██║   ██║   ██║   ██║   ██║
╚██╗ ██╔╝██║██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══╝      ██╔══██║██║   ██║   ██║   ██║   ██║
 ╚████╔╝ ██║╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║███████╗    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
  ╚═══╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ 
                                                                                                      
            ██╗  ██╗███████╗██╗   ██╗     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗                               
            ██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗                              
            █████╔╝ █████╗   ╚████╔╝     ██║     ██║██████╔╝███████║█████╗  ██████╔╝                              
            ██╔═██╗ ██╔══╝    ╚██╔╝      ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗                              
            ██║  ██╗███████╗   ██║       ╚██████╗██║██║     ██║  ██║███████╗██║  ██║                              
            ╚═╝  ╚═╝╚══════╝   ╚═╝        ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                              
{reset}"""
    print(ascii_art)
    print(blue + "E N H A N C E D   V I G E N E R E   A U T O K E Y   C I P H E R" + reset, end=" ")
    print(red + "Version 1.00" + reset)
    print(black + "By Joshua M Clatney - Ethical Pentesting Enthusiast" + reset)
    
    print("-----------------------------------------------------")
    print("Options:")
    print("1. Encrypt text")
    print("2. Decrypt text\n")


# -----------------------------
# Hex-to-Alphabet mapping functions
# -----------------------------
# Mapping hex digits (0-9, A-F) to letters.
_HEX_TO_ALPHA = {
    '0': 'A', '1': 'B', '2': 'C', '3': 'D',
    '4': 'E', '5': 'F', '6': 'G', '7': 'H',
    '8': 'I', '9': 'J', 'A': 'K', 'B': 'L',
    'C': 'M', 'D': 'N', 'E': 'O', 'F': 'P'
}

_ALPHA_TO_HEX = {v: k for k, v in _HEX_TO_ALPHA.items()}


def hex_to_alpha(hex_str: str) -> str:
    return "".join(_HEX_TO_ALPHA[c] for c in hex_str)


def alpha_to_hex(alpha_str: str) -> str:
    return "".join(_ALPHA_TO_HEX[c] for c in alpha_str)


# -----------------------------
# Pre-Encrypt and Post-Decrypt Transformations
# -----------------------------
def pre_encrypt_transform(plaintext: str) -> str:
    """
    Compress the plaintext with zlib, hex‑encode the compressed data,
    map hex digits to letters, and add random padding at the beginning and end.
    The first four characters form a header with two 2‑digit numbers indicating padding lengths.
    """
    compressed = zlib.compress(plaintext.encode('utf-8'))
    hex_str = compressed.hex().upper()
    alpha_str = hex_to_alpha(hex_str)
    pad_length_start = random.randint(5, 10)
    pad_length_end = random.randint(5, 10)
    start_padding = ''.join(random.choices(string.ascii_uppercase, k=pad_length_start))
    end_padding = ''.join(random.choices(string.ascii_uppercase, k=pad_length_end))
    header = f"{pad_length_start:02d}{pad_length_end:02d}"
    transformed = header + start_padding + alpha_str + end_padding
    return transformed


def post_decrypt_transform(transformed: str) -> str:
    """
    Remove padding using the header, convert the alphabetic hex back to hexadecimal,
    and decompress to recover the original plaintext.
    """
    pad_length_start = int(transformed[:2])
    pad_length_end = int(transformed[2:4])
    core = transformed[4 + pad_length_start: -pad_length_end] if pad_length_end != 0 else transformed[4 + pad_length_start:]
    hex_str = alpha_to_hex(core)
    decompressed = zlib.decompress(bytes.fromhex(hex_str))
    return decompressed.decode('utf-8')


# -----------------------------
# Subkey Derivation via KDF
# -----------------------------
def generate_subkey(keyword: str, iv: bytes, salt: bytes, iterations: int = 100000, length: int = 32) -> bytes:
    """
    Derive a subkey from the keyword using PBKDF2-HMAC-SHA256.
    Uses (IV || salt) as the salt for the KDF.
    """
    key_bytes = keyword.encode('utf-8')
    subkey = hashlib.pbkdf2_hmac('sha256', key_bytes, iv + salt, iterations, dklen=length)
    return subkey


# -----------------------------
# Autokey Encryption with Periodic Subkey Injection
# -----------------------------
INJECTION_INTERVAL = 8
INITIAL_KEY_LENGTH = INJECTION_INTERVAL  # Use first 8 subkey bytes (modified by IV) as initial keystream.

def autokey_encrypt(plain: str, subkey: bytes, iv: bytes) -> str:
    """
    Encrypt the transformed plaintext using an autokey approach with periodic injection
    of subkey-derived shift values. Non-alphabetic characters remain unchanged.
    """
    result = []
    effective_key = []
    for i in range(INITIAL_KEY_LENGTH):
        iv_shift = iv[i] % 26 if i < len(iv) else 0
        effective_key.append((subkey[i] % 26 + iv_shift) % 26)
    injection_pointer = INITIAL_KEY_LENGTH
    autokey_counter = 0
    for char in plain:
        if char.isalpha():
            shift = effective_key.pop(0)
            char_val = ord(char) - ord('A')
            enc_val = (char_val + shift) % 26
            enc_char = chr(enc_val + ord('A'))
            result.append(enc_char)
            autokey_counter += 1
            if autokey_counter % INJECTION_INTERVAL == 0:
                effective_key.append(subkey[injection_pointer] % 26)
                injection_pointer += 1
            effective_key.append(char_val)
        else:
            result.append(char)
    return "".join(result)


def autokey_decrypt(cipher: str, subkey: bytes, iv: bytes) -> str:
    """
    Reverse the autokey encryption with periodic subkey injection.
    Non-alphabetic characters remain unchanged.
    """
    result = []
    effective_key = []
    for i in range(INITIAL_KEY_LENGTH):
        iv_shift = iv[i] % 26 if i < len(iv) else 0
        effective_key.append((subkey[i] % 26 + iv_shift) % 26)
    injection_pointer = INITIAL_KEY_LENGTH
    autokey_counter = 0
    for char in cipher:
        if char.isalpha():
            shift = effective_key.pop(0)
            enc_val = ord(char) - ord('A')
            plain_val = (enc_val - shift + 26) % 26
            plain_char = chr(plain_val + ord('A'))
            result.append(plain_char)
            autokey_counter += 1
            if autokey_counter % INJECTION_INTERVAL == 0:
                effective_key.append(subkey[injection_pointer] % 26)
                injection_pointer += 1
            effective_key.append(plain_val)
        else:
            result.append(char)
    return "".join(result)


# -----------------------------
# Transposition Cipher (Blockwise Permutation)
# -----------------------------
TRANSPOSTION_BLOCK_SIZE = 8

def derive_permutation(subkey: bytes, block_size: int) -> list:
    """
    Derive a permutation (list of indices) from the first block_size bytes of the subkey.
    """
    values = list(subkey[:block_size])
    indices = list(range(block_size))
    perm = sorted(indices, key=lambda x: values[x])
    return perm


def transposition_encrypt(cipher: str, subkey: bytes, block_size: int = TRANSPOSTION_BLOCK_SIZE) -> str:
    """
    Apply a blockwise transposition to the ciphertext.
    Each block of exactly block_size letters is permuted.
    Incomplete final blocks remain unchanged.
    """
    perm = derive_permutation(subkey, block_size)
    result = []
    for i in range(0, len(cipher), block_size):
        block = list(cipher[i:i + block_size])
        if len(block) == block_size:
            transposed = [''] * block_size
            for j in range(block_size):
                transposed[j] = block[perm[j]]
            result.append("".join(transposed))
        else:
            result.append("".join(block))
    return "".join(result)


def transposition_decrypt(cipher: str, subkey: bytes, block_size: int = TRANSPOSTION_BLOCK_SIZE) -> str:
    """
    Reverse the blockwise transposition applied during encryption.
    """
    perm = derive_permutation(subkey, block_size)
    inv_perm = [0] * block_size
    for i, p in enumerate(perm):
        inv_perm[p] = i
    result = []
    for i in range(0, len(cipher), block_size):
        block = list(cipher[i:i + block_size])
        if len(block) == block_size:
            untransposed = [''] * block_size
            for j in range(block_size):
                untransposed[j] = block[inv_perm[j]]
            result.append("".join(untransposed))
        else:
            result.append("".join(block))
    return "".join(result)


# -----------------------------
# Full Encryption and Decryption Routines (without visible IV/Salt)
# -----------------------------
KDF_ITERATIONS = 100000
SUBKEY_LENGTH = 32  # bytes

def full_encrypt(plaintext: str, keyword: str) -> str:
    """
    Full encryption pipeline:
      1. Generate a random 64-bit IV and 64-bit salt.
      2. Derive the subkey from the keyword.
      3. Pre-transform the plaintext (compress and add padding).
      4. Encrypt with autokey (with periodic subkey injection).
      5. Apply blockwise transposition.
      6. Package the IV and salt (as raw bytes) with the ciphertext and base64‑encode.
    """
    iv = os.urandom(8)    # 64-bit IV
    salt = os.urandom(8)  # 64-bit salt
    subkey = generate_subkey(keyword, iv, salt, iterations=KDF_ITERATIONS, length=SUBKEY_LENGTH)
    
    transformed = pre_encrypt_transform(plaintext)
    auto_cipher = autokey_encrypt(transformed, subkey, iv)
    trans_cipher = transposition_encrypt(auto_cipher, subkey, block_size=TRANSPOSTION_BLOCK_SIZE)
    
    # Combine IV, salt, and ciphertext as raw bytes and then base64-encode
    final_binary = iv + salt + trans_cipher.encode('ascii')
    final_output = base64.b64encode(final_binary).decode('ascii')
    return final_output


def full_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Full decryption pipeline:
      1. Decode the base64 ciphertext and extract the IV (first 8 bytes),
         salt (next 8 bytes), and the remaining ciphertext.
      2. Derive the subkey using the IV and salt.
      3. Reverse blockwise transposition.
      4. Reverse the autokey encryption.
      5. Remove padding and decompress to obtain the original plaintext.
    """
    try:
        final_binary = base64.b64decode(ciphertext)
    except Exception as e:
        return "Error decoding base64: " + str(e)
    
    if len(final_binary) < 16:
        return "Error: Ciphertext too short."
    iv = final_binary[:8]
    salt = final_binary[8:16]
    trans_cipher_bytes = final_binary[16:]
    try:
        trans_cipher = trans_cipher_bytes.decode('ascii')
    except Exception as e:
        return "Error decoding ciphertext bytes: " + str(e)
    
    subkey = generate_subkey(keyword, iv, salt, iterations=KDF_ITERATIONS, length=SUBKEY_LENGTH)
    auto_cipher = transposition_decrypt(trans_cipher, subkey, block_size=TRANSPOSTION_BLOCK_SIZE)
    transformed = autokey_decrypt(auto_cipher, subkey, iv)
    try:
        plaintext = post_decrypt_transform(transformed)
    except Exception as e:
        plaintext = "Error during decompression/depadding: " + str(e)
    return plaintext


# -----------------------------
# Processing Routines for User Interaction
# -----------------------------
def process_encrypt():
    text = input("Enter text to encrypt: ")
    keyword = input("Enter keyword: ").strip().upper()
    
    if not text:
        print("Error: Please provide non-empty text.")
        return
    if not keyword.isalpha():
        print("Error: Keyword must consist of alphabetic characters only.")
        return
    
    result = full_encrypt(text, keyword)
    print("\nEncrypted text:\n", result)


def process_decrypt():
    text = input("Enter text to decrypt: ")
    keyword = input("Enter keyword: ").strip().upper()
    
    if not text:
        print("Error: Please provide non-empty text.")
        return
    if not keyword.isalpha():
        print("Error: Keyword must consist of alphabetic characters only.")
        return
    
    result = full_decrypt(text, keyword)
    print("\nDecrypted text:\n", result)


# -----------------------------
# Main Loop
# -----------------------------
def main():
    while True:
        clear_screen()
        print_home_screen()
        choice = input("Choose an option (1 or 2): ").strip()
        if choice == '1':
            process_encrypt()
        elif choice == '2':
            process_decrypt()
        else:
            print("Invalid option. Please choose 1 or 2.")
        input("\nPress Enter to return to the home screen...")

        
if __name__ == "__main__":
    main()