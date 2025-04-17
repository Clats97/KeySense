import os
import hashlib
import zlib
import random
import string
import base64
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

ASCII_ART = r"""
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
"""

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


def pre_encrypt_transform(plaintext: str) -> str:
    compressed = zlib.compress(plaintext.encode('utf‑8'))
    hex_str = compressed.hex().upper()
    alpha_str = hex_to_alpha(hex_str)
    pad_length_start = random.randint(5, 10)
    pad_length_end = random.randint(5, 10)
    start_padding = ''.join(random.choices(string.ascii_uppercase, k=pad_length_start))
    end_padding = ''.join(random.choices(string.ascii_uppercase, k=pad_length_end))
    header = f"{pad_length_start:02d}{pad_length_end:02d}"
    return header + start_padding + alpha_str + end_padding


def post_decrypt_transform(transformed: str) -> str:
    pad_length_start = int(transformed[:2])
    pad_length_end = int(transformed[2:4])
    core = transformed[4 + pad_length_start: -pad_length_end] if pad_length_end != 0 else transformed[4 + pad_length_start:]
    hex_str = alpha_to_hex(core)
    return zlib.decompress(bytes.fromhex(hex_str)).decode('utf‑8')
def generate_subkey(keyword: str, iv: bytes, salt: bytes, iterations: int = 100_000, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', keyword.encode('utf‑8'), iv + salt, iterations, dklen=length)


INJECTION_INTERVAL = 8
INITIAL_KEY_LENGTH = INJECTION_INTERVAL
BLOCK_SIZE = 8
KDF_ITERATIONS = 100_000
SUBKEY_LENGTH = 32


def autokey_encrypt(plain: str, subkey: bytes, iv: bytes) -> str:
    result, effective_key = [], []
    for i in range(INITIAL_KEY_LENGTH):
        iv_shift = iv[i] % 26 if i < len(iv) else 0
        effective_key.append((subkey[i] % 26 + iv_shift) % 26)

    pointer, counter = INITIAL_KEY_LENGTH, 0
    for char in plain:
        if char.isalpha():
            shift = effective_key.pop(0)
            val = ord(char) - ord('A')
            enc = (val + shift) % 26
            result.append(chr(enc + ord('A')))
            counter += 1
            if counter % INJECTION_INTERVAL == 0:
                effective_key.append(subkey[pointer] % 26)
                pointer += 1
            effective_key.append(val)
        else:
            result.append(char)
    return ''.join(result)


def autokey_decrypt(cipher: str, subkey: bytes, iv: bytes) -> str:
    result, effective_key = [], []
    for i in range(INITIAL_KEY_LENGTH):
        iv_shift = iv[i] % 26 if i < len(iv) else 0
        effective_key.append((subkey[i] % 26 + iv_shift) % 26)

    pointer, counter = INITIAL_KEY_LENGTH, 0
    for char in cipher:
        if char.isalpha():
            shift = effective_key.pop(0)
            val = ord(char) - ord('A')
            dec = (val - shift + 26) % 26
            result.append(chr(dec + ord('A')))
            counter += 1
            if counter % INJECTION_INTERVAL == 0:
                effective_key.append(subkey[pointer] % 26)
                pointer += 1
            effective_key.append(dec)
        else:
            result.append(char)
    return ''.join(result)


def derive_permutation(subkey: bytes, block_size: int) -> list:
    vals = list(subkey[:block_size])
    idxs = list(range(block_size))
    return sorted(idxs, key=lambda x: vals[x])


def transposition_encrypt(text: str, subkey: bytes, block_size: int = BLOCK_SIZE) -> str:
    perm = derive_permutation(subkey, block_size)
    out = []
    for i in range(0, len(text), block_size):
        blk = list(text[i:i + block_size])
        if len(blk) == block_size:
            tmp = [''] * block_size
            for j in range(block_size):
                tmp[j] = blk[perm[j]]
            out.append(''.join(tmp))
        else:
            out.append(''.join(blk))
    return ''.join(out)


def transposition_decrypt(text: str, subkey: bytes, block_size: int = BLOCK_SIZE) -> str:
    perm = derive_permutation(subkey, block_size)
    inv = [0] * block_size
    for i, p in enumerate(perm):
        inv[p] = i
    out = []
    for i in range(0, len(text), block_size):
        blk = list(text[i:i + block_size])
        if len(blk) == block_size:
            tmp = [''] * block_size
            for j in range(block_size):
                tmp[j] = blk[inv[j]]
            out.append(''.join(tmp))
        else:
            out.append(''.join(blk))
    return ''.join(out)


def full_encrypt(plaintext: str, keyword: str) -> str:
    iv = os.urandom(8)
    salt = os.urandom(8)
    subkey = generate_subkey(keyword, iv, salt, iterations=KDF_ITERATIONS, length=SUBKEY_LENGTH)
    transformed = pre_encrypt_transform(plaintext)
    auto = autokey_encrypt(transformed, subkey, iv)
    trans = transposition_encrypt(auto, subkey)
    final = iv + salt + trans.encode('ascii')
    return base64.b64encode(final).decode('ascii')


def full_decrypt(ciphertext: str, keyword: str) -> str:
    try:
        data = base64.b64decode(ciphertext)
    except Exception as e:
        return f"Error decoding base64: {e}"
    if len(data) < 16:
        return "Error: Ciphertext too short."
    iv, salt = data[:8], data[8:16]
    cin = data[16:]
    try:
        cin_text = cin.decode('ascii')
    except Exception as e:
        return f"Error decoding ciphertext bytes: {e}"
    subkey = generate_subkey(keyword, iv, salt, iterations=KDF_ITERATIONS, length=SUBKEY_LENGTH)
    auto = transposition_decrypt(cin_text, subkey)
    transformed = autokey_decrypt(auto, subkey, iv)
    try:
        return post_decrypt_transform(transformed)
    except Exception as e:
        return f"Error during decompression/depadding: {e}"

class AutokeyCipherGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KeySense Cipher GUI v1.00")
        self.geometry("1040x760")
        self.minsize(940, 660)
        banner = tk.Label(self, text=ASCII_ART, font=("Courier New", 10, "bold"),
                          foreground="#c0392b", justify="center")
        banner.pack(pady=(10, 0))
        title_row = ttk.Frame(self)
        title_row.pack(pady=(5, 0))

        title_lbl = tk.Label(title_row,
                             text="E N H A N C E D   A U T O K E Y   C I P H E R",
                             font=("Helvetica", 14, "bold"),
                             foreground="#2980b9")
        title_lbl.pack(side="left")

        version_lbl = tk.Label(title_row, text="  Version 1.00",
                               font=("Helvetica", 14, "bold"),
                               foreground="#c0392b")
        version_lbl.pack(side="left")

        subtitle = tk.Label(self,
                            text="By Joshua M Clatney – Ethical Pentesting Enthusiast",
                            font=("Helvetica", 10), foreground="#2c3e50")
        subtitle.pack(pady=(0, 15))
        key_frame = ttk.Frame(self)
        key_frame.pack(pady=(0, 10), fill="x", padx=50)
        ttk.Label(key_frame, text="Keyword (A‑Z only):").grid(row=0, column=0, sticky="w")
        self.keyword_entry = ttk.Entry(key_frame, width=30)
        self.keyword_entry.grid(row=0, column=1, sticky="w", padx=(5, 0))
        ttk.Button(key_frame, text="Copy", width=6, command=self.copy_keyword).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(key_frame, text="Paste", width=6, command=self.paste_keyword).grid(row=0, column=3, padx=(5, 0))
        text_frame = ttk.Frame(self)
        text_frame.pack(expand=True, fill="both", padx=50)

        ttk.Label(text_frame, text="Input (Plaintext or Ciphertext):").grid(row=0, column=0, sticky="w")
        ttk.Label(text_frame, text="Output:").grid(row=0, column=1, sticky="w")

        self.input_text = scrolledtext.ScrolledText(text_frame, wrap="word", width=60,
                                                    height=15, font=("Courier New", 10))
        self.output_text = scrolledtext.ScrolledText(text_frame, wrap="word", width=60,
                                                     height=15, font=("Courier New", 10))

        self.input_text.grid(row=1, column=0, padx=(0, 10), pady=(0, 5), sticky="nsew")
        self.output_text.grid(row=1, column=1, pady=(0, 5), sticky="nsew")

        inp_btn_frame = ttk.Frame(text_frame)
        out_btn_frame = ttk.Frame(text_frame)
        inp_btn_frame.grid(row=2, column=0, pady=(0, 10))
        out_btn_frame.grid(row=2, column=1, pady=(0, 10))

        ttk.Button(inp_btn_frame, text="Copy", width=6, command=self.copy_input).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(inp_btn_frame, text="Paste", width=6, command=self.paste_input).grid(row=0, column=1)
        ttk.Button(out_btn_frame, text="Copy", width=6, command=self.copy_output).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(out_btn_frame, text="Paste", width=6, command=self.paste_output).grid(row=0, column=1)

        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=(0, 15))

        ttk.Button(btn_frame, text="Encrypt →", command=self.encrypt_action)\
            .grid(row=0, column=0, padx=10, ipadx=10, ipady=5)
        ttk.Button(btn_frame, text="Decrypt →", command=self.decrypt_action)\
            .grid(row=0, column=1, padx=10, ipadx=10, ipady=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_action)\
            .grid(row=0, column=2, padx=10, ipadx=10, ipady=5)

        self.bind_all("<Control-e>", lambda e: self.encrypt_action())
        self.bind_all("<Control-d>", lambda e: self.decrypt_action())
        self.bind_all("<Control-l>", lambda e: self.clear_action())

    def _copy_to_clip(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _paste_from_clip(self) -> str:
        try:
            return self.clipboard_get()
        except tk.TclError:
            return ""

    def copy_keyword(self):
        self._copy_to_clip(self.keyword_entry.get())

    def paste_keyword(self):
        self.keyword_entry.delete(0, tk.END)
        self.keyword_entry.insert(0, self._paste_from_clip().strip())

    def copy_input(self):
        self._copy_to_clip(self.input_text.get("1.0", "end-1c"))

    def paste_input(self):
        self.input_text.insert(tk.INSERT, self._paste_from_clip())

    def copy_output(self):
        self._copy_to_clip(self.output_text.get("1.0", "end-1c"))

    def paste_output(self):
        self.output_text.insert(tk.INSERT, self._paste_from_clip())

    def _get_keyword(self) -> str:
        kw = self.keyword_entry.get().strip().upper()
        if not kw:
            messagebox.showerror("Keyword Missing", "Please provide a keyword (A–Z only).")
            return ""
        if not kw.isalpha():
            messagebox.showerror("Keyword Error", "Keyword must consist of alphabetic characters A–Z only.")
            return ""
        return kw

    def encrypt_action(self):
        keyword = self._get_keyword()
        if not keyword:
            return
        plaintext = self.input_text.get("1.0", "end-1c")
        if not plaintext.strip():
            messagebox.showerror("Input Missing", "Please enter plaintext to encrypt.")
            return
        try:
            cipher = full_encrypt(plaintext, keyword)
        except Exception as exc:
            messagebox.showerror("Encryption Error", str(exc))
            return
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", cipher)

    def decrypt_action(self):
        keyword = self._get_keyword()
        if not keyword:
            return
        ciphertext = self.input_text.get("1.0", "end-1c").strip()
        if not ciphertext:
            messagebox.showerror("Input Missing", "Please enter ciphertext to decrypt.")
            return
        plain = full_decrypt(ciphertext, keyword)
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", plain)

    def clear_action(self):
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")

if __name__ == "__main__":
    AutokeyCipherGUI().mainloop()