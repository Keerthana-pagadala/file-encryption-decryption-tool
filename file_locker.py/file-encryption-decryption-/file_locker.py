import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets

# Key Derivation Function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encryption Function
def decrypt_file(file_path, password):
    try:
        print(f"Decrypting file: {file_path}")  # Prints file path to terminal
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_file_path = file_path.replace(".enc", "_decrypted")
        print(f"Saving decrypted file as: {decrypted_file_path}")  # Check saved location

        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as:\n{decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))
# Decryption Function
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()

        salt = raw_data[:16]
        iv = raw_data[16:32]
        encrypted_data = raw_data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        output_path = file_path.replace(".enc", "_decrypted")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
def open_encrypt_window():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if password:
            encrypt_file(file_path, password)
        else:
            messagebox.showwarning("Warning", "Please enter a password!")

def open_decrypt_window():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if password:
            decrypt_file(file_path, password)
        else:
            messagebox.showwarning("Warning", "Please enter a password!")

# Main GUI Window
root = tk.Tk()
root.title("File Encryption/Decryption Tool")
root.geometry("400x250")
root.resizable(False, False)

title_label = tk.Label(root, text="Secure File Locker", font=("Helvetica", 18, "bold"))
title_label.pack(pady=10)

password_label = tk.Label(root, text="Enter Password:", font=("Helvetica", 12))
password_label.pack()

password_entry = tk.Entry(root, show="*", width=30, font=("Helvetica", 12))
password_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt File", command=open_encrypt_window, bg="#4CAF50", fg="white", width=20, height=2)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=open_decrypt_window, bg="#2196F3", fg="white", width=20, height=2)
decrypt_button.pack()

root.mainloop()