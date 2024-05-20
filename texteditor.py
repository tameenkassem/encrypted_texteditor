import tkinter as tk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.simpledialog import askstring
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os

def generate_salt(length=16):
    """Generate a random salt."""
    return os.urandom(length)

def generate_key_from_password(password_provided, salt):
    password = password_provided.encode() #convert to type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_text(text_to_encrypt, key):
    fernet = Fernet(key)
    return fernet.encrypt(text_to_encrypt.encode())

def decrypt_text(text_to_decrypt, key):
    fernet = Fernet(key)
    try:
        return fernet.decrypt(text_to_decrypt).decode()
    except Exception as e:
        raise ValueError("Decryption failed.") from e
    

def prompt_for_password(window):
    return askstring("Password", "Enter Password:", show='*',parent=window)

def open_file(window, text_edit):
    filepath = askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

    if not filepath:
        return
    password = prompt_for_password(window)
    if not password:
        messagebox.showerror("Error", "No Password provided.")
        return

    text_edit.delete(1.0,tk.END)
    with open(filepath, "rb") as f:
        file_content = f.read()
        salt = file_content[:16]
        encrypted_content = file_content[16:]
        key = generate_key_from_password(password, salt)

        try:
            decrypted_content = decrypt_text(encrypted_content, key)
            text_edit.insert(tk.END, decrypted_content)
        except ValueError as e:
            messagebox.showerror("Error", "Failed to decrypt file. Wrong password or corrupted file.")
        window.title(f"Opened: {filepath}")
     

def save_file(window, text_edit):
    filepath = asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
 
    if not filepath:
        return
    password = prompt_for_password(window)
    if not password:
        messagebox.showerror("Error", "No Password provided.")
        return
    salt = generate_salt()
    key = generate_key_from_password(password, salt)
    
    content = text_edit.get(1.0, tk.END)
    encrypted_content = encrypt_text(content, key)

    with open(filepath, "wb") as f:
        f.write(salt + encrypted_content) #stores salt and encrypted content together
    window.title(f"Saved: {filepath}")
  
def main():
    window = tk.Tk()
    window.title("Encrypted Text editor")

    
    window.rowconfigure(0, minsize=400)
    window.columnconfigure(1, minsize=500)

    text_edit = tk.Text(window, font="Helvetica 13")
    text_edit.grid(row=0, column=1)

    frame = tk.Frame(window, relief=tk.RAISED, bd=2)

    #buttons
    save_button = tk.Button(frame, text="Save", command=lambda: save_file(window, text_edit))
    open_button = tk.Button(frame, text="Open", command=lambda: open_file(window, text_edit))

    save_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
    open_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

#sticky - north south
    frame.grid(row=1, column=1, sticky="ns")

    window.mainloop()

main()
