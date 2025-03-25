import customtkinter as ctk
from tkinter import messagebox
import os
import json
import base64
import hashlib
from Crypto.Cipher import AES

class ABEPage:
    def __init__(self, main_frame):
        self.main_frame = main_frame
        self.user_dict_abe = {}
        self.create_page()

    def create_page(self):
        """Create the Attribute-Based Encryption page."""
        # Clear existing widgets
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Main container
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=20, pady=20)

        # Title
        title = ctk.CTkLabel(
            container, 
            text="Attribute-Based Encryption (ABE)", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=10)

        # User Management Frame
        user_frame = ctk.CTkFrame(container)
        user_frame.pack(pady=10, fill="x")

        # Username Entry
        username_label = ctk.CTkLabel(user_frame, text="Username:", font=ctk.CTkFont(size=14))
        username_label.pack(side="left", padx=(0, 10))
        username_entry = ctk.CTkEntry(user_frame, width=200)
        username_entry.pack(side="left", padx=(0, 10))

        # Attributes Entry
        attr_label = ctk.CTkLabel(user_frame, text="Attributes (comma-separated):", font=ctk.CTkFont(size=14))
        attr_label.pack(side="left", padx=(10, 10))
        attr_entry = ctk.CTkEntry(user_frame, width=300)
        attr_entry.pack(side="left", padx=(0, 10))

        # User Dropdown
        user_var = ctk.StringVar()
        user_dropdown = ctk.CTkComboBox(
            container, 
            variable=user_var, 
            values=list(self.user_dict_abe.keys()),
            state="readonly",
            width=300
        )
        user_dropdown.pack(pady=10)

        # Encryption Frame
        encrypt_frame = ctk.CTkFrame(container)
        encrypt_frame.pack(pady=10, fill="x")

        # Encryption Input
        encrypt_label = ctk.CTkLabel(encrypt_frame, text="Message to Encrypt:", font=ctk.CTkFont(size=14))
        encrypt_label.pack(side="left", padx=(0, 10))
        encrypt_entry = ctk.CTkEntry(encrypt_frame, width=400)
        encrypt_entry.pack(side="left", padx=(0, 10))

        # Encrypted Result
        encrypted_var = ctk.StringVar()
        encrypted_result = ctk.CTkEntry(
            container, 
            textvariable=encrypted_var, 
            state="readonly", 
            width=600
        )
        encrypted_result.pack(pady=10)

        # Decryption Frame
        decrypt_frame = ctk.CTkFrame(container)
        decrypt_frame.pack(pady=10, fill="x")

        # Decryption Input
        decrypt_label = ctk.CTkLabel(decrypt_frame, text="Message to Decrypt:", font=ctk.CTkFont(size=14))
        decrypt_label.pack(side="left", padx=(0, 10))
        decrypt_entry = ctk.CTkEntry(decrypt_frame, width=400)
        decrypt_entry.pack(side="left", padx=(0, 10))

        # Decrypted Result
        decrypted_var = ctk.StringVar()
        decrypted_result = ctk.CTkEntry(
            container, 
            textvariable=decrypted_var, 
            state="readonly", 
            width=600
        )
        decrypted_result.pack(pady=10)

        def add_user():
            user_id = username_entry.get().strip()
            attributes = [attr.strip() for attr in attr_entry.get().split(",") if attr.strip()]
            if user_id and attributes:
                self.user_dict_abe[user_id] = attributes
                user_dropdown.configure(values=list(self.user_dict_abe.keys()))
                user_var.set(user_id)
                messagebox.showinfo("Success", f"User {user_id} added successfully!")
            else:
                messagebox.showerror("Error", "Please enter username and attributes.")

        def encrypt_action():
            selected_user = user_var.get()
            msg = encrypt_entry.get().strip()
            if selected_user and msg:
                encrypted_msg = self.encrypt_message_abe(self.user_dict_abe[selected_user], msg)
                encrypted_var.set(encrypted_msg)
            else:
                messagebox.showerror("Error", "Select a user and enter a message.")

        def decrypt_action():
            selected_user = user_var.get()
            encrypted_msg = decrypt_entry.get().strip()
            if selected_user and encrypted_msg:
                decrypted_msg = self.decrypt_message_abe(self.user_dict_abe[selected_user], encrypted_msg)
                decrypted_var.set(decrypted_msg)
            else:
                messagebox.showerror("Error", "Select a user and enter an encrypted message.")

        # Buttons
        btn_frame = ctk.CTkFrame(container)
        btn_frame.pack(pady=10)

        add_user_btn = ctk.CTkButton(btn_frame, text="Add User", command=add_user)
        add_user_btn.pack(side="left", padx=10)

        encrypt_btn = ctk.CTkButton(btn_frame, text="Encrypt", command=encrypt_action)
        encrypt_btn.pack(side="left", padx=10)

        decrypt_btn = ctk.CTkButton(btn_frame, text="Decrypt", command=decrypt_action)
        decrypt_btn.pack(side="left", padx=10)

    def derive_key_abe(self, attributes):
        """Generate AES key from attributes."""
        attr_string = "-".join(sorted(attributes))
        return hashlib.sha256(attr_string.encode()).digest()

    def pad(self, text):
        pad_length = 16 - (len(text) % 16)
        return text + chr(pad_length) * pad_length

    def unpad(self, text):
        return text[:-ord(text[-1])]

    def encrypt_message_abe(self, attributes, plaintext):
        """Encrypt a message with AES using attributes."""
        key = self.derive_key_abe(attributes)
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(self.pad(plaintext).encode())
        metadata = json.dumps(attributes).encode()
        return base64.b64encode(iv + metadata + b"||" + encrypted_bytes).decode()

    def decrypt_message_abe(self, user_attributes, encrypted_text):
        """Decrypt a message if user has required attributes."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_text)
            iv = encrypted_bytes[:16]
            metadata_encrypted = encrypted_bytes[16:].split(b"||")
            required_attributes = json.loads(metadata_encrypted[0].decode())
            encrypted_message = metadata_encrypted[1]

            if not set(required_attributes).issubset(set(user_attributes)):
                return "Access denied: insufficient attributes."
            
            key = self.derive_key_abe(required_attributes)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return self.unpad(cipher.decrypt(encrypted_message).decode())
        except Exception:
            return "Decryption error."

def show_abe_page(main_frame):
    """Create an instance of ABE page."""
    return ABEPage(main_frame)