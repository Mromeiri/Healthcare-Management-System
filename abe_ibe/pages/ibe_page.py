import customtkinter as ctk
from tkinter import messagebox
import base64
import hashlib
from Crypto.Cipher import AES

class IBEPage:
    def __init__(self, main_frame):
        self.main_frame = main_frame
        self.user_list_ibe = []
        self.create_page()

    def create_page(self):
        """Display Identity-Based Encryption (IBE) page."""
        # Clear existing widgets
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Main container
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=20, pady=20)

        # Title
        title = ctk.CTkLabel(
            container, 
            text="Identity-Based Encryption (IBE)", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=10)

        # User Management Frame
        user_frame = ctk.CTkFrame(container)
        user_frame.pack(pady=10, fill="x")

        # Username Entry
        username_label = ctk.CTkLabel(user_frame, text="User ID:", font=ctk.CTkFont(size=14))
        username_label.pack(side="left", padx=(0, 10))
        username_entry = ctk.CTkEntry(user_frame, width=300)
        username_entry.pack(side="left", padx=(0, 10))

        # User Dropdown
        user_var = ctk.StringVar()
        user_dropdown = ctk.CTkComboBox(
            container, 
            variable=user_var, 
            values=self.user_list_ibe,
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
            if user_id and user_id not in self.user_list_ibe:
                self.user_list_ibe.append(user_id)
                user_dropdown.configure(values=self.user_list_ibe)
                user_var.set(user_id)
                messagebox.showinfo("Success", f"User {user_id} added successfully!")
            else:
                messagebox.showerror("Error", "Please enter a unique user ID.")

        def encrypt_action():
            selected_user = user_var.get()
            msg = encrypt_entry.get().strip()
            if selected_user and msg:
                encrypted_msg = self.encrypt_message_ibe(selected_user, msg)
                encrypted_var.set(encrypted_msg)
            else:
                messagebox.showerror("Error", "Select a user and enter a message.")

        def decrypt_action():
            selected_user = user_var.get()
            encrypted_msg = decrypt_entry.get().strip()
            if selected_user and encrypted_msg:
                decrypted_msg = self.decrypt_message_ibe(selected_user, encrypted_msg)
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

    def derive_key_ibe(self, user_id):
        """Generate AES key from user ID."""
        return hashlib.sha256(user_id.encode()).digest()

    def encrypt_message_ibe(self, user_id, plaintext):
        """Encrypt a message with AES using user ID."""
        key = self.derive_key_ibe(user_id)
        cipher = AES.new(key, AES.MODE_ECB)
        padded_text = plaintext.ljust(16)[:16]  # Padding for AES (16 bytes)
        encrypted_bytes = cipher.encrypt(padded_text.encode())
        return base64.b64encode(encrypted_bytes).decode()

    def decrypt_message_ibe(self, user_id, encrypted_text):
        """Decrypt a message using user ID."""
        try:
            key = self.derive_key_ibe(user_id)
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_bytes = base64.b64decode(encrypted_text)
            decrypted_text = cipher.decrypt(encrypted_bytes).decode().strip()
            return decrypted_text
        except Exception:
            return "Decryption error."

def show_ibe_page(main_frame):
    """Create an instance of IBE page."""
    return IBEPage(main_frame)