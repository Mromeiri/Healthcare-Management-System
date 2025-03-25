import customtkinter as ctk

def show_home_page(main_frame):
    """Display the home page."""
    # Clear existing widgets in main frame
    for widget in main_frame.winfo_children():
        widget.destroy()

    # Welcome Label
    welcome_label = ctk.CTkLabel(
        main_frame, 
        text="Encryption Toolkit", 
        font=ctk.CTkFont(size=24, weight="bold")
    )
    welcome_label.pack(pady=(20, 10))

    # Subtitle
    subtitle = ctk.CTkLabel(
        main_frame, 
        text="Explore Attribute-Based and Identity-Based Encryption",
        font=ctk.CTkFont(size=16)
    )
    subtitle.pack(pady=(0, 20))

    # Description
    description = ctk.CTkLabel(
        main_frame, 
        text=(
            "This toolkit demonstrates two advanced encryption techniques:\n\n"
            "1. Attribute-Based Encryption (ABE):\n"
            "   - Encrypt messages based on user attributes\n"
            "   - Flexible access control mechanism\n\n"
            "2. Identity-Based Encryption (IBE):\n"
            "   - Use user identities as encryption keys\n"
            "   - Simplifies key management"
        ),
        font=ctk.CTkFont(size=14),
        justify="left"
    )
    description.pack(pady=20)