import customtkinter as ctk
import tkinter as tk
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import subprocess
import page_manager


from pages.home_page import show_home_page
from pages.abe_page import show_abe_page
from pages.ibe_page import show_ibe_page

class ModernApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("Attribute-Based & Identity-Based Encryption")
        self.geometry("1400x900")
        self.minsize(1000, 700)

        # Configure grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Create sidebar frame
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        # Sidebar logo
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Encryption Toolkit", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Navigation buttons
        self.create_nav_button("Home", 1, self.show_home)
        self.create_nav_button("ABE (Attribute-Based)", 2, self.show_abe)
        self.create_nav_button("IBE (Identity-Based)", 3, self.show_ibe)
        self.create_nav_button("EHealth", 4, self.on_ehealth_click)

        # Theme switcher
        self.theme_switch = ctk.CTkSwitch(
            self.sidebar_frame, 
            text="Dark Mode", 
            command=self.toggle_theme
        )
        self.theme_switch.grid(row=7, column=0, padx=20, pady=20, sticky="sw")

        # Main content frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # Initially show home page
        self.show_home()

    def on_ehealth_click(self, event=None):
        """Closes the current window and opens ehealth_main.py"""
        self.destroy()  # Close the main window

        # Open ehealth_main.py
        subprocess.Popen(["python", "./ehealth/ehealth_main.py"])

    def create_nav_button(self, text, row, command):
        """Create a stylish navigation button."""
        button = ctk.CTkButton(
            self.sidebar_frame, 
            text=text, 
            command=command,
            corner_radius=10,
            hover_color=("gray70", "gray30"),
            font=ctk.CTkFont(size=16)
        )
        button.grid(row=row, column=0, padx=20, pady=10, sticky="ew")

    def toggle_theme(self):
        """Toggle between light and dark themes."""
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("light")
            self.theme_switch.configure(text="Light Mode")
        else:
            ctk.set_appearance_mode("dark")
            self.theme_switch.configure(text="Dark Mode")

    def show_home(self):
        """Display the home page."""
        show_home_page(self.main_frame)

    def show_abe(self):
        """Display the Attribute-Based Encryption page."""
        show_abe_page(self.main_frame)

    def show_ibe(self):
        """Display the Identity-Based Encryption page."""
        show_ibe_page(self.main_frame)

def main():
    """Main application entry point."""
    # Set default appearance and color theme
    ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
    ctk.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

    # Create and run the application
    app = ModernApp()
    app.mainloop()

if __name__ == "__main__":
    main()