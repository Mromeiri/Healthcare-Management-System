import tkinter as tk
from tkinter import ttk
from themes.styles import DARK_THEME

class CustomButton(ttk.Button):
    def __init__(self, parent, text, command, style_name="Custom.TButton", **kwargs):
        """
        Un bouton personnalisé utilisant les couleurs du thème.
        Vous pouvez surcharger les options via kwargs.
        """
        # Configuration de style
        style = ttk.Style()
        style.configure(style_name, 
                        background=DARK_THEME["button_bg"], 
                        foreground=DARK_THEME["button_fg"],
                        padding=6)
        super().__init__(parent, text=text, command=command, style=style_name, **kwargs)
