import tkinter as tk
from tkinter import ttk
from themes.styles import DARK_THEME

class LabeledEntry(ttk.Frame):
    def __init__(self, parent, label_text, entry_var, **kwargs):
        """
        Composant regroupant un label et un champ d'entrée.
        """
        super().__init__(parent, **kwargs)
        self.label = ttk.Label(self, text=label_text, foreground=DARK_THEME["text_color"])
        self.label.pack(side=tk.LEFT, padx=(0, 5))
        self.entry = ttk.Entry(self, textvariable=entry_var)
        self.entry.pack(side=tk.LEFT)
