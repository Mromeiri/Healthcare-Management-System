import tkinter as tk
from UI_components.styles import BUTTON_COLOR, TEXT_COLOR, BUTTON_WIDTH, BUTTON_HEIGHT, FONT_FAMILY, BUTTON_FONT_SIZE, HOVER_COLOR, CLICK_COLOR, TEXT_COLOR_On_click

def create_custom_button(parent, text, command, **kwargs):
    """Crée un bouton réutilisable avec un style personnalisé."""
    btn = tk.Button(
        parent,
        text=text,
        bg=BUTTON_COLOR,
        fg=TEXT_COLOR,
        font=(FONT_FAMILY, BUTTON_FONT_SIZE, "bold"),
        width=kwargs.get("width", BUTTON_WIDTH),
        height=kwargs.get("height", BUTTON_HEIGHT),
        relief=kwargs.get("relief", "flat"),
        cursor="hand2",
        command=command  # Pas besoin de `lambda: command(root)`
    )

    # Effets de hover et clic
    def on_enter(event):
        btn.config(bg=HOVER_COLOR)
    def on_leave(event):
        btn.config(bg=BUTTON_COLOR)
    def on_press(event):
        btn.config(bg=CLICK_COLOR, fg=TEXT_COLOR_On_click)

    def on_release(event):
        btn.config(bg=HOVER_COLOR, fg=TEXT_COLOR)

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    btn.bind("<ButtonPress-1>", on_press)
    btn.bind("<ButtonRelease-1>", on_release)

    return btn
