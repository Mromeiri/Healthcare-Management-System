import subprocess
import page_manager

def on_home_click():
    from pages.home_page import show_home_page
    page_manager.switch_page(show_home_page)

def on_abe_click():
    from pages.abe_page import show_abe_page
    page_manager.switch_page(show_abe_page)

def on_ibe_click():
    from pages.ibe_page import show_ibe_page
    page_manager.switch_page(show_ibe_page)

def on_ehealth_click():
    # 1) Fermer la fenêtre actuelle
    page_manager._root.destroy()

    # 2) Lancer ehealth_main.py
    subprocess.Popen(["python", "./ehealth/ehealth_main.py"])
