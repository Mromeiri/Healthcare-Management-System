# page_manager.py

_root = None

def set_root(root):
    global _root
    _root = root

def switch_page(page_function):
    global _root
    # Détruire tous les widgets actuels de la fenêtre principale
    for widget in _root.winfo_children():
        widget.destroy()
    # Appeler la fonction de page pour reconstruire l'interface
    page_function(_root)
