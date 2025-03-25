# 🎨 Couleurs principales
BACKGROUND_COLOR = "#282828"   # Fond sombre
TITLEBAR_COLOR = "#252525"     # (Ici, on ne l'utilise pas, mais on le laisse pour la cohérence)
TEXT_COLOR = "#FFFFFF"         # Texte blanc
TEXT_COLOR_On_click = "#000000"         # Texte noire

# Boutons circulaires façon macOS (non utilisés ici, mais on les laisse pour la cohérence)
CLOSE_BUTTON_COLOR = "#FF5F56"
CLOSE_BUTTON_HOVER = "#CC4941"
MINIMIZE_BUTTON_COLOR = "#FFBD2E"
MINIMIZE_BUTTON_HOVER = "#D9A022"
MAXIMIZE_BUTTON_COLOR = "#28C840"
MAXIMIZE_BUTTON_HOVER = "#1F9F33"

# Boutons principaux
BUTTON_COLOR = "#1f1f1f"

HOVER_COLOR = "#333333"  # Couleur au survol
CLICK_COLOR = "#555555"  # Couleur lorsqu'on clique
# 🏗️ Taille de la barre de titre (inutile ici, on laisse pour cohérence)
TITLEBAR_HEIGHT = 35

# 🖋️ Police et tailles
FONT_FAMILY = "Arial"
FONT_SIZE = 12
BUTTON_FONT_SIZE = 14

# 📏 Taille des boutons principaux
BUTTON_WIDTH = 30
BUTTON_HEIGHT = 4

# 📏 Taille des boutons circulaires (style macOS)
MAC_BUTTON_SIZE = 15

def apply_styles(root):
    """Applique les styles globaux à la fenêtre principale"""
    root.configure(bg=BACKGROUND_COLOR)
