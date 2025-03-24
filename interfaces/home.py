import tkinter as tk
from tkinter import ttk
import ttkbootstrap as tb

class HomeFrame(ttk.Frame):
    """
    Cette classe représente l'écran d'accueil (Home).
    On pourra l'appeler depuis le main ou un contrôleur pour l'afficher.
    """
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(padding=20)
        
        # Container principal
        main_container = ttk.Frame(self)
        main_container.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)

        # Logo et titre en haut
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(20, 50))
        
        # Logo stylisé
        logo_frame = ttk.Frame(header_frame)
        logo_frame.pack(pady=20)
        
        logo_label = ttk.Label(logo_frame, text="SSI", 
                             background="#3a7ebf", foreground="white",
                             font=("Helvetica", 28, "bold"))
        logo_label.configure(width=3, anchor="center", padding=20)
        logo_label.pack()
        
        # Titre principal
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(pady=10)
        
        title = ttk.Label(title_frame, text="Système Médical", 
                        font=("Helvetica", 28, "bold"), 
                        foreground="#333333")
        title.pack()
        
        subtitle = ttk.Label(title_frame, text="Gestion des dossiers médicaux", 
                           font=("Helvetica", 14), 
                           foreground="#666666")
        subtitle.pack(pady=(5, 0))

        # Container central avec effet de carte
        card_frame = ttk.Frame(main_container, padding=30)
        card_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        welcome_text = ttk.Label(card_frame, 
                               text="Bienvenue dans votre espace santé", 
                               font=("Helvetica", 16, "bold"),
                               foreground="#333333")
        welcome_text.pack(pady=(0, 20))
        
        info_text = ttk.Label(card_frame, 
                            text="Accédez à vos dossiers médicaux, résultats d'analyses\net prenez rendez-vous avec votre médecin",
                            font=("Helvetica", 12),
                            justify="center",
                            foreground="#555555")
        info_text.pack(pady=(0, 30))
        
        # Conteneur pour les boutons
        button_container = ttk.Frame(card_frame)
        button_container.pack(pady=10)
        
        # Bouton qui dirige vers l'inscription - style principal
        btn_register = ttk.Button(
            button_container, 
            text="Créer un compte", 
            style="Accent.TButton",
            command=lambda: controller.show_frame("AuthFrame", mode="register")
        )
        btn_register.pack(fill=tk.X, pady=10, ipady=10)

        # Bouton qui dirige vers la connexion - style secondaire
        btn_login = ttk.Button(
            button_container, 
            text="Se connecter", 
            style="Secondary.TButton",
            command=lambda: controller.show_frame("AuthFrame", mode="login")
        )
        btn_login.pack(fill=tk.X, pady=10, ipady=10)
        
        # Footer avec informations
        footer_frame = ttk.Frame(main_container)
        footer_frame.pack(fill=tk.X, pady=(30, 0))
        
        footer_text = ttk.Label(footer_frame, 
                              text="© 2025 Système Médical - Tous droits réservés au M1 ssi",
                              font=("Helvetica", 9),
                              foreground="#999999")
        footer_text.pack(side=tk.LEFT)
        
        version_text = ttk.Label(footer_frame, 
                               text="v1.0",
                               font=("Helvetica", 9),
                               foreground="#999999")
        version_text.pack(side=tk.RIGHT)


# Mise à jour des styles pour inclure le HomeFrame
def setup_styles():
    style = tb.Style(theme="litera")
    
    # Configure button styles
    style.configure("Accent.TButton", 
                  background="#3a7ebf", 
                  foreground="white", 
                  font=("Helvetica", 12))
                  
    style.map("Accent.TButton",
            background=[('active', '#2a6eaf'), ('pressed', '#1a5e9f')],
            foreground=[('active', 'white'), ('pressed', 'white')])
    
    style.configure("Secondary.TButton", 
                  background="#f8f9fa", 
                  foreground="#3a7ebf", 
                  font=("Helvetica", 12))
                  
    style.map("Secondary.TButton",
            background=[('active', '#e2e6ea'), ('pressed', '#dae0e5')],
            foreground=[('active', '#2a6eaf'), ('pressed', '#1a5e9f')])
    
    style.configure("Link.TButton", 
                  background=None,
                  foreground="#3a7ebf", 
                  font=("Helvetica", 10, "underline"),
                  borderwidth=0)
    
    style.map("Link.TButton",
            foreground=[('active', '#2a6eaf'), ('pressed', '#1a5e9f')])
                  
    return style