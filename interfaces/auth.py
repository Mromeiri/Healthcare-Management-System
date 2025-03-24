import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *

class AuthFrame(ttk.Frame):
    """
    Cette classe gère l'interface d'authentification : inscription et connexion.
    On peut la paramétrer en mode 'register' ou 'login' selon les besoins.
    """
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.mode = None  # 'register' ou 'login'
        
        # Configuration du style
        self.style = tb.Style()
        self.style.configure("TFrame", background="#ffffff")
        self.style.configure("TLabel", background="#ffffff", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10))
        self.style.configure("Title.TLabel", font=("Helvetica", 24, "bold"), background="#ffffff")
        self.style.configure("Subtitle.TLabel", font=("Helvetica", 12), background="#ffffff")
        
        # Container principal
        self.main_container = ttk.Frame(self, padding=20)
        self.main_container.pack(padx=40, pady=40, fill=tk.BOTH, expand=True)
        
        # Titre et image
        self.header_frame = ttk.Frame(self.main_container)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Logo (cercle de couleur simple)
        self.create_logo()
        
        self.title_label = ttk.Label(self.header_frame, text="", style="Title.TLabel")
        self.title_label.pack(pady=10)
        
        self.subtitle = ttk.Label(self.header_frame, text="", style="Subtitle.TLabel")
        self.subtitle.pack()

        # Variables associées aux champs
        self.nom_var = tk.StringVar()
        self.prenom_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.role_var = tk.StringVar()

        # Conteneur pour les champs
        self.form_frame = ttk.Frame(self.main_container)
        self.form_frame.pack(fill=tk.BOTH, expand=True, pady=15)

        # Création de champs stylisés
        self.create_input_field("Nom", self.nom_var, 0)
        self.create_input_field("Prénom", self.prenom_var, 1)
        self.create_password_field("Mot de passe", self.pass_var, 2)
        
        # Champ de rôle (uniquement pour inscription)
        self.role_frame = ttk.Frame(self.form_frame)
        self.role_frame.pack(fill=tk.X, pady=10)
        
        self.role_label = ttk.Label(self.role_frame, text="Rôle:")
        self.role_label.pack(anchor="w", pady=(0, 5))
        
        self.role_entry = ttk.Combobox(self.role_frame, 
                                    textvariable=self.role_var,
                                    values=["medecin", "laborantin", "patient", "radiologue"])
        self.role_entry.pack(fill=tk.X, ipady=2)

        # Conteneur pour les boutons
        self.button_frame = ttk.Frame(self.main_container)
        self.button_frame.pack(fill=tk.X, pady=20)

        # Bouton principal (s'adapte selon le mode)
        self.btn_action = ttk.Button(self.button_frame, text="", 
                                  style="Accent.TButton",
                                  command=self.do_action)
        self.btn_action.pack(pady=10, ipady=5, fill=tk.X)

        # Switch entre login et register
        self.switch_frame = ttk.Frame(self.button_frame)
        self.switch_frame.pack(pady=10)
        
        self.switch_text = ttk.Label(self.switch_frame, text="")
        self.switch_text.pack(side=tk.LEFT, padx=(0, 5))
        
        self.switch_btn = ttk.Button(self.switch_frame, text="", 
                                  style="Link.TButton",
                                  command=self.toggle_mode)
        self.switch_btn.pack(side=tk.LEFT)

        # Bouton pour revenir à l'écran d'accueil
        self.back_btn = ttk.Button(self.button_frame, text="Retour", 
                                command=lambda: controller.show_frame("HomeFrame"))
        self.back_btn.pack(pady=5, ipady=3)
        
        # Gestion du champ de passe (afficher/masquer)
        self.show_password = False

    def create_logo(self):
        """Crée un simple logo stylisé"""
        logo_frame = ttk.Frame(self.header_frame)
        logo_frame.pack(pady=10)
        
        # Utilisons un simple label coloré comme logo
        logo_label = ttk.Label(logo_frame, text="SSI", 
                             background="#3a7ebf", foreground="white",
                             font=("Helvetica", 20, "bold"))
        # Appliquer un style pour le rendre circulaire
        logo_label.configure(width=3, anchor="center", padding=15)
        logo_label.pack()

    def create_input_field(self, label_text, variable, row):
        """Crée un champ d'entrée stylisé"""
        frame = ttk.Frame(self.form_frame)
        frame.pack(fill=tk.X, pady=10)
        
        label = ttk.Label(frame, text=label_text)
        label.pack(anchor="w", pady=(0, 5))
        
        entry = ttk.Entry(frame, textvariable=variable)
        entry.pack(fill=tk.X, ipady=2)
        
        return entry

    def create_password_field(self, label_text, variable, row):
        """Crée un champ de mot de passe avec bouton pour afficher/masquer"""
        frame = ttk.Frame(self.form_frame)
        frame.pack(fill=tk.X, pady=10)
        
        label = ttk.Label(frame, text=label_text)
        label.pack(anchor="w", pady=(0, 5))
        
        password_frame = ttk.Frame(frame)
        password_frame.pack(fill=tk.X)
        
        self.entry_pass = ttk.Entry(password_frame, textvariable=variable, show="●")
        self.entry_pass.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=2)
        
        # Bouton pour afficher/masquer le mot de passe
        toggle_btn = ttk.Button(password_frame, text="👁️", style="Link.TButton",
                             command=self.toggle_password_visibility)
        toggle_btn.pack(side=tk.RIGHT)
        
        return self.entry_pass

    def toggle_password_visibility(self):
        """Affiche ou masque le mot de passe"""
        self.show_password = not self.show_password
        self.entry_pass.config(show="" if self.show_password else "●")

    def toggle_mode(self):
        """Bascule entre les modes connexion et inscription"""
        if self.mode == "login":
            self.set_mode("register")
        else:
            self.set_mode("login")

    def set_mode(self, mode):
        """
        Configure l'interface en mode 'register' ou 'login'.
        """
        self.mode = mode
        self.nom_var.set("")
        self.prenom_var.set("")
        self.pass_var.set("")
        self.role_var.set("")
        
        # Pour le mode inscription, afficher le champ de sélection du rôle
        if mode == "register":
            self.title_label.config(text="Créer un compte")
            self.subtitle.config(text="Veuillez remplir les informations suivantes")
            self.btn_action.config(text="S'inscrire")
            self.role_frame.pack(fill=tk.X, pady=10)
            self.switch_text.config(text="Déjà inscrit ?")
            self.switch_btn.config(text="Se connecter")
        else:
            self.title_label.config(text="Bienvenue")
            self.subtitle.config(text="Connectez-vous à votre compte")
            self.btn_action.config(text="Se connecter")
            self.role_frame.pack_forget()
            self.switch_text.config(text="Pas encore de compte ?")
            self.switch_btn.config(text="S'inscrire")

    def do_action(self):
        """
        Exécute l'action en fonction du mode (register ou login).
        """
        nom = self.nom_var.get().strip()
        prenom = self.prenom_var.get().strip()
        password = self.pass_var.get().strip()

        if not (nom and prenom and password):
            messagebox.showerror("Erreur", "Tous les champs doivent être remplis")
            return

        if self.mode == "register":
            role = self.role_var.get().strip()
            if role not in ["medecin", "laborantin", "patient", "radiologue"]:
                messagebox.showerror("Erreur", "Veuillez choisir un rôle valide")
                return
            try:
                uid = self.controller.health_system.register_user(nom, prenom, role, password)
                messagebox.showinfo("Succès", f"Compte créé. ID: {uid}")
                # On bascule automatiquement vers l'écran de connexion après inscription
                self.set_mode("login")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))
        else:
            if self.controller.health_system.login(nom, prenom, password):
                role = self.controller.health_system.current_role
                messagebox.showinfo("Succès", f"Connecté en tant que {role}")
                self.controller.frames["ManagementFrame"].update_actions_visibility()
                self.controller.show_frame("ManagementFrame")
            else:
                messagebox.showerror("Erreur", "Identifiants incorrects")


# Style setup helper - can be added to your main.py
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
    
    style.configure("Link.TButton", 
                  background=None,
                  foreground="#3a7ebf", 
                  font=("Helvetica", 10, "underline"),
                  borderwidth=0)
    
    style.map("Link.TButton",
            foreground=[('active', '#2a6eaf'), ('pressed', '#1a5e9f')])
                  
    return style