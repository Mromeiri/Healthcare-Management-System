import tkinter as tk
from tkinter import ttk, messagebox
import re
import ttkbootstrap as tb

class AuthFrame(ttk.Frame):
    """
    Interface d'authentification pour inscription et connexion.
    En mode inscription, on demande plusieurs champs (email, nom, prénom, rôle, adresse,
    date de naissance, téléphone, et pour les patients, genre et groupe sanguin).
    En mode connexion, seuls email et mot de passe sont demandés.
    """
    def __init__(self, parent, controller, mode="login"):
        super().__init__(parent)
        self.controller = controller
        self.mode = mode  # "login" ou "register"
        self.configure(padding=20)
        self.create_widgets()

    def create_widgets(self):
        # Nettoyer le cadre
        for widget in self.winfo_children():
            widget.destroy()
        
        # Container principal
        main_container = ttk.Frame(self)
        main_container.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)
        
        # Titre et sous-titre
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(20, 50))
        
        title_text = "Créer un compte" if self.mode == "register" else "Se connecter"
        title = ttk.Label(header_frame, text=title_text, 
                        font=("Helvetica", 28, "bold"), 
                        foreground="#333333")
        title.pack(pady=10)
        
        subtitle_text = "Gérez votre espace santé en toute sécurité" 
        subtitle = ttk.Label(header_frame, text=subtitle_text, 
                           font=("Helvetica", 14), 
                           foreground="#666666")
        subtitle.pack(pady=(0, 20))
        
        # Cadre de carte pour le formulaire
        card_frame = ttk.Frame(main_container, padding=30)
        card_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Conteneur de formulaire
        form = ttk.Frame(card_frame)
        form.pack(expand=True, fill=tk.BOTH)
        
        # Champ Email (obligatoire pour les deux modes)
        ttk.Label(form, text="Email:", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.email_entry = ttk.Entry(form, width=40)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)
        
        if self.mode == "register":
            # Champs supplémentaires pour l'inscription
            ttk.Label(form, text="Nom:", font=("Helvetica", 12)).grid(row=1, column=0, sticky="w", padx=5, pady=5)
            self.nom_entry = ttk.Entry(form, width=40)
            self.nom_entry.grid(row=1, column=1, padx=5, pady=5)
            
            ttk.Label(form, text="Prénom:", font=("Helvetica", 12)).grid(row=2, column=0, sticky="w", padx=5, pady=5)
            self.prenom_entry = ttk.Entry(form, width=40)
            self.prenom_entry.grid(row=2, column=1, padx=5, pady=5)
            
            ttk.Label(form, text="Rôle:", font=("Helvetica", 12)).grid(row=3, column=0, sticky="w", padx=5, pady=5)
            self.role_combobox = ttk.Combobox(form, values=["medecin", "laborantin", "patient", "radiologue"], width=38)
            self.role_combobox.grid(row=3, column=1, padx=5, pady=5)
            self.role_combobox.bind("<<ComboboxSelected>>", self.update_fields)
            
            ttk.Label(form, text="Adresse:", font=("Helvetica", 12)).grid(row=4, column=0, sticky="w", padx=5, pady=5)
            self.adresse_entry = ttk.Entry(form, width=40)
            self.adresse_entry.grid(row=4, column=1, padx=5, pady=5)
            
            ttk.Label(form, text="Date de naissance (YYYY-MM-DD):", font=("Helvetica", 12)).grid(row=5, column=0, sticky="w", padx=5, pady=5)
            self.date_naissance_entry = ttk.Entry(form, width=40)
            self.date_naissance_entry.grid(row=5, column=1, padx=5, pady=5)
            
            ttk.Label(form, text="Téléphone:", font=("Helvetica", 12)).grid(row=6, column=0, sticky="w", padx=5, pady=5)
            self.telephone_entry = ttk.Entry(form, width=40)
            self.telephone_entry.grid(row=6, column=1, padx=5, pady=5)
            
            # Les champs suivants sont spécifiques aux patients
            self.genre_label = ttk.Label(form, text="Genre (M/F):", font=("Helvetica", 12))
            self.genre_entry = ttk.Entry(form, width=40)
            self.groupe_label = ttk.Label(form, text="Groupe sanguin (A/B/AB/O):", font=("Helvetica", 12))
            self.groupe_entry = ttk.Entry(form, width=40)
            
            ttk.Label(form, text="Mot de passe:", font=("Helvetica", 12)).grid(row=8, column=0, sticky="w", padx=5, pady=5)
            self.pass_entry = ttk.Entry(form, show="*", width=40)
            self.pass_entry.grid(row=8, column=1, padx=5, pady=5)
            
            ttk.Label(form, text="Confirmer le mot de passe:", font=("Helvetica", 12)).grid(row=9, column=0, sticky="w", padx=5, pady=5)
            self.confirm_pass_entry = ttk.Entry(form, show="*", width=40)
            self.confirm_pass_entry.grid(row=9, column=1, padx=5, pady=5)
        else:
            # Mode connexion : seul email et mot de passe sont requis
            ttk.Label(form, text="Mot de passe:", font=("Helvetica", 12)).grid(row=1, column=0, sticky="w", padx=5, pady=5)
            self.pass_entry = ttk.Entry(form, show="*", width=40)
            self.pass_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Conteneur pour les boutons
        button_container = ttk.Frame(card_frame)
        button_container.pack(pady=20)
        
        # Bouton d'action
        action_text = "S'inscrire" if self.mode == "register" else "Se connecter"
        action_button = ttk.Button(
            button_container, 
            text=action_text, 
            style="Accent.TButton",
            command=self.submit_form
        )
        action_button.pack(fill=tk.X, ipady=10)
        
        # Bouton pour changer de mode
        switch_text = "Vous avez déjà un compte ? Se connecter" if self.mode == "register" else "Créer un compte"
        switch_button = ttk.Button(
            button_container, 
            text=switch_text, 
            style="Secondary.TButton",
            command=self.switch_mode
        )
        switch_button.pack(fill=tk.X, pady=(10, 0), ipady=10)
        
        # Footer
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

    def update_fields(self, event=None):
        """ Affiche les champs supplémentaires pour le rôle patient. """
        role = self.role_combobox.get().strip().lower()
        if role == "patient":
            self.genre_label.grid(row=7, column=0, sticky="w", padx=5, pady=5)
            self.genre_entry.grid(row=7, column=1, padx=5, pady=5)
            self.groupe_label.grid(row=8, column=0, sticky="w", padx=5, pady=5)
            self.groupe_entry.grid(row=8, column=1, padx=5, pady=5)
        else:
            self.genre_label.grid_forget()
            self.genre_entry.grid_forget()
            self.groupe_label.grid_forget()
            self.groupe_entry.grid_forget()

    def switch_mode(self):
        """ Bascule entre inscription et connexion. """
        self.mode = "register" if self.mode == "login" else "login"
        self.create_widgets()

    def submit_form(self):
        if self.mode == "register":
            email = self.email_entry.get().strip()
            password = self.pass_entry.get().strip()
            confirm_password = self.confirm_pass_entry.get().strip()
            if password != confirm_password:
                messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
                return

            # Récupération des autres champs
            nom = self.nom_entry.get().strip()
            prenom = self.prenom_entry.get().strip()
            role = self.role_combobox.get().strip().lower()
            adresse = self.adresse_entry.get().strip()
            date_naissance = self.date_naissance_entry.get().strip()
            telephone = self.telephone_entry.get().strip()
            genre = self.genre_entry.get().strip() if role == "patient" else None
            groupe = self.groupe_entry.get().strip() if role == "patient" else None
            
            # Validation avec regex pour la date (format YYYY-MM-DD)
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_naissance):
                messagebox.showerror("Erreur", "La date de naissance doit être au format YYYY-MM-DD")
                return

            # Validation du numéro de téléphone (doit contenir uniquement des chiffres)
            if not re.match(r"^\d+$", telephone):
                messagebox.showerror("Erreur", "Le numéro de téléphone doit contenir uniquement des chiffres")
                return
            
            # Appel à la méthode d'inscription
            try:
                self.controller.health_system.register_user(
                    email, nom, prenom, role, password, adresse, date_naissance, telephone, genre, groupe
                )
                messagebox.showinfo("Succès", f"Utilisateur inscrit avec l'email {email}")
                self.switch_mode()  # Passe en mode connexion après inscription
            except Exception as e:
                messagebox.showerror("Erreur", str(e))
        else:
            # Mode connexion
            email = self.email_entry.get().strip()
            password = self.pass_entry.get().strip()
            try:
                if self.controller.health_system.login(email, password):
                    messagebox.showinfo("Succès", f"Connecté en tant que {self.controller.health_system.current_role}")
                    self.controller.frames["ManagementFrame"].update_actions_visibility()
                    self.controller.show_frame("ManagementFrame")
                else:
                    messagebox.showerror("Erreur", "Email ou mot de passe incorrect")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))