import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkFont
from datetime import datetime

class ManagementFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(padding=20)
        
        # Custom style definitions
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f5f5f7")
        self.style.configure("TLabelframe", background="#f5f5f7", borderwidth=1, relief="solid")
        self.style.configure("TLabelframe.Label", foreground="#1e88e5", background="#f5f5f7", font=("Helvetica", 10, "bold"))
        self.style.configure("TLabel", background="#f5f5f7", font=("Helvetica", 10))
        self.style.configure("Status.TLabel", foreground="#1e88e5", background="#f5f5f7", font=("Helvetica", 14, "bold"))
        self.style.configure("TButton", background="#1e88e5", foreground="white", borderwidth=0, focusthickness=0, font=("Helvetica", 10))
        self.style.map("TButton", background=[("active", "#1565c0"), ("pressed", "#0d47a1")])
        self.style.configure("Accent.TButton", background="#ff6d00", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#e65100"), ("pressed", "#bf360c")])
        self.style.configure("TNotebook", background="#f5f5f7", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#e0e0e0", foreground="#616161", padding=[12, 4], font=("Helvetica", 10))
        self.style.map("TNotebook.Tab", background=[("selected", "#1e88e5")], foreground=[("selected", "white")])
        
        # Configure tree style
        self.style.configure("Treeview", background="white", foreground="#333333", rowheight=25, fieldbackground="white", font=("Helvetica", 10))
        self.style.configure("Treeview.Heading", background="#e0e0e0", foreground="#333333", relief="flat", font=("Helvetica", 10, "bold"))
        self.style.map("Treeview", background=[("selected", "#bbdefb")], foreground=[("selected", "#1e88e5")])
        
        # Set background
        self.configure(style="TFrame")
        
        # Top frame with logo, status and logout
        top_frame = ttk.Frame(self, style="TFrame")
        top_frame.pack(fill="x", pady=(0, 15))
        
        # Logo or title
        logo_label = ttk.Label(top_frame, text="SSI-Health-Sys", font=("Helvetica", 20, "bold"), foreground="#1e88e5", style="TLabel")
        logo_label.pack(side="left", padx=10)
        
        # Status and logout on right side
        status_frame = ttk.Frame(top_frame, style="TFrame")
        status_frame.pack(side="right")
        
        self.lbl_status = ttk.Label(status_frame, text="Non connecté", style="Status.TLabel")
        self.lbl_status.pack(side="left", padx=20)
        
        btn_logout = ttk.Button(status_frame, text="Déconnexion", command=self.logout)
        btn_logout.pack(side="left", padx=10)
        
        # Main content frame
        content_frame = ttk.Frame(self, style="TFrame")
        content_frame.pack(fill="both", expand=True, pady=10)
        
        # Left panel: Actions
        left_panel = ttk.Frame(content_frame, style="TFrame")
        left_panel.pack(side="left", fill="y", padx=(0, 15), anchor="n")
        
        # Notebook for organizing actions
        self.notebook = ttk.Notebook(left_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Tab: Actions générales
        self.actions_frame = ttk.Frame(self.notebook, style="TFrame", padding=15)
        self.notebook.add(self.actions_frame, text="Actions")
        
        # Search section
        search_frame = ttk.LabelFrame(self.actions_frame, text="Recherche de Dossiers", padding=10)
        search_frame.pack(fill="x", pady=(0, 15))
        
        # Search with icon (represented by text here)
        search_box_frame = ttk.Frame(search_frame, style="TFrame")
        search_box_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(search_box_frame, text="🔍", font=("Helvetica", 12)).pack(side="left", padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_box_frame, textvariable=self.search_var, width=50)
        search_entry.pack(side="left", fill="x", expand=True)
        search_entry.bind("<KeyRelease>", self.filter_dossiers)
        
        btn_view_dossiers = ttk.Button(search_frame, text="Voir Mes Derniers Dossiers", command=self.view_dossiers)
        btn_view_dossiers.pack(fill="x", pady=(10, 0))
        
        # Dossier ID Section
        dossier_frame = ttk.LabelFrame(self.actions_frame, text="Dossier Actif", padding=10)
        dossier_frame.pack(fill="x", pady=(0, 15))
        
        id_frame = ttk.Frame(dossier_frame, style="TFrame")
        id_frame.pack(fill="x", pady=5)
        ttk.Label(id_frame, text="ID Dossier:").pack(side="left", padx=5)
        self.dossier_var = tk.StringVar()
        ttk.Entry(id_frame, textvariable=self.dossier_var, width=30).pack(side="left", padx=5, fill="x", expand=True)
        
        # Action buttons
        btn_frame = ttk.Frame(dossier_frame, style="TFrame")
        btn_frame.pack(fill="x", pady=10)
        
        # First row of buttons
        row1 = ttk.Frame(btn_frame, style="TFrame")
        row1.pack(fill="x", pady=2)
        ttk.Button(row1, text="Voir Notes", command=self.view_notes).pack(side="left", padx=2, fill="x", expand=True)
        ttk.Button(row1, text="Voir Imagerie", command=self.view_imaging).pack(side="left", padx=2, fill="x", expand=True)
        
        # Second row of buttons
        row2 = ttk.Frame(btn_frame, style="TFrame")
        row2.pack(fill="x", pady=2)
        ttk.Button(row2, text="Voir Analyses", command=self.view_lab).pack(side="left", padx=2, fill="x", expand=True)
        ttk.Button(row2, text="Voir Dossiers", command=self.view_dossiers).pack(side="left", padx=2, fill="x", expand=True)
        
        # Role-specific action frames
        self.medecin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Médecin", padding=10)
        
        # Médecin actions UI
        patient_frame = ttk.Frame(self.medecin_frame, style="TFrame")
        patient_frame.pack(fill="x", pady=5)
        ttk.Label(patient_frame, text="ID Patient:").pack(side="left", padx=5)
        self.patient_var = tk.StringVar()
        ttk.Entry(patient_frame, textvariable=self.patient_var, width=20).pack(side="left", padx=5, fill="x", expand=True)
        
        action_buttons = ttk.Frame(self.medecin_frame, style="TFrame")
        action_buttons.pack(fill="x", pady=5)
        ttk.Button(action_buttons, text="Créer Dossier", command=self.create_dossier, style="Accent.TButton").pack(side="left", padx=2, fill="x", expand=True)
        ttk.Button(action_buttons, text="Voir Mes Patients", command=self.view_patients).pack(side="left", padx=2, fill="x", expand=True)
        
        # Note entry
        note_frame = ttk.Frame(self.medecin_frame, style="TFrame")
        note_frame.pack(fill="x", pady=10)
        ttk.Label(note_frame, text="Note Médicale:").pack(anchor="w", pady=(0, 5))
        self.note_text = tk.Text(note_frame, width=30, height=3, font=("Helvetica", 10), bg="white", relief="solid", bd=1)
        self.note_text.pack(fill="x")
        ttk.Button(note_frame, text="Ajouter Note", command=self.add_note, style="Accent.TButton").pack(anchor="e", pady=(5, 0))
        
        # Radiologue frame
        self.radiologue_frame = ttk.LabelFrame(self.actions_frame, text="Actions Radiologue", padding=10)
        
        # Radiologue actions UI
        radiologue_input = ttk.Frame(self.radiologue_frame, style="TFrame")
        radiologue_input.pack(fill="x", pady=5)
        ttk.Label(radiologue_input, text="Rapport d'Imagerie:").pack(anchor="w", pady=(0, 5))
        self.imaging_text = tk.Text(radiologue_input, width=30, height=3, font=("Helvetica", 10), bg="white", relief="solid", bd=1)
        self.imaging_text.pack(fill="x")
        
        rad_buttons = ttk.Frame(self.radiologue_frame, style="TFrame")
        rad_buttons.pack(fill="x", pady=10)
        ttk.Button(rad_buttons, text="Ajouter Imagerie", command=self.add_imaging, style="Accent.TButton").pack(side="left", padx=2, fill="x", expand=True)
        ttk.Button(rad_buttons, text="Voir Dossiers Radiologue", command=self.view_radiologue_dossiers).pack(side="left", padx=2, fill="x", expand=True)
        
        # Laborantin frame
        self.laborantin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Laborantin", padding=10)
        
        # Laborantin actions UI
        laborantin_input = ttk.Frame(self.laborantin_frame, style="TFrame")
        laborantin_input.pack(fill="x", pady=5)
        ttk.Label(laborantin_input, text="Résultat d'Analyse:").pack(anchor="w", pady=(0, 5))
        self.lab_text = tk.Text(laborantin_input, width=30, height=3, font=("Helvetica", 10), bg="white", relief="solid", bd=1)
        self.lab_text.pack(fill="x")
        
        lab_buttons = ttk.Frame(self.laborantin_frame, style="TFrame")
        lab_buttons.pack(fill="x", pady=10)
        ttk.Button(lab_buttons, text="Ajouter Analyse", command=self.add_lab, style="Accent.TButton").pack(side="left", padx=2, fill="x", expand=True)
        ttk.Button(lab_buttons, text="Voir Dossiers Laborantin", command=self.view_laborantin_dossiers).pack(side="left", padx=2, fill="x", expand=True)
        
        # Right panel: Results
        self.result_frame = ttk.LabelFrame(content_frame, text="Résultats", padding=10)
        self.result_frame.pack(side="right", fill="both", expand=True)
        
        # Tree frame with scrollbars
        tree_frame = ttk.Frame(self.result_frame, style="TFrame")
        tree_frame.pack(fill="both", expand=True, pady=5)
        
        # Create scrollbars
        self.vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        self.hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # Create treeview
        self.tree = ttk.Treeview(tree_frame, columns=("id", "info"), show="headings",
                                yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        
        # Configure scrollbars
        self.vsb.config(command=self.tree.yview)
        self.hsb.config(command=self.tree.xview)
        
        # Pack scrollbars and treeview
        self.vsb.pack(side="right", fill="y")
        self.hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        
        # Configure columns
        self.tree.heading("id", text="ID")
        self.tree.heading("info", text="Informations")
        self.tree.column("id", width=150, anchor="center", minwidth=100)
        self.tree.column("info", width=400, anchor="w")
        
        # Bind double-click event
        self.tree.bind("<Double-1>", self.copy_id)
        
        # Add status bar at the bottom
        status_bar = ttk.Frame(self, style="TFrame", relief="sunken")
        status_bar.pack(fill="x", side="bottom", pady=(10, 0))
        status_txt = ttk.Label(status_bar, text="Prêt", foreground="#666", padding=(10, 5))
        status_txt.pack(side="left")
        
    def update_actions_visibility(self):
        role = self.controller.health_system.current_role.strip()
        self.lbl_status.config(text=f"Connecté en tant que {role}")
        # Masquer d'abord tous les cadres spécifiques
        self.medecin_frame.pack_forget()
        self.radiologue_frame.pack_forget()
        self.laborantin_frame.pack_forget()
        if role == "medecin":
            self.medecin_frame.pack(fill="x", pady=5)
        elif role == "radiologue":
            self.radiologue_frame.pack(fill="x", pady=5)
        elif role == "laborantin":
            self.laborantin_frame.pack(fill="x", pady=5)
        
    def logout(self):
        self.controller.health_system.logout()
        for item in self.tree.get_children():
            self.tree.delete(item)
        messagebox.showinfo("Déconnexion", "Vous avez été déconnecté.")
        self.controller.show_frame("HomeFrame")
        
    def create_dossier(self):
        try:
            dossier_id = self.controller.health_system.medecin_create_dossier(self.patient_var.get().strip())
            self.dossier_var.set(dossier_id)
            messagebox.showinfo("Succès", f"Dossier créé : {dossier_id}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def add_note(self):
        try:
            note = self.note_text.get("1.0", tk.END).strip()
            if note:
                if self.controller.health_system.medecin_add_note(self.dossier_var.get().strip(), note):
                    messagebox.showinfo("Succès", "Note ajoutée")
                    self.note_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def add_imaging(self):
        try:
            imaging = self.imaging_text.get("1.0", tk.END).strip()
            if imaging:
                if self.controller.health_system.radiologue_add_imaging(self.dossier_var.get().strip(), imaging):
                    messagebox.showinfo("Succès", "Résultat d'imagerie ajouté")
                    self.imaging_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def add_lab(self):
        try:
            lab = self.lab_text.get("1.0", tk.END).strip()
            if lab:
                if self.controller.health_system.laborantin_add_lab(self.dossier_var.get().strip(), lab):
                    messagebox.showinfo("Succès", "Résultat d'analyse ajouté")
                    self.lab_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_notes(self):
        try:
            role = self.controller.health_system.current_role.strip()
            if role == "medecin":
                notes = self.controller.health_system.medecin_get_notes(self.dossier_var.get().strip())
            elif role == "patient":
                notes = self.controller.health_system.patient_get_notes(self.dossier_var.get().strip())
            else:
                raise Exception("Rôle non autorisé à voir les notes")
            self.display_results("Notes Médicales", notes)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_imaging(self):
        try:
            role = self.controller.health_system.current_role.strip()
            if role in ["radiologue", "medecin", "patient"]:
                if role == "radiologue":
                    results = self.controller.health_system.radiologue_get_imaging(self.dossier_var.get().strip())
                elif role == "medecin":
                    results = self.controller.health_system.medecin_get_imaging(self.dossier_var.get().strip())
                else:
                    results = self.controller.health_system.patient_get_imaging(self.dossier_var.get().strip())
                self.display_results("Résultats d'Imagerie", results)
            else:
                raise Exception("Rôle non autorisé à voir l'imagerie")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_lab(self):
        try:
            role = self.controller.health_system.current_role.strip()
            if role in ["laborantin", "medecin", "patient"]:
                if role == "laborantin":
                    results = self.controller.health_system.laborantin_get_lab(self.dossier_var.get().strip())
                elif role == "medecin":
                    results = self.controller.health_system.medecin_get_lab(self.dossier_var.get().strip())
                else:
                    results = self.controller.health_system.patient_get_lab(self.dossier_var.get().strip())
                self.display_results("Résultats d'Analyses", results)
            else:
                raise Exception("Rôle non autorisé à voir les analyses")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_dossiers(self):
        try:
            role = self.controller.health_system.current_role.strip()
            if role == "patient":
                records = self.controller.health_system.patient_get_dossiers()
            elif role == "medecin":
                self.controller.health_system.cursor.execute(
                    "SELECT id, patient_id, date_creation FROM dossiers_medicaux WHERE medecin_id = ?",
                    (self.controller.health_system.current_user,)
                )
                records = [{"id": r[0], "patient_id": r[1], "date_creation": r[2]} 
                           for r in self.controller.health_system.cursor.fetchall()]
            else:
                raise Exception("Seuls les patients et médecins peuvent voir leurs dossiers")
            self.display_results("Mes Dossiers", records)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_radiologue_dossiers(self):
        try:
            if self.controller.health_system.current_role.strip() != "radiologue":
                raise Exception("Fonction réservée aux radiologues")
            dossiers = self.controller.health_system.radiologue_get_dossiers()
            self.display_results("Dossiers Radiologue", dossiers)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_laborantin_dossiers(self):
        try:
            if self.controller.health_system.current_role.strip() != "laborantin":
                raise Exception("Fonction réservée aux laborantins")
            dossiers = self.controller.health_system.laborantin_get_dossiers()
            self.display_results("Dossiers Laborantin", dossiers)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def view_patients(self):
        try:
            patients = self.controller.health_system.medecin_get_patients_and_dossiers()
            display_list = []
            for patient in patients:
                dossiers_str = ", ".join([f"{d['id']} ({d['date_creation']})" for d in patient.get("dossiers", [])])
                info = f"{patient.get('nom', '')} {patient.get('prenom', '')} (ID: {patient.get('patient_id', '')}) - Dossiers: {dossiers_str}"
                display_list.append({"id": patient.get("patient_id", ""), "info": info})
            self.display_results("Mes Patients", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def filter_dossiers(self, event=None):
        search_text = self.search_var.get().lower()
        try:
            role = self.controller.health_system.current_role.strip()
            if role == "patient":
                dossiers = self.controller.health_system.patient_get_dossiers()
            elif role == "medecin":
                self.controller.health_system.cursor.execute(
                    "SELECT id, patient_id, date_creation FROM dossiers_medicaux WHERE medecin_id = ?",
                    (self.controller.health_system.current_user,)
                )
                dossiers = [{"id": r[0], "patient_id": r[1], "date_creation": r[2]} 
                            for r in self.controller.health_system.cursor.fetchall()]
            else:
                dossiers = []
            filtered = [d for d in dossiers if search_text in d['id'].lower() or search_text in d['date_creation'].lower()]
            self.display_results("Résultats de la recherche", filtered)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def display_results(self, title, results):
        # Vider le Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.append_log(f"Affichage : {title}")
        
        # Mesurer la largeur maximale du texte dans la colonne "Informations"
        default_font = tkFont.nametofont("TkDefaultFont")
        max_width = 0
        processed_results = []
        for item in results:
            info = item.get("contenu", item.get("date_creation", item.get("info", ""))).replace("\n", " ")
            text_width = default_font.measure(info)
            if text_width > max_width:
                max_width = text_width
            processed_results.append({
                "id": item.get("id", ""),
                "info": info
            })
        # Insérer les données
        for item in processed_results:
            self.tree.insert("", "end", values=(item["id"], item["info"]))
        # Ajuster la largeur de la colonne "Informations"
        self.tree.column("info", width=max_width + 30)
            
    def append_log(self, message):
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        
    def copy_id(self, event):
        selected = self.tree.focus()
        if selected:
            values = self.tree.item(selected, "values")
            if values:
                self.clipboard_clear()
                self.clipboard_append(values[0])
                messagebox.showinfo("ID copié", f"L'ID {values[0]} a été copié.")