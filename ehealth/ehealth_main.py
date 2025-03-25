import tkinter as tk
from tkinter import ttk, messagebox
from ABE_AES_GCM_RSA_WITH_DB import KeyManager, HealthRecordSystem, PasswordDialog
from interfaces.home import HomeFrame
from interfaces.auth import AuthFrame
from interfaces.management import ManagementFrame

class MedicalApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Système de Dossiers Médicaux")
        self.minsize(900, 700)
        
        # Initialisation du système (clé maître, HealthRecordSystem, etc.)
        self.initialize_system()
        
        # Conteneur pour les interfaces (frames)
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        # Chargement des différentes interfaces
        for F in (HomeFrame, AuthFrame, ManagementFrame):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame("HomeFrame")
    
    def initialize_system(self):
        # Demande du mot de passe maître via une boîte de dialogue
        pwd_dialog = PasswordDialog(self, "Mot de passe de la clé maître", confirm=False)
        password = pwd_dialog.result
        if not password:
            messagebox.showerror("Erreur", "Mot de passe requis pour initialiser le système")
            self.destroy()
            return
        
        self.key_manager = KeyManager()
        try:
            # Tentative d'initialisation avec le mot de passe fourni
            self.key_manager.initialize(password)
        except Exception as e:
            messagebox.showerror("Erreur", f"La clé maître est fausse ou invalide.\nDétails : {e}")
            self.destroy()
            return
        
        self.health_system = HealthRecordSystem(key_manager=self.key_manager)
        # Si vous avez une méthode d'affichage des logs, appelez-la ici
        # self.activity_log("Système initialisé avec la clé maître.")
    
    def show_frame(self, frame_name, **kwargs):
        frame = self.frames[frame_name]
        if hasattr(frame, "set_mode") and "mode" in kwargs:
            frame.set_mode(kwargs["mode"])
        frame.tkraise()

if __name__ == "__main__":
    app = MedicalApp()
    app.mainloop()
