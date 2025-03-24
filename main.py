from tkinter import messagebox
from ABE_AES_GCM_RSA_WITH_DB import KeyManager, HealthRecordSystem, PasswordDialog
import tkinter as tk
from tkinter import ttk
# Assurez-vous d'importer vos frames HomeFrame, AuthFrame et ManagementFrame
from interfaces.home import HomeFrame
from interfaces.auth import AuthFrame
from interfaces.management import ManagementFrame

class MedicalApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Système de Dossiers Médicaux")
        self.minsize(900, 700)
        self.configure(bg="white")
        
        # Initialisation du système métier avec gestion de la clé maître
        self.initialize_system()

        # Conteneur de frames
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomeFrame, AuthFrame, ManagementFrame):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame("HomeFrame")
        
        # Effectue un SELECT sur toute la base de données pour le test
        self.test_select_database()

    def initialize_system(self):
        # Demande du mot de passe de la clé maître
        pwd_dialog = PasswordDialog(self, "Mot de passe de la clé maître", confirm=False)
        password = pwd_dialog.result
        if not password:
            messagebox.showerror("Erreur", "Mot de passe requis pour initialiser le système")
            self.destroy()
            return
        self.key_manager = KeyManager()
        try:
            self.key_manager.initialize(password)
        except Exception as e:
            messagebox.showerror("Erreur", "La clé maître est fausse : " + str(e))
            self.destroy()
            return
        self.health_system = HealthRecordSystem(key_manager=self.key_manager)

    def show_frame(self, frame_name, **kwargs):
        frame = self.frames[frame_name]
        if hasattr(frame, "set_mode") and "mode" in kwargs:
            frame.set_mode(kwargs["mode"])
        frame.tkraise()
        
    def test_select_database(self):
        # Exemple : sélection de toutes les entrées de la table 'users'
        try:
            cursor = self.health_system.cursor
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            print("=== Contenu de la table 'users' ===")
            for user in users:
                print(user)
        except Exception as e:
            print("Erreur lors de la requête SELECT:", e)

if __name__ == "__main__":
    app = MedicalApp()
    app.mainloop()
