
"""
Système de dossiers médicaux avec gestion de clé maître,
méthode d'enveloppe pour chiffrer les données, chiffrement des clés privées RSA avec la master key,
et contraintes d'accès par rôle.
Chaque rôle peut voir ses propres résultats, médecin et patient voient tout.
Section Résultats à la même position et avec les mêmes dimensions que le journal d'activité.
"""
import customtkinter as ctk
import json
import os
import shutil
import base64
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
import uuid
import hashlib


# --------------------------------------------
# Gestion de la clé maître (KeyManager) avec AES-GCM
# --------------------------------------------
class KeyManager:
    def __init__(self, filename="master_key.json"):
        self.filename = filename
        self.master_key = None

    def initialize(self, password):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                data = json.load(f)
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])
            tag = base64.b64decode(data["tag"])
            encrypted_master = base64.b64decode(data["encrypted_master"])
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            self.master_key = cipher.decrypt_and_verify(encrypted_master, tag)
        else:
            self.master_key = get_random_bytes(32)
            salt = os.urandom(16)
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
            cipher = AES.new(key, AES.MODE_GCM)
            encrypted_master, tag = cipher.encrypt_and_digest(self.master_key)
            data = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "encrypted_master": base64.b64encode(encrypted_master).decode('utf-8')
            }
            with open(self.filename, "w") as f:
                json.dump(data, f)


# --------------------------------------------
# Fonctions RSA de base
# --------------------------------------------
def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)


def generate_rsa_keys(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key(format="PEM")
    public_key = key.publickey().export_key(format="PEM")
    return private_key, public_key


# --------------------------------------------
# Méthode d'enveloppe pour encryptage/déchiffrement
# --------------------------------------------
class EnvelopeEncryption:
    @staticmethod
    def encrypt(message, authorized):
        if isinstance(message, str):
            message = message.encode('utf-8')
        # Génération d'une clé de session aléatoire (pour AES-GCM)
        session_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        envelope = {}
        for uid, pub_key in authorized.items():
            encrypted_key = rsa_encrypt(pub_key, session_key)
            envelope[uid] = base64.b64encode(encrypted_key).decode('utf-8')
        return {
            "schema": "EnvelopeEncryption",
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "encrypted_message": base64.b64encode(ciphertext).decode('utf-8'),
            "envelope": envelope
        }

    @staticmethod
    def decrypt(encrypted_data, user_id, rsa_private_key):
        envelope = encrypted_data.get("envelope", {})
        if user_id not in envelope:
            raise Exception("Accès non autorisé à ces données")
        encrypted_session_key = base64.b64decode(envelope[user_id])
        session_key = rsa_decrypt(rsa_private_key, encrypted_session_key)
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["encrypted_message"])
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        message = cipher.decrypt_and_verify(ciphertext, tag)
        return message.decode('utf-8')


# --------------------------------------------
# Système de gestion des dossiers médicaux
# --------------------------------------------
class HealthRecordSystem:
    def __init__(self, db_name="health_records.db", key_manager=None, activity_log_callback=None):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.initialize_database()
        self.current_user = None
        self.current_role = None
        self.rsa_keys = {}
        self.key_dir = "keys"
        os.makedirs(self.key_dir, exist_ok=True)
        self.key_manager = key_manager
        self.activity_log = activity_log_callback if activity_log_callback else lambda msg: None

    def log(self, message):
        self.activity_log(message)

    def initialize_database(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('medecin', 'laborantin', 'patient', 'radiologue')),
            password_hash TEXT NOT NULL,
            rsa_public_key_path TEXT NOT NULL,
            rsa_private_key_path TEXT NOT NULL
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS dossiers_medicaux (
            id TEXT PRIMARY KEY,
            patient_id TEXT NOT NULL,
            medecin_id TEXT NOT NULL,
            date_creation TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (medecin_id) REFERENCES users(id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS notes_medicales (
            id TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            date TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            FOREIGN KEY (dossier_id) REFERENCES dossiers_medicaux(id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS resultats_imagerie (
            id TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            date TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            radiologue_id TEXT NOT NULL,
            FOREIGN KEY (dossier_id) REFERENCES dossiers_medicaux(id)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS resultats_analyses (
            id TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            date TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            laborantin_id TEXT NOT NULL,
            FOREIGN KEY (dossier_id) REFERENCES dossiers_medicaux(id)
        )''')
        self.conn.commit()

    def hash_password(self, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt + key).decode('utf-8')

    def verify_password(self, stored_hash, password):
        decoded = base64.b64decode(stored_hash)
        salt, stored_key = decoded[:16], decoded[16:]
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return key == stored_key

    def register_user(self, nom, prenom, role, password):
        if role not in ['medecin', 'laborantin', 'patient', 'radiologue']:
            self.log("Rôle invalide lors de l'inscription")
            raise ValueError("Rôle invalide")
        user_id = str(uuid.uuid4())
        password_hash = self.hash_password(password)
        user_key_dir = os.path.join(self.key_dir, user_id)
        os.makedirs(user_key_dir, exist_ok=True)
        # Génération des clés RSA
        rsa_private_key, rsa_public_key = generate_rsa_keys()
        rsa_public_key_path = os.path.join(user_key_dir, "rsa_public.pem")
        rsa_private_key_path = os.path.join(user_key_dir, "rsa_private.json")
        # Sauvegarde de la clé publique en clair
        with open(rsa_public_key_path, "wb") as f:
            f.write(rsa_public_key)
        # Chiffrement de la clé privée avec la master key
        cipher = AES.new(self.key_manager.master_key, AES.MODE_GCM)
        encrypted_priv, tag = cipher.encrypt_and_digest(rsa_private_key)
        priv_data = {
            "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "encrypted_priv": base64.b64encode(encrypted_priv).decode('utf-8')
        }
        with open(rsa_private_key_path, "w") as f:
            json.dump(priv_data, f)
        self.cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, nom, prenom, role, password_hash, rsa_public_key_path, rsa_private_key_path)
        )
        self.conn.commit()
        self.log(f"Utilisateur inscrit : {user_id} ({role})")
        return user_id

    def login(self, nom, prenom, password):
        self.cursor.execute("SELECT * FROM users WHERE nom = ? AND prenom = ?", (nom, prenom))
        user = self.cursor.fetchone()
        if not user or not self.verify_password(user[4], password):
            self.log("Échec de connexion pour {} {}".format(nom, prenom))
            return False
        user_id, _, _, role, _, rsa_public_key_path, rsa_private_key_path = user
        # Chargement de la clé publique
        with open(rsa_public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        # Chargement et déchiffrement de la clé privée à l'aide de la master key
        with open(rsa_private_key_path, "r") as f:
            data = json.load(f)
        nonce = base64.b64decode(data["nonce"])
        tag = base64.b64decode(data["tag"])
        encrypted_priv = base64.b64decode(data["encrypted_priv"])
        cipher = AES.new(self.key_manager.master_key, AES.MODE_GCM, nonce=nonce)
        rsa_private_key_bytes = cipher.decrypt_and_verify(encrypted_priv, tag)
        private_key = RSA.import_key(rsa_private_key_bytes)
        self.rsa_keys[user_id] = {"public": public_key, "private": private_key}
        self.current_user, self.current_role = user_id, role
        self.log(f"Connexion réussie : {user_id} ({role})")
        return True

    def logout(self):
        self.log(f"Déconnexion de l'utilisateur {self.current_user}")
        self.current_user = None
        self.current_role = None
        self.rsa_keys = {}

    def delete_account(self):
        if not self.current_user:
            raise Exception("Aucun utilisateur connecté")
        if self.current_role == 'medecin':
            self.cursor.execute("SELECT id FROM dossiers_medicaux WHERE medecin_id = ?", (self.current_user,))
            dossiers = [row[0] for row in self.cursor.fetchall()]
            for dossier in dossiers:
                self.cursor.execute("DELETE FROM notes_medicales WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_imagerie WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_analyses WHERE dossier_id = ?", (dossier,))
            self.cursor.execute("DELETE FROM dossiers_medicaux WHERE medecin_id = ?", (self.current_user,))
        elif self.current_role == 'patient':
            self.cursor.execute("SELECT id FROM dossiers_medicaux WHERE patient_id = ?", (self.current_user,))
            dossiers = [row[0] for row in self.cursor.fetchall()]
            for dossier in dossiers:
                self.cursor.execute("DELETE FROM notes_medicales WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_imagerie WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_analyses WHERE dossier_id = ?", (dossier,))
            self.cursor.execute("DELETE FROM dossiers_medicaux WHERE patient_id = ?", (self.current_user,))
        elif self.current_role == 'laborantin':
            self.cursor.execute("DELETE FROM resultats_analyses WHERE laborantin_id = ?", (self.current_user,))
        elif self.current_role == 'radiologue':
            self.cursor.execute("DELETE FROM resultats_imagerie WHERE radiologue_id = ?", (self.current_user,))
        self.cursor.execute("DELETE FROM users WHERE id = ?", (self.current_user,))
        self.conn.commit()
        self.log(f"Compte supprimé : {self.current_user}")
        user_key_dir = os.path.join(self.key_dir, self.current_user)
        if os.path.exists(user_key_dir):
            shutil.rmtree(user_key_dir)
        self.logout()

    def medecin_create_dossier(self, patient_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : création dossier réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent créer des dossiers")
        self.cursor.execute("SELECT id FROM users WHERE id = ? AND role = 'patient'", (patient_id,))
        if not self.cursor.fetchone():
            self.log("Échec création dossier : patient introuvable")
            raise ValueError("Patient non trouvé")
        dossier_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO dossiers_medicaux VALUES (?, ?, ?, ?)",
            (dossier_id, patient_id, self.current_user, datetime.now().isoformat())
        )
        self.conn.commit()
        self.log(f"Dossier créé : {dossier_id}")
        return dossier_id

    def medecin_add_note(self, dossier_id, note_content):
        if self.current_role != 'medecin':
            self.log("Accès refusé : ajout note réservé aux médecins")
            raise PermissionError("Seuls les médecins peuvent ajouter des notes")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Ajout note échoué : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        patient_id = dossier[0]
        if patient_id not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE id = ?", (patient_id,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_id] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_id: self.rsa_keys[patient_id]["public"]
        }
        encrypted_data = EnvelopeEncryption.encrypt(note_content, envelope)
        note_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO notes_medicales VALUES (?, ?, ?, ?)",
            (note_id, dossier_id, datetime.now().isoformat(), json.dumps(encrypted_data))
        )
        self.conn.commit()
        self.log(f"Note ajoutée par {self.current_user} dans dossier {dossier_id}")
        return True

    def medecin_get_notes(self, dossier_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : visualisation notes réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent voir les notes")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Accès notes refusé : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM notes_medicales WHERE dossier_id = ?", (dossier_id,))
        notes = self.cursor.fetchall()
        result = []
        for note_id, date, enc_data in notes:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": note_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note {note_id}: {str(e)}")
                continue
        return result

    def medecin_get_imaging(self, dossier_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : visualisation imagerie réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Accès imagerie refusé : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?",
                            (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour médecin: {str(e)}")
                continue
        return result

    def medecin_get_lab(self, dossier_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : visualisation analyses réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Accès analyses refusé : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?",
                            (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour médecin: {str(e)}")
                continue
        return result

    def medecin_get_patients_and_dossiers(self):
        if self.current_role != 'medecin':
            raise PermissionError("Seuls les médecins peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT patient_id FROM dossiers_medicaux WHERE medecin_id = ?",
                            (self.current_user,))
        patient_ids = [row[0] for row in self.cursor.fetchall()]
        result = []
        for pid in patient_ids:
            self.cursor.execute("SELECT nom, prenom FROM users WHERE id = ?", (pid,))
            user_data = self.cursor.fetchone()
            nom, prenom = (user_data if user_data else ("", ""))
            self.cursor.execute(
                "SELECT id, date_creation FROM dossiers_medicaux WHERE medecin_id = ? AND patient_id = ?",
                (self.current_user, pid))
            dossiers = [{"id": row[0], "date_creation": row[1]} for row in self.cursor.fetchall()]
            result.append({"patient_id": pid, "nom": nom, "prenom": prenom, "dossiers": dossiers})
        return result

    def radiologue_get_dossiers(self):
        if self.current_role != 'radiologue':
            raise PermissionError("Seuls les radiologues peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT dossier_id FROM resultats_imagerie WHERE radiologue_id = ?",
                            (self.current_user,))
        dossier_ids = [row[0] for row in self.cursor.fetchall()]
        result = []
        for did in dossier_ids:
            self.cursor.execute("SELECT patient_id, date_creation FROM dossiers_medicaux WHERE id = ?", (did,))
            row = self.cursor.fetchone()
            if row:
                result.append({"id": did, "patient_id": row[0], "date_creation": row[1]})
        return result

    def laborantin_get_dossiers(self):
        if self.current_role != 'laborantin':
            raise PermissionError("Seuls les laborantins peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT dossier_id FROM resultats_analyses WHERE laborantin_id = ?",
                            (self.current_user,))
        dossier_ids = [row[0] for row in self.cursor.fetchall()]
        result = []
        for did in dossier_ids:
            self.cursor.execute("SELECT patient_id, date_creation FROM dossiers_medicaux WHERE id = ?", (did,))
            row = self.cursor.fetchone()
            if row:
                result.append({"id": did, "patient_id": row[0], "date_creation": row[1]})
        return result

    def patient_get_dossiers(self):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation dossiers réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir leurs dossiers")
        self.cursor.execute("SELECT id, patient_id, date_creation FROM dossiers_medicaux WHERE patient_id = ?",
                            (self.current_user,))
        return [{"id": row[0], "patient_id": row[1], "date_creation": row[2]} for row in self.cursor.fetchall()]

    def patient_get_notes(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation notes réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir leurs notes")
        self.cursor.execute("SELECT patient_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            self.log("Accès notes refusé : dossier non associé au patient")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM notes_medicales WHERE dossier_id = ?", (dossier_id,))
        notes = self.cursor.fetchall()
        result = []
        for note_id, date, enc_data in notes:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": note_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note {note_id} pour patient: {str(e)}")
                continue
        return result

    def patient_get_imaging(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation imagerie réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            self.log("Accès imagerie refusé : dossier non associé au patient")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?",
                            (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour patient: {str(e)}")
                continue
        return result

    def patient_get_lab(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation analyses réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            self.log("Accès analyses refusé : dossier non associé au patient")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?",
                            (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour patient: {str(e)}")
                continue
        return result

    def radiologue_add_imaging(self, dossier_id, result_content):
        if self.current_role != 'radiologue':
            self.log("Accès refusé : ajout imagerie réservé aux radiologues")
            raise PermissionError("Seuls les radiologues peuvent ajouter des résultats d'imagerie")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
            self.log("Ajout imagerie échoué : dossier introuvable")
            raise ValueError("Dossier non trouvé")
        patient_id, medecin_id = dossier
        if patient_id not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE id = ?", (patient_id,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_id] = {"public": RSA.import_key(f.read())}
        if medecin_id not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE id = ?", (medecin_id,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[medecin_id] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_id: self.rsa_keys[patient_id]["public"],
            medecin_id: self.rsa_keys[medecin_id]["public"]
        }
        encrypted_data = EnvelopeEncryption.encrypt(result_content, envelope)
        result_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO resultats_imagerie VALUES (?, ?, ?, ?, ?)",
            (result_id, dossier_id, datetime.now().isoformat(), json.dumps(encrypted_data), self.current_user)
        )
        self.conn.commit()
        self.log(f"Résultat imagerie ajouté par {self.current_user} dans dossier {dossier_id}")
        return True

    def radiologue_get_imaging(self, dossier_id):
        if self.current_role != 'radiologue':
            self.log("Accès refusé : visualisation imagerie réservée aux radiologues")
            raise PermissionError("Seuls les radiologues peuvent voir leurs résultats d'imagerie")
        self.cursor.execute(
            "SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ? AND radiologue_id = ?",
            (dossier_id, self.current_user))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour radiologue: {str(e)}")
                continue
        return result

    def laborantin_add_lab(self, dossier_id, result_content):
        if self.current_role != 'laborantin':
            self.log("Accès refusé : ajout analyse réservé aux laborantins")
            raise PermissionError("Seuls les laborantins peuvent ajouter des résultats d'analyses")
        self.cursor.execute("SELECT patient_id, medecin_id FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
            self.log("Ajout analyse échoué : dossier introuvable")
            raise ValueError("Dossier non trouvé")
        patient_id, medecin_id = dossier
        if patient_id not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE id = ?", (patient_id,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_id] = {"public": RSA.import_key(f.read())}
        if medecin_id not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE id = ?", (medecin_id,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[medecin_id] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_id: self.rsa_keys[patient_id]["public"],
            medecin_id: self.rsa_keys[medecin_id]["public"]
        }
        encrypted_data = EnvelopeEncryption.encrypt(result_content, envelope)
        result_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO resultats_analyses VALUES (?, ?, ?, ?, ?)",
            (result_id, dossier_id, datetime.now().isoformat(), json.dumps(encrypted_data), self.current_user)
        )
        self.conn.commit()
        self.log(f"Résultat analyse ajouté par {self.current_user} dans dossier {dossier_id}")
        return True

    def laborantin_get_lab(self, dossier_id):
        if self.current_role != 'laborantin':
            self.log("Accès refusé : visualisation analyses réservée aux laborantins")
            raise PermissionError("Seuls les laborantins peuvent voir leurs résultats d'analyses")
        self.cursor.execute(
            "SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ? AND laborantin_id = ?",
            (dossier_id, self.current_user))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user,
                                                     self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour laborantin: {str(e)}")
                continue
        return result

    def close(self):
        self.conn.close()


# --------------------------------------------
# Boîte de dialogue pour mot de passe
# --------------------------------------------
class PasswordDialog:
    def __init__(self, parent, title, confirm=False):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.confirm = confirm
        window_width = 300
        window_height = 150 if confirm else 100
        x = (parent.winfo_screenwidth() - window_width) // 2
        y = (parent.winfo_screenheight() - window_height) // 2
        self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ttk.Label(self.dialog, text="Mot de passe:").grid(row=0, column=0, padx=10, pady=10)
        self.password = ttk.Entry(self.dialog, show="*")
        self.password.grid(row=0, column=1, padx=10, pady=10)
        if confirm:
            ttk.Label(self.dialog, text="Confirmez:").grid(row=1, column=0, padx=10, pady=10)
            self.confirm_password = ttk.Entry(self.dialog, show="*")
            self.confirm_password.grid(row=1, column=1, padx=10, pady=10)
        ttk.Button(self.dialog, text="OK", command=self.on_ok).grid(row=2 if confirm else 1, column=0, pady=10)
        ttk.Button(self.dialog, text="Annuler", command=self.on_cancel).grid(row=2 if confirm else 1, column=1, pady=10)
        self.dialog.wait_window()

    def on_ok(self):
        if self.confirm and self.password.get() != self.confirm_password.get():
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            return
        self.result = self.password.get()
        self.dialog.destroy()

    def on_cancel(self):
        self.dialog.destroy()


# --------------------------------------------
# Interface graphique (Tkinter) avec améliorations UI
# --------------------------------------------
class ABEUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Système Dossiers Médicaux")
        self.root.minsize(900, 700)
        self.nom = tk.StringVar()
        self.prenom = tk.StringVar()
        self.role = tk.StringVar()
        self.patient_id = tk.StringVar()
        self.dossier_id = tk.StringVar()
        self.key_manager = None
        self.health_system = None
        self.theme_mode = "clair"  # "clair" ou "sobre"
        self.setup_ui()
        self.initialize_system()
        self.apply_theme()

    def activity_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def initialize_system(self):
        pwd_dialog = PasswordDialog(self.root, "Mot de passe de la clé maître", confirm=False)
        password = pwd_dialog.result
        if not password:
            messagebox.showerror("Erreur", "Mot de passe requis pour initialiser le système")
            self.root.quit()
        self.key_manager = KeyManager()
        self.key_manager.initialize(password)
        self.health_system = HealthRecordSystem(key_manager=self.key_manager, activity_log_callback=self.activity_log)
        self.activity_log("Système initialisé avec la clé maître.")

    def setup_ui(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Bouton de basculement du thème
        self.theme_button = ttk.Button(self.main_frame, text="Thème : Clair", command=self.toggle_theme)
        self.theme_button.pack(anchor="ne", padx=10, pady=10)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.login_tab = ttk.Frame(self.notebook)
        self.health_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.login_tab, text="Connexion/Inscription")
        self.notebook.add(self.health_tab, text="Gestion Médicale")

        # Onglet Connexion/Inscription
        frame1 = ttk.Frame(self.login_tab, padding=10)
        frame1.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame1, text="Nom:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(frame1, textvariable=self.nom, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Prénom:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(frame1, textvariable=self.prenom, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Rôle:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Combobox(frame1, textvariable=self.role, values=["medecin", "laborantin", "patient", "radiologue"]).grid(
            row=2, column=1, padx=5, pady=5)
        ttk.Button(frame1, text="S'inscrire", command=self.register_user).grid(row=3, column=0, pady=10)
        ttk.Label(frame1, text="Mot de passe:").grid(row=4, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(frame1, show="*")
        self.pass_entry.grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(frame1, text="Se connecter", command=self.login).grid(row=5, column=0, pady=10)

        self.log_frame = ttk.LabelFrame(frame1, text="Journal d'activité")
        self.log_frame.place(relx=0, rely=1, anchor="sw", relwidth=1)
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)

        # Onglet Gestion Médicale
        # Création du Canvas pour les actions avec défilement
        canvas = tk.Canvas(self.health_tab)
        vsb = ttk.Scrollbar(self.health_tab, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="top", fill=tk.BOTH, expand=True)
        self.inner_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")
        self.inner_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))

        frame2 = ttk.Frame(self.inner_frame, padding=10)
        frame2.pack(fill=tk.BOTH, expand=True)

        # Actions et barre de recherche
        self.actions_frame = ttk.Frame(frame2)
        self.actions_frame.pack(fill=tk.BOTH, expand=True)

        # Barre de recherche pour dossiers
        search_frame = ttk.LabelFrame(self.actions_frame, text="Recherche de Dossiers")
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Rechercher :").pack(side=tk.LEFT, padx=5, pady=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        self.search_entry.bind("<KeyRelease>", self.filter_dossiers)
        ttk.Button(search_frame, text="Mes Derniers Dossiers", command=self.view_dossiers).pack(side=tk.LEFT, padx=5,
                                                                                                pady=5)

        # Cadres d'actions pour chaque rôle
        self.medecin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Médecin")
        ttk.Label(self.medecin_frame, text="ID Patient:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Entry(self.medecin_frame, textvariable=self.patient_id).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.medecin_frame, text="Créer Dossier", command=self.create_dossier).pack(side=tk.LEFT, padx=5,
                                                                                               pady=5)
        ttk.Button(self.medecin_frame, text="Voir Mes Patients", command=self.view_patients).pack(side=tk.LEFT, padx=5,
                                                                                                  pady=5)
        ttk.Label(self.medecin_frame, text="Note:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.note_text = scrolledtext.ScrolledText(self.medecin_frame, height=5, width=40)
        self.note_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.medecin_frame, text="Ajouter Note", command=self.add_note).pack(pady=5)

        self.radiologue_frame = ttk.LabelFrame(self.actions_frame, text="Actions Radiologue")
        ttk.Label(self.radiologue_frame, text="Résultat Imagerie:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.imaging_text = scrolledtext.ScrolledText(self.radiologue_frame, height=5, width=40)
        self.imaging_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.radiologue_frame, text="Ajouter Imagerie", command=self.add_imaging).pack(pady=5)
        ttk.Button(self.radiologue_frame, text="Voir Mes Dossiers Traitès (Radiologue)",
                   command=self.view_radiologue_dossiers).pack(pady=5)

        self.laborantin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Laborantin")
        ttk.Label(self.laborantin_frame, text="Résultat Analyse:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.lab_text = scrolledtext.ScrolledText(self.laborantin_frame, height=5, width=40)
        self.lab_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.laborantin_frame, text="Ajouter Analyse", command=self.add_lab).pack(pady=5)
        ttk.Button(self.laborantin_frame, text="Voir Mes Dossiers Traitès (Laborantin)",
                   command=self.view_laborantin_dossiers).pack(pady=5)

        # Cadre des actions communes
        self.common_frame = ttk.Frame(self.actions_frame)
        self.common_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.common_frame, text="ID Dossier:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Entry(self.common_frame, textvariable=self.dossier_id, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        btn_frame = ttk.Frame(self.common_frame)
        btn_frame.pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(btn_frame, text="Voir Notes", command=self.view_notes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Voir Imagerie", command=self.view_imaging).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Voir Analyses", command=self.view_lab).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Voir Mes Dossiers", command=self.view_dossiers).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Se Déconnecter", command=self.logout).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Supprimer Compte", command=self.delete_account).pack(side=tk.LEFT, padx=2)

        # Section Résultats en bas, similaire au journal d'activité
        self.result_frame = ttk.LabelFrame(self.health_tab, text="Résultats")
        self.result_frame.place(relx=0, rely=1, anchor="sw", relwidth=1)
        tree_container = ttk.Frame(self.result_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree = ttk.Treeview(tree_container, columns=("id", "info"), show="headings")
        self.tree.heading("id", text="ID")
        self.tree.heading("info", text="Informations")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        h_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        h_scroll.pack(side=tk.BOTTOM, fill="x")
        self.tree.configure(xscrollcommand=h_scroll.set)
        self.tree.bind("<Double-1>", self.on_treeview_double_click)

    def on_treeview_double_click(self, event):
        selected_item = self.tree.focus()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            if values:
                item_id = values[0]
                self.root.clipboard_clear()
                self.root.clipboard_append(item_id)
                messagebox.showinfo("ID copié", f"L'ID {item_id} a été copié dans le presse-papier.")

    def toggle_theme(self):
        self.theme_mode = "sobre" if self.theme_mode == "clair" else "clair"
        self.apply_theme()
        self.theme_button.config(text=f"Thème : {'Clair' if self.theme_mode == 'clair' else 'Sobre'}")

    def apply_theme(self):
        style = ttk.Style()
        if self.theme_mode == "clair":
            self.root.configure(bg="white")
            style.theme_use('default')
            style.configure("TFrame", background="white")
            style.configure("TLabel", background="white", foreground="black")
            style.configure("TButton", background="lightgrey", foreground="black")
            style.configure("TEntry", fieldbackground="white", foreground="black")
            style.configure("TCombobox", fieldbackground="white", foreground="black")
            self.log_text.config(bg="white", fg="black")
            self.tree.tag_configure('even', background='white')
            self.tree.tag_configure('odd', background='lightgrey')
        else:
            self.root.configure(bg="gray20")
            style.theme_use('clam')
            style.configure("TFrame", background="gray20")
            style.configure("TLabel", background="gray20", foreground="white")
            style.configure("TButton", background="gray40", foreground="white")
            style.configure("TEntry", fieldbackground="gray30", foreground="white")
            style.configure("TCombobox", fieldbackground="gray30", foreground="white")
            self.log_text.config(bg="gray30", fg="white")
            self.tree.tag_configure('even', background='gray30')
            self.tree.tag_configure('odd', background='gray40')

    def register_user(self):
        if not (self.nom.get() and self.prenom.get() and self.role.get() and self.pass_entry.get()):
            messagebox.showerror("Erreur", "Tous les champs doivent être remplis")
            return
        try:
            uid = self.health_system.register_user(self.nom.get(), self.prenom.get(), self.role.get(),
                                                   self.pass_entry.get())
            messagebox.showinfo("Succès", f"Utilisateur inscrit avec l'ID {uid}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def login(self):
    # Clear any previous error messages
        if hasattr(self, 'error_label') and self.error_label:
            self.error_label.destroy()
        
        # Validate fields with improved visual feedback
        fields_valid = True
        empty_fields = []
        
        # Check each field and highlight empty ones
        for field, name in [(self.nom, "Nom"), (self.prenom, "Prénom"), (self.pass_entry, "Mot de passe")]:
            if not field.get().strip():
                fields_valid = False
                empty_fields.append(name)
                field.configure(border_color="#E74C3C")  # Red highlight for empty fields
            else:
                field.configure(border_color="#2ECC71")  # Green highlight for filled fields
        
        if not fields_valid:
            # Show elegant error message below the form
            error_text = f"Veuillez remplir les champs suivants : {', '.join(empty_fields)}"
            self.error_label = ctk.CTkLabel(
                self.login_frame, 
                text=error_text,
                text_color="#E74C3C",
                font=("Roboto", 12)
            )
            self.error_label.pack(pady=(5, 10), padx=20)
            
            # Shake animation for empty fields
            for field_name in empty_fields:
                field = self.nom if field_name == "Nom" else self.prenom if field_name == "Prénom" else self.pass_entry
                self.shake_widget(field)
            
            return
        
        # Show loading animation
        self.login_button.configure(state="disabled", text="Connexion en cours...")
        loading_indicator = self.create_loading_indicator()
        
        # Use after to simulate network request and prevent UI freezing
        self.after(800, lambda: self.process_login(loading_indicator))

    def process_login(self, loading_indicator):
        # Process the actual login
        if self.health_system.login(self.nom.get(), self.prenom.get(), self.pass_entry.get()):
            # Remove loading indicator
            loading_indicator.destroy()
            
            # Success animation
            self.login_button.configure(fg_color="#2ECC71", text="Connecté ✓")
            
            # Show success message with fade-in animation
            self.show_success_message(f"Bienvenue, {self.nom.get()} {self.prenom.get()}")
            
            # Transition to main interface after delay
            self.after(1000, self.update_actions_visibility)
        else:
            # Remove loading indicator
            loading_indicator.destroy()
            
            # Reset button
            self.login_button.configure(state="normal", text="Se connecter")
            
            # Show elegant error message
            self.error_label = ctk.CTkLabel(
                self.login_frame, 
                text="Identifiants incorrects. Veuillez réessayer.",
                text_color="#E74C3C",
                font=("Roboto", 12)
            )
            self.error_label.pack(pady=(5, 10), padx=20)
            
            # Highlight all fields for retry
            for field in [self.nom, self.prenom, self.pass_entry]:
                field.configure(border_color="#E74C3C")
                self.shake_widget(field)

    def create_loading_indicator(self):
        """Create a loading animation indicator"""
        loading_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        loading_frame.pack(pady=(5, 10))
        
        for i in range(4):
            dot = ctk.CTkLabel(
                loading_frame, 
                text="•", 
                font=("Roboto", 24),
                text_color="#3498DB"
            )
            dot.pack(side="left", padx=2)
            
            # Create pulsing animation
            self.animate_loading_dot(dot, i * 200)
        
        return loading_frame

    def animate_loading_dot(self, dot, delay):
        """Create pulsing animation for loading dots"""
        def pulse():
            dot.configure(text_color="#3498DB")
            self.after(200, lambda: dot.configure(text_color="#AED6F1"))
            self.after(400, lambda: dot.configure(text_color="#3498DB"))
        
        self.after(delay, pulse)
        self.after(delay + 800, pulse)  # Repeat animation

    def shake_widget(self, widget):
        """Create shake animation for invalid fields"""
        original_x = widget.winfo_x()
        
        def shake(count, distance):
            if count > 0:
                widget.place(x=original_x + distance)
                self.after(50, lambda: shake(count - 1, -distance))
        
        shake(6, 10)  # Shake 3 times in each direction

    def show_success_message(self, message):
        """Show success message with fade-in animation"""
        success_frame = ctk.CTkFrame(
            self.master,
            fg_color="#2ECC71",
            corner_radius=10
        )
        success_frame.place(relx=0.5, rely=0.1, anchor="center")
        
        success_label = ctk.CTkLabel(
            success_frame,
            text=message,
            text_color="white",
            font=("Roboto", 14, "bold"),
            padx=20,
            pady=10
        )
        success_label.pack()
        
        # Fade out after 2 seconds
        self.after(2000, lambda: self.fade_out_widget(success_frame))

    def fade_out_widget(self, widget, steps=10):
        """Create fade-out animation"""
        def fade(step):
            if step > 0:
                opacity = step / steps
                widget.configure(fg_color=(f"#{int(46 * opacity):02x}{int(204 * opacity):02x}{int(113 * opacity):02x}"))
                self.after(50, lambda: fade(step - 1))
            else:
                widget.destroy()
                
        fade(steps)

    def logout(self):
        self.health_system.logout()
        self.nom.set("")
        self.prenom.set("")
        self.role.set("")
        self.patient_id.set("")
        self.dossier_id.set("")
        self.pass_entry.delete(0, tk.END)
        self.note_text.delete("1.0", tk.END)
        self.imaging_text.delete("1.0", tk.END)
        self.lab_text.delete("1.0", tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.activity_log("Déconnexion réussie")
        self.update_actions_visibility()  # Masquer les cadres de rôle après déconnexion
        messagebox.showinfo("Déconnexion", "Vous avez été déconnecté avec succès.")

    def delete_account(self):
        if messagebox.askyesno("Confirmation",
                               "Êtes-vous sûr de vouloir supprimer votre compte ainsi que toutes les informations associées ? Cette action est irréversible."):
            try:
                self.health_system.delete_account()
                self.nom.set("")
                self.prenom.set("")
                self.role.set("")
                self.patient_id.set("")
                self.dossier_id.set("")
                self.pass_entry.delete(0, tk.END)
                self.note_text.delete("1.0", tk.END)
                self.imaging_text.delete("1.0", tk.END)
                self.lab_text.delete("1.0", tk.END)
                for item in self.tree.get_children():
                    self.tree.delete(item)
                self.activity_log("Compte supprimé et déconnexion effectuée")
                self.update_actions_visibility()  # Masquer les cadres de rôle
                messagebox.showinfo("Compte supprimé",
                                    "Votre compte et toutes les informations associées ont été supprimés avec succès.")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

    def create_dossier(self):
        try:
            dossier_id = self.health_system.medecin_create_dossier(self.patient_id.get())
            self.dossier_id.set(dossier_id)
            messagebox.showinfo("Succès", f"Dossier créé : {dossier_id}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def add_note(self):
        try:
            if self.health_system.medecin_add_note(self.dossier_id.get(), self.note_text.get("1.0", tk.END).strip()):
                messagebox.showinfo("Succès", "Note ajoutée")
                self.note_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def add_imaging(self):
        try:
            if self.health_system.radiologue_add_imaging(self.dossier_id.get(),
                                                         self.imaging_text.get("1.0", tk.END).strip()):
                messagebox.showinfo("Succès", "Résultat d'imagerie ajouté")
                self.imaging_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def add_lab(self):
        try:
            if self.health_system.laborantin_add_lab(self.dossier_id.get(), self.lab_text.get("1.0", tk.END).strip()):
                messagebox.showinfo("Succès", "Résultat d'analyse ajouté")
                self.lab_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_notes(self):
        try:
            if self.health_system.current_role == 'medecin':
                notes = self.health_system.medecin_get_notes(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                notes = self.health_system.patient_get_notes(self.dossier_id.get())
            else:
                raise PermissionError("Rôle non autorisé à voir les notes")
            self.display_results("Notes Médicales", notes)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_imaging(self):
        try:
            if self.health_system.current_role == 'radiologue':
                results = self.health_system.radiologue_get_imaging(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                results = self.health_system.patient_get_imaging(self.dossier_id.get())
            elif self.health_system.current_role == 'medecin':
                results = self.health_system.medecin_get_imaging(self.dossier_id.get())
            else:
                raise PermissionError(
                    "Seuls les radiologues, médecins et patients peuvent voir les résultats d'imagerie")
            self.display_results("Résultats d'Imagerie", results)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_lab(self):
        try:
            if self.health_system.current_role == 'laborantin':
                results = self.health_system.laborantin_get_lab(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                results = self.health_system.patient_get_lab(self.dossier_id.get())
            elif self.health_system.current_role == 'medecin':
                results = self.health_system.medecin_get_lab(self.dossier_id.get())
            else:
                raise PermissionError(
                    "Seuls les laborantins, médecins et patients peuvent voir les résultats d'analyses")
            self.display_results("Résultats d'Analyses", results)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_dossiers(self):
        try:
            if self.health_system.current_role == 'patient':
                records = self.health_system.patient_get_dossiers()
            elif self.health_system.current_role == 'medecin':
                self.health_system.cursor.execute(
                    "SELECT id, patient_id, date_creation FROM dossiers_medicaux WHERE medecin_id = ?",
                    (self.health_system.current_user,)
                )
                records = [{"id": row[0], "patient_id": row[1], "date_creation": row[2]} for row in
                           self.health_system.cursor.fetchall()]
            else:
                raise PermissionError("Seuls les médecins et patients peuvent voir les dossiers")
            self.display_results("Mes Dossiers", records)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def filter_dossiers(self, event=None):
        search_text = self.search_var.get().lower()
        try:
            if self.health_system.current_role == 'patient':
                dossiers = self.health_system.patient_get_dossiers()
            elif self.health_system.current_role == 'medecin':
                self.health_system.cursor.execute(
                    "SELECT id, patient_id, date_creation FROM dossiers_medicaux WHERE medecin_id = ?",
                    (self.health_system.current_user,)
                )
                dossiers = [{"id": row[0], "patient_id": row[1], "date_creation": row[2]} for row in
                            self.health_system.cursor.fetchall()]
            else:
                dossiers = []
            filtered = [d for d in dossiers if
                        search_text in d['id'].lower() or search_text in d['date_creation'].lower()]
            self.display_results("Résultats de la recherche", filtered)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_patients(self):
        try:
            if self.health_system.current_role != 'medecin':
                raise PermissionError("Cette fonctionnalité est réservée aux médecins")
            patients = self.health_system.medecin_get_patients_and_dossiers()
            display_list = []
            for patient in patients:
                dossiers_str = ", ".join([f"{d['id']} ({d['date_creation']})" for d in patient["dossiers"]])
                info = f"{patient['nom']} {patient['prenom']} (ID: {patient['patient_id']}) - Dossiers: {dossiers_str}"
                display_list.append({"id": patient['patient_id'], "info": info})
            self.display_results("Mes Patients", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_radiologue_dossiers(self):
        try:
            if self.health_system.current_role != 'radiologue':
                raise PermissionError("Cette fonctionnalité est réservée aux radiologues")
            dossiers = self.health_system.radiologue_get_dossiers()
            display_list = [{"id": d["id"], "info": f"Patient: {d['patient_id']} - Création: {d['date_creation']}"} for
                            d in dossiers]
            self.display_results("Mes Dossiers Traitès (Radiologue)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_laborantin_dossiers(self):
        try:
            if self.health_system.current_role != 'laborantin':
                raise PermissionError("Cette fonctionnalité est réservée aux laborantins")
            dossiers = self.health_system.laborantin_get_dossiers()
            display_list = [{"id": d["id"], "info": f"Patient: {d['patient_id']} - Création: {d['date_creation']}"} for
                            d in dossiers]
            self.display_results("Mes Dossiers Traitès (Laborantin)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def display_results(self, title, results):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.activity_log(f"Affichage: {title}")
        for idx, item in enumerate(results):
            info = ""
            if "contenu" in item:
                info = item["contenu"]
            elif "date_creation" in item:
                info = f"Date: {item['date_creation']}"
            else:
                info = item.get("info", "")
            tag = 'even' if idx % 2 == 0 else 'odd'
            self.tree.insert("", tk.END, values=(item.get("id", ""), info), tags=(tag,))

    # Méthode pour mettre à jour l'affichage des actions en fonction du rôle de l'utilisateur
    def update_actions_visibility(self):
        # Masquer tous les cadres spécifiques aux rôles
        self.medecin_frame.pack_forget()
        self.radiologue_frame.pack_forget()
        self.laborantin_frame.pack_forget()
        # Afficher uniquement le cadre correspondant au rôle connecté
        if self.health_system.current_role == "medecin":
            self.medecin_frame.pack(fill=tk.X, pady=5)
        elif self.health_system.current_role == "radiologue":
            self.radiologue_frame.pack(fill=tk.X, pady=5)
        elif self.health_system.current_role == "laborantin":
            self.laborantin_frame.pack(fill=tk.X, pady=5)
        # Pour les patients, aucun cadre spécifique n'est affiché


if __name__ == "__main__":
    root = tk.Tk()
    app = ABEUI(root)
    root.mainloop()