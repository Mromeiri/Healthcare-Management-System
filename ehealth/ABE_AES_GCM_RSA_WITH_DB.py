#!/usr/bin/env python3
"""
Système de dossiers médicaux avec gestion de clé maître,
méthode d'enveloppe pour chiffrer les données, chiffrement des clés privées RSA avec la master key,
et contraintes d'accès par rôle.
Ajout des champs téléphone, genre, groupe sanguin dans users selon le rôle.
Adaptation de l'interface d'inscription et de l'onglet Profil avec nombre de dossiers.
"""

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
import re

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
        session_key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        envelope = {}
        for email, pub_key in authorized.items():
            encrypted_key = rsa_encrypt(pub_key, session_key)
            envelope[email] = base64.b64encode(encrypted_key).decode('utf-8')
        return {
            "schema": "EnvelopeEncryption",
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "encrypted_message": base64.b64encode(ciphertext).decode('utf-8'),
            "envelope": envelope
        }

    @staticmethod
    def decrypt(encrypted_data, user_email, rsa_private_key):
        envelope = encrypted_data.get("envelope", {})
        if user_email not in envelope:
            raise Exception("Accès non autorisé à ces données")
        encrypted_session_key = base64.b64decode(envelope[user_email])
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
            email TEXT PRIMARY KEY,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('medecin', 'laborantin', 'patient', 'radiologue')),
            password_hash TEXT NOT NULL,
            adresse TEXT NOT NULL,
            date_naissance TEXT NOT NULL,
            telephone TEXT,
            genre TEXT,
            groupe_sanguin TEXT,
            rsa_public_key_path TEXT NOT NULL,
            rsa_private_key_path TEXT NOT NULL
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS dossiers_medicaux (
            id TEXT PRIMARY KEY,
            patient_email TEXT NOT NULL,
            medecin_email TEXT NOT NULL,
            date_creation TEXT NOT NULL,
            FOREIGN KEY (patient_email) REFERENCES users(email),
            FOREIGN KEY (medecin_email) REFERENCES users(email)
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
            radiologue_email TEXT NOT NULL,
            FOREIGN KEY (dossier_id) REFERENCES dossiers_medicaux(id),
            FOREIGN KEY (radiologue_email) REFERENCES users(email)
        )''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS resultats_analyses (
            id TEXT PRIMARY KEY,
            dossier_id TEXT NOT NULL,
            date TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,
            laborantin_email TEXT NOT NULL,
            FOREIGN KEY (dossier_id) REFERENCES dossiers_medicaux(id),
            FOREIGN KEY (laborantin_email) REFERENCES users(email)
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
    
    def is_valid_email(self, email):
        # Vérifie si l'email a la forme standard : quelquechose@domaine.extension
        pattern = r"[^@]+@[^@]+\.[^@]+"
        return re.match(pattern, email)
    
    def is_valid_phone(self, phone):
        # Vérifie que le numéro de téléphone contient uniquement des chiffres
        return phone.isdigit()

    def register_user(self, email, nom, prenom, role, password, adresse, date_naissance, telephone=None, genre=None, groupe_sanguin=None):
        if not self.is_valid_email(email):
            messagebox.showerror("Erreur", "L'email fourni n'est pas valide.")
            self.log("Email non valide")
            raise ValueError("Email invalide")

        if role not in ['medecin', 'laborantin', 'patient', 'radiologue']:
            self.log("Rôle invalide lors de l'inscription")
            raise ValueError("Rôle invalide")
        self.cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        if self.cursor.fetchone():
            self.log("L'utilisateur existe déjà")
            raise ValueError("L'utilisateur existe déjà")
        password_hash = self.hash_password(password)
        user_key_dir = os.path.join(self.key_dir, email)
        os.makedirs(user_key_dir, exist_ok=True)
        rsa_private_key, rsa_public_key = generate_rsa_keys()
        rsa_public_key_path = os.path.join(user_key_dir, "rsa_public.pem")
        rsa_private_key_path = os.path.join(user_key_dir, "rsa_private.json")
        with open(rsa_public_key_path, "wb") as f:
            f.write(rsa_public_key)
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
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (email, nom, prenom, role, password_hash, adresse, date_naissance, telephone, genre, groupe_sanguin, rsa_public_key_path, rsa_private_key_path)
        )
        self.conn.commit()
        self.log(f"Utilisateur inscrit : {email} ({role})")
        return email

    def login(self, email, password):
        self.cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = self.cursor.fetchone()
        if not user or not self.verify_password(user[4], password):
            self.log(f"Échec de connexion pour {email}")
            return False
        email, _, _, role, _, _, _, _, _, _, rsa_public_key_path, rsa_private_key_path = user
        with open(rsa_public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        with open(rsa_private_key_path, "r") as f:
            data = json.load(f)
        nonce = base64.b64decode(data["nonce"])
        tag = base64.b64decode(data["tag"])
        encrypted_priv = base64.b64decode(data["encrypted_priv"])
        cipher = AES.new(self.key_manager.master_key, AES.MODE_GCM, nonce=nonce)
        rsa_private_key_bytes = cipher.decrypt_and_verify(encrypted_priv, tag)
        private_key = RSA.import_key(rsa_private_key_bytes)
        self.rsa_keys[email] = {"public": public_key, "private": private_key}
        self.current_user, self.current_role = email, role
        self.log(f"Connexion réussie : {email} ({role})")
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
            self.cursor.execute("SELECT id FROM dossiers_medicaux WHERE medecin_email = ?", (self.current_user,))
            dossiers = [row[0] for row in self.cursor.fetchall()]
            for dossier in dossiers:
                self.cursor.execute("DELETE FROM notes_medicales WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_imagerie WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_analyses WHERE dossier_id = ?", (dossier,))
            self.cursor.execute("DELETE FROM dossiers_medicaux WHERE medecin_email = ?", (self.current_user,))
        elif self.current_role == 'patient':
            self.cursor.execute("SELECT id FROM dossiers_medicaux WHERE patient_email = ?", (self.current_user,))
            dossiers = [row[0] for row in self.cursor.fetchall()]
            for dossier in dossiers:
                self.cursor.execute("DELETE FROM notes_medicales WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_imagerie WHERE dossier_id = ?", (dossier,))
                self.cursor.execute("DELETE FROM resultats_analyses WHERE dossier_id = ?", (dossier,))
            self.cursor.execute("DELETE FROM dossiers_medicaux WHERE patient_email = ?", (self.current_user,))
        elif self.current_role == 'laborantin':
            self.cursor.execute("DELETE FROM resultats_analyses WHERE laborantin_email = ?", (self.current_user,))
        elif self.current_role == 'radiologue':
            self.cursor.execute("DELETE FROM resultats_imagerie WHERE radiologue_email = ?", (self.current_user,))
        self.cursor.execute("DELETE FROM users WHERE email = ?", (self.current_user,))
        self.conn.commit()
        self.log(f"Compte supprimé : {self.current_user}")
        user_key_dir = os.path.join(self.key_dir, self.current_user)
        if os.path.exists(user_key_dir):
            shutil.rmtree(user_key_dir)
        self.logout()

    def get_user_profile(self):
        if not self.current_user:
            raise Exception("Aucun utilisateur connecté")
        self.cursor.execute("SELECT email, nom, prenom, role, adresse, date_naissance, telephone, genre, groupe_sanguin FROM users WHERE email = ?", (self.current_user,))
        return self.cursor.fetchone()

    def get_dossier_count(self):
        if not self.current_user:
            return 0
        if self.current_role == 'medecin':
            self.cursor.execute("SELECT COUNT(*) FROM dossiers_medicaux WHERE medecin_email = ?", (self.current_user,))
        elif self.current_role == 'patient':
            self.cursor.execute("SELECT COUNT(*) FROM dossiers_medicaux WHERE patient_email = ?", (self.current_user,))
        elif self.current_role == 'radiologue':
            self.cursor.execute("SELECT COUNT(DISTINCT dossier_id) FROM resultats_imagerie WHERE radiologue_email = ?", (self.current_user,))
        elif self.current_role == 'laborantin':
            self.cursor.execute("SELECT COUNT(DISTINCT dossier_id) FROM resultats_analyses WHERE laborantin_email = ?", (self.current_user,))
        else:
            return 0
        return self.cursor.fetchone()[0]

    def medecin_create_dossier(self, patient_email):
        if self.current_role != 'medecin':
            self.log("Accès refusé : création dossier réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent créer des dossiers")
        self.cursor.execute("SELECT email FROM users WHERE email = ? AND role = 'patient'", (patient_email,))
        if not self.cursor.fetchone():
            self.log("Échec création dossier : patient introuvable")
            raise ValueError("Patient non trouvé")
        dossier_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO dossiers_medicaux VALUES (?, ?, ?, ?)",
            (dossier_id, patient_email, self.current_user, datetime.now().isoformat())
        )
        self.conn.commit()
        self.log(f"Dossier créé : {dossier_id}")
        return dossier_id

    def medecin_add_note(self, dossier_id, note_content):
        if self.current_role != 'medecin':
            self.log("Accès refusé : ajout note réservé aux médecins")
            raise PermissionError("Seuls les médecins peuvent ajouter des notes")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Ajout note échoué : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        patient_email = dossier[0]
        if patient_email not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (patient_email,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_email] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_email: self.rsa_keys[patient_email]["public"]
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
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
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
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": note_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note {note_id}: {str(e)}")
                continue
        return result

    def medecin_get_imaging(self, dossier_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : visualisation imagerie réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Accès imagerie refusé : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour médecin: {str(e)}")
                continue
        return result

    def medecin_get_lab(self, dossier_id):
        if self.current_role != 'medecin':
            self.log("Accès refusé : visualisation analyses réservée aux médecins")
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            self.log("Accès analyses refusé : dossier non associé au médecin")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour médecin: {str(e)}")
                continue
        return result

    def medecin_get_patients_and_dossiers(self):
        if self.current_role != 'medecin':
            raise PermissionError("Seuls les médecins peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT patient_email FROM dossiers_medicaux WHERE medecin_email = ?", (self.current_user,))
        patient_emails = [row[0] for row in self.cursor.fetchall()]
        result = []
        for email in patient_emails:
            self.cursor.execute("SELECT nom, prenom FROM users WHERE email = ?", (email,))
            user_data = self.cursor.fetchone()
            nom, prenom = (user_data if user_data else ("", ""))
            self.cursor.execute(
                "SELECT id, date_creation FROM dossiers_medicaux WHERE medecin_email = ? AND patient_email = ?",
                (self.current_user, email)
            )
            dossiers = [{"id": row[0], "date_creation": row[1]} for row in self.cursor.fetchall()]
            result.append({"patient_email": email, "nom": nom, "prenom": prenom, "dossiers": dossiers})
        return result

    def radiologue_get_dossiers(self):
        if self.current_role != 'radiologue':
            raise PermissionError("Seuls les radiologues peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT dossier_id FROM resultats_imagerie WHERE radiologue_email = ?", (self.current_user,))
        dossier_ids = [row[0] for row in self.cursor.fetchall()]
        result = []
        for did in dossier_ids:
            self.cursor.execute("SELECT patient_email, date_creation FROM dossiers_medicaux WHERE id = ?", (did,))
            row = self.cursor.fetchone()
            if row:
                result.append({"id": did, "patient_email": row[0], "date_creation": row[1]})
        return result

    def laborantin_get_dossiers(self):
        if self.current_role != 'laborantin':
            raise PermissionError("Seuls les laborantins peuvent accéder à cette fonctionnalité")
        self.cursor.execute("SELECT DISTINCT dossier_id FROM resultats_analyses WHERE laborantin_email = ?", (self.current_user,))
        dossier_ids = [row[0] for row in self.cursor.fetchall()]
        result = []
        for did in dossier_ids:
            self.cursor.execute("SELECT patient_email, date_creation FROM dossiers_medicaux WHERE id = ?", (did,))
            row = self.cursor.fetchone()
            if row:
                result.append({"id": did, "patient_email": row[0], "date_creation": row[1]})
        return result

    def patient_get_dossiers(self):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation dossiers réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir leurs dossiers")
        self.cursor.execute("SELECT id, patient_email, date_creation FROM dossiers_medicaux WHERE patient_email = ?", (self.current_user,))
        return [{"id": row[0], "patient_email": row[1], "date_creation": row[2]} for row in self.cursor.fetchall()]

    def patient_get_notes(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation notes réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir leurs notes")
        self.cursor.execute("SELECT patient_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
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
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": note_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note {note_id} pour patient: {str(e)}")
                continue
        return result

    def patient_get_imaging(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation imagerie réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            self.log("Accès imagerie refusé : dossier non associé au patient")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour patient: {str(e)}")
                continue
        return result

    def patient_get_lab(self, dossier_id):
        if self.current_role != 'patient':
            self.log("Accès refusé : visualisation analyses réservée aux patients")
            raise PermissionError("Seuls les patients peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            self.log("Accès analyses refusé : dossier non associé au patient")
            raise PermissionError("Accès refusé au dossier")
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour patient: {str(e)}")
                continue
        return result

    def radiologue_add_imaging(self, dossier_id, result_content):
        if self.current_role != 'radiologue':
            self.log("Accès refusé : ajout imagerie réservé aux radiologues")
            raise PermissionError("Seuls les radiologues peuvent ajouter des résultats d'imagerie")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
            self.log("Ajout imagerie échoué : dossier introuvable")
            raise ValueError("Dossier non trouvé")
        patient_email, medecin_email = dossier
        if patient_email not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (patient_email,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_email] = {"public": RSA.import_key(f.read())}
        if medecin_email not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (medecin_email,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[medecin_email] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_email: self.rsa_keys[patient_email]["public"],
            medecin_email: self.rsa_keys[medecin_email]["public"]
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
            "SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ? AND radiologue_email = ?",
            (dossier_id, self.current_user)
        )
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
                result.append({"id": res_id, "date": date, "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour radiologue: {str(e)}")
                continue
        return result

    def laborantin_add_lab(self, dossier_id, result_content):
        if self.current_role != 'laborantin':
            self.log("Accès refusé : ajout analyse réservé aux laborantins")
            raise PermissionError("Seuls les laborantins peuvent ajouter des résultats d'analyses")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
            self.log("Ajout analyse échoué : dossier introuvable")
            raise ValueError("Dossier non trouvé")
        patient_email, medecin_email = dossier
        if patient_email not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (patient_email,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[patient_email] = {"public": RSA.import_key(f.read())}
        if medecin_email not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (medecin_email,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[medecin_email] = {"public": RSA.import_key(f.read())}
        envelope = {
            self.current_user: self.rsa_keys[self.current_user]["public"],
            patient_email: self.rsa_keys[patient_email]["public"],
            medecin_email: self.rsa_keys[medecin_email]["public"]
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
            "SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ? AND laborantin_email = ?",
            (dossier_id, self.current_user)
        )
        results = self.cursor.fetchall()
        result = []
        for res_id, date, enc_data in results:
            try:
                data = json.loads(enc_data)
                contenu = EnvelopeEncryption.decrypt(data, self.current_user, self.rsa_keys[self.current_user]["private"])
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
        self.email = tk.StringVar()
        self.nom = tk.StringVar()
        self.prenom = tk.StringVar()
        self.role = tk.StringVar()
        self.adresse = tk.StringVar()
        self.date_naissance = tk.StringVar()
        self.telephone = tk.StringVar()
        self.genre = tk.StringVar()
        self.groupe_sanguin = tk.StringVar()
        self.patient_email = tk.StringVar()
        self.dossier_id = tk.StringVar()
        self.key_manager = None
        self.health_system = None
        self.theme_mode = "clair"
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

        self.theme_button = ttk.Button(self.main_frame, text="Thème : Clair", command=self.toggle_theme)
        self.theme_button.pack(anchor="ne", padx=10, pady=10)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.login_tab = ttk.Frame(self.notebook)
        self.health_tab = ttk.Frame(self.notebook)
        self.profil_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.login_tab, text="Connexion/Inscription")
        self.notebook.add(self.health_tab, text="Gestion Médicale")
        self.notebook.add(self.profil_tab, text="Profil")

        # Onglet Connexion/Inscription
        frame1 = ttk.Frame(self.login_tab, padding=10)
        frame1.pack(fill=tk.BOTH, expand=True)

        # Champs communs
        ttk.Label(frame1, text="Email:").grid(row=0, column=0, sticky="w", pady=5)
        self.email_entry = ttk.Entry(frame1, textvariable=self.email, width=50)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Nom:").grid(row=1, column=0, sticky="w", pady=5)
        self.nom_entry = ttk.Entry(frame1, textvariable=self.nom, width=50)
        self.nom_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Prénom:").grid(row=2, column=0, sticky="w", pady=5)
        self.prenom_entry = ttk.Entry(frame1, textvariable=self.prenom, width=50)
        self.prenom_entry.grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Rôle:").grid(row=3, column=0, sticky="w", pady=5)
        self.role_combobox = ttk.Combobox(frame1, textvariable=self.role, values=["medecin", "laborantin", "patient", "radiologue"])
        self.role_combobox.grid(row=3, column=1, padx=5, pady=5)
        self.role_combobox.bind("<<ComboboxSelected>>", self.update_inscription_fields)
        ttk.Label(frame1, text="Adresse:").grid(row=4, column=0, sticky="w", pady=5)
        self.adresse_entry = ttk.Entry(frame1, textvariable=self.adresse, width=50)
        self.adresse_entry.grid(row=4, column=1, padx=5, pady=5)
        ttk.Label(frame1, text="Date de naissance (YYYY-MM-DD):").grid(row=5, column=0, sticky="w", pady=5)
        self.date_naissance_entry = ttk.Entry(frame1, textvariable=self.date_naissance, width=50)
        self.date_naissance_entry.grid(row=5, column=1, padx=5, pady=5)
        
        # Affichage du numéro de téléphone (toujours visible)
        self.telephone_label = ttk.Label(frame1, text="Téléphone:")
        self.telephone_entry = ttk.Entry(frame1, textvariable=self.telephone, width=50)
        self.telephone_label.grid(row=6, column=0, sticky="w", pady=5)
        self.telephone_entry.grid(row=6, column=1, padx=5, pady=5)
        
        # Champs spécifiques au rôle patient
        self.genre_label = ttk.Label(frame1, text="Genre (M/F):")
        self.genre_entry = ttk.Entry(frame1, textvariable=self.genre, width=50)
        self.groupe_sanguin_label = ttk.Label(frame1, text="Groupe sanguin (A/B/AB/O):")
        self.groupe_sanguin_entry = ttk.Entry(frame1, textvariable=self.groupe_sanguin, width=50)

        # Boutons et mot de passe
        ttk.Button(frame1, text="S'inscrire", command=self.register_user).grid(row=10, column=0, pady=10)
        ttk.Label(frame1, text="Mot de passe:").grid(row=11, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(frame1, show="*")
        self.pass_entry.grid(row=11, column=1, padx=5, pady=5)
        ttk.Button(frame1, text="Se connecter", command=self.login).grid(row=12, column=0, pady=10)

        self.log_frame = ttk.LabelFrame(frame1, text="Journal d'activité")
        self.log_frame.place(relx=0, rely=1, anchor="sw", relwidth=1)
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)

        # Onglet Gestion Médicale
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

        self.actions_frame = ttk.Frame(frame2)
        self.actions_frame.pack(fill=tk.BOTH, expand=True)

        search_frame = ttk.LabelFrame(self.actions_frame, text="Recherche de Dossiers")
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Rechercher :").pack(side=tk.LEFT, padx=5, pady=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        self.search_entry.bind("<KeyRelease>", self.filter_dossiers)
        ttk.Button(search_frame, text="Mes Derniers Dossiers", command=self.view_dossiers).pack(side=tk.LEFT, padx=5, pady=5)

        self.medecin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Médecin")
        ttk.Label(self.medecin_frame, text="Email Patient:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Entry(self.medecin_frame, textvariable=self.patient_email).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.medecin_frame, text="Créer Dossier", command=self.create_dossier).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.medecin_frame, text="Voir Mes Patients", command=self.view_patients).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Label(self.medecin_frame, text="Note:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.note_text = scrolledtext.ScrolledText(self.medecin_frame, height=5, width=40)
        self.note_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.medecin_frame, text="Ajouter Note", command=self.add_note).pack(pady=5)

        self.radiologue_frame = ttk.LabelFrame(self.actions_frame, text="Actions Radiologue")
        ttk.Label(self.radiologue_frame, text="Résultat Imagerie:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.imaging_text = scrolledtext.ScrolledText(self.radiologue_frame, height=5, width=40)
        self.imaging_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.radiologue_frame, text="Ajouter Imagerie", command=self.add_imaging).pack(pady=5)
        ttk.Button(self.radiologue_frame, text="Voir Mes Dossiers Traités (Radiologue)", command=self.view_radiologue_dossiers).pack(pady=5)

        self.laborantin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Laborantin")
        ttk.Label(self.laborantin_frame, text="Résultat Analyse:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.lab_text = scrolledtext.ScrolledText(self.laborantin_frame, height=5, width=40)
        self.lab_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.laborantin_frame, text="Ajouter Analyse", command=self.add_lab).pack(pady=5)
        ttk.Button(self.laborantin_frame, text="Voir Mes Dossiers Traités (Laborantin)", command=self.view_laborantin_dossiers).pack(pady=5)

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
        # Modification : au double-clic, on affiche la fenêtre popup avec le détail du dossier.
        self.tree.bind("<Double-1>", self.on_treeview_double_click)

        # Onglet Profil
        profil_frame = ttk.Frame(self.profil_tab, padding=10)
        profil_frame.pack(fill=tk.BOTH, expand=True)
        self.profil_text = scrolledtext.ScrolledText(profil_frame, height=10, wrap=tk.WORD)
        self.profil_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.profil_text.config(state=tk.DISABLED)
        ttk.Button(profil_frame, text="Afficher Profil", command=self.display_profile).pack(pady=10)

    def update_inscription_fields(self, event=None):
        role = self.role.get()
        # Le champ téléphone reste affiché pour tous les rôles.
        self.telephone_label.grid(row=6, column=0, sticky="w", pady=5)
        self.telephone_entry.grid(row=6, column=1, padx=5, pady=5)
        if role == "patient":
            self.genre_label.grid(row=7, column=0, sticky="w", pady=5)
            self.genre_entry.grid(row=7, column=1, padx=5, pady=5)
            self.groupe_sanguin_label.grid(row=8, column=0, sticky="w", pady=5)
            self.groupe_sanguin_entry.grid(row=8, column=1, padx=5, pady=5)
        else:
            self.genre_label.grid_forget()
            self.genre_entry.grid_forget()
            self.groupe_sanguin_label.grid_forget()
            self.groupe_sanguin_entry.grid_forget()

    # Nouvelle fonction pour afficher les détails du dossier dans une popup.
    def display_dossier_popup(self, dossier_id):
        popup = tk.Toplevel(self.root)
        popup.title("Détails du Dossier")
        popup.geometry("600x400")
        info_text = scrolledtext.ScrolledText(popup, width=80, height=20)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        try:
            # Récupération des informations du dossier
            self.health_system.cursor.execute("SELECT * FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
            dossier = self.health_system.cursor.fetchone()
            if dossier:
                id_dossier, patient_email, medecin_email, date_creation = dossier
                details = f"Dossier ID : {id_dossier}\nDate de création : {date_creation}\n"
                # Pour les médecins, on affiche les informations détaillées du patient
                if self.health_system.current_role == "medecin":
                    self.health_system.cursor.execute("SELECT nom, prenom, genre, groupe_sanguin, telephone, adresse FROM users WHERE email = ?", (patient_email,))
                    patient = self.health_system.cursor.fetchone()
                    if patient:
                        nom, prenom, genre, groupe_sanguin, telephone, adresse = patient
                        details += f"\n--- Informations Patient ---\nEmail : {patient_email}\nNom : {nom}\nPrénom : {prenom}\nGenre : {genre}\nGroupe sanguin : {groupe_sanguin}\nTéléphone : {telephone}\nAdresse : {adresse}\n"
                # Pour les patients, on affiche une confirmation
                elif self.health_system.current_role == "patient":
                    details += "\nCeci est votre dossier patient."
                # Pour radiologues et laborantins, on affiche les informations de base du dossier
                else:
                    details += f"\nPatient : {patient_email}\nMédecin : {medecin_email}\n"
                # Affichage des notes si accessibles (médecin et patient)
                try:
                    if self.health_system.current_role in ["medecin", "patient"]:
                        if self.health_system.current_role == "medecin":
                            notes = self.health_system.medecin_get_notes(dossier_id)
                        else:
                            notes = self.health_system.patient_get_notes(dossier_id)
                        if notes:
                            details += "\n--- Notes Médicales ---\n"
                            for note in notes:
                                details += f"Date : {note['date']}\nContenu : {note['contenu']}\n\n"
                        else:
                            details += "\nAucune note disponible.\n"
                except Exception as e:
                    details += f"\nErreur lors de la récupération des notes : {str(e)}\n"
                info_text.insert(tk.END, details)
            else:
                info_text.insert(tk.END, "Dossier introuvable.")
        except Exception as e:
            info_text.insert(tk.END, f"Erreur : {str(e)}")
        info_text.config(state=tk.DISABLED)

    # Modification de la fonction double-clic pour afficher le popup des détails du dossier
    def on_treeview_double_click(self, event):
        selected_item = self.tree.focus()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            if values and values[0]:
                dossier_id = values[0]
                self.display_dossier_popup(dossier_id)

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
            self.profil_text.config(bg="white", fg="black")
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
            self.profil_text.config(bg="gray30", fg="white")
            self.tree.tag_configure('even', background='gray30')
            self.tree.tag_configure('odd', background='gray40')

    def register_user(self):
        role = self.role.get()
        # Vérification des champs obligatoires
        if not (self.email.get() and self.nom.get() and self.prenom.get() and role and self.adresse.get() and self.date_naissance.get() and self.pass_entry.get() and self.telephone.get()):
            messagebox.showerror("Erreur", "Tous les champs obligatoires doivent être remplis")
            return
        # Validation de l'email
        email_input = self.email.get().strip()
        if not self.health_system.is_valid_email(email_input):
            messagebox.showerror("Erreur", "L'email fourni n'est pas valide.")
            return
        # Validation du numéro de téléphone (pour tous les rôles)
        phone_input = self.telephone.get().strip()
        if not phone_input:
            messagebox.showerror("Erreur", "Le téléphone est requis.")
            return
        if not self.health_system.is_valid_phone(phone_input):
            messagebox.showerror("Erreur", "Le numéro de téléphone doit contenir uniquement des chiffres.")
            return
        telephone = phone_input
        if role == "patient":
            if not (self.genre.get() and self.groupe_sanguin.get()):
                messagebox.showerror("Erreur", "Pour le rôle patient, genre et groupe sanguin sont requis")
                return
            genre = self.genre.get().strip()
            groupe_sanguin = self.groupe_sanguin.get().strip()
        else:
            genre = None
            groupe_sanguin = None
        try:
            self.health_system.register_user(
                email_input, self.nom.get(), self.prenom.get(), role, self.pass_entry.get(),
                self.adresse.get(), self.date_naissance.get(), telephone, genre, groupe_sanguin
            )
            messagebox.showinfo("Succès", f"Utilisateur inscrit avec l'email {email_input}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def login(self):
        if not (self.email.get() and self.pass_entry.get()):
            messagebox.showerror("Erreur", "Email et mot de passe requis")
            return
        if self.health_system.login(self.email.get(), self.pass_entry.get()):
            messagebox.showinfo("Succès", f"Connecté en tant que {self.health_system.current_role}")
            self.update_actions_visibility()
            self.display_profile()
        else:
            messagebox.showerror("Erreur", "Email ou mot de passe incorrect")

    def logout(self):
        self.health_system.logout()
        self.email.set("")
        self.nom.set("")
        self.prenom.set("")
        self.role.set("")
        self.adresse.set("")
        self.date_naissance.set("")
        self.telephone.set("")
        self.genre.set("")
        self.groupe_sanguin.set("")
        self.patient_email.set("")
        self.dossier_id.set("")
        self.pass_entry.delete(0, tk.END)
        self.note_text.delete("1.0", tk.END)
        self.imaging_text.delete("1.0", tk.END)
        self.lab_text.delete("1.0", tk.END)
        self.profil_text.config(state=tk.NORMAL)
        self.profil_text.delete("1.0", tk.END)
        self.profil_text.config(state=tk.DISABLED)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.activity_log("Déconnexion réussie")
        self.update_actions_visibility()
        messagebox.showinfo("Déconnexion", "Vous avez été déconnecté avec succès.")

    def delete_account(self):
        if messagebox.askyesno("Confirmation", "Êtes-vous sûr de vouloir supprimer votre compte ainsi que toutes les informations associées ? Cette action est irréversible."):
            try:
                self.health_system.delete_account()
                self.email.set("")
                self.nom.set("")
                self.prenom.set("")
                self.role.set("")
                self.adresse.set("")
                self.date_naissance.set("")
                self.telephone.set("")
                self.genre.set("")
                self.groupe_sanguin.set("")
                self.patient_email.set("")
                self.dossier_id.set("")
                self.pass_entry.delete(0, tk.END)
                self.note_text.delete("1.0", tk.END)
                self.imaging_text.delete("1.0", tk.END)
                self.lab_text.delete("1.0", tk.END)
                self.profil_text.config(state=tk.NORMAL)
                self.profil_text.delete("1.0", tk.END)
                self.profil_text.config(state=tk.DISABLED)
                for item in self.tree.get_children():
                    self.tree.delete(item)
                self.activity_log("Compte supprimé et déconnexion effectuée")
                self.update_actions_visibility()
                messagebox.showinfo("Compte supprimé", "Votre compte et toutes les informations associées ont été supprimés avec succès.")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

    def display_profile(self):
        if not self.health_system.current_user:
            messagebox.showerror("Erreur", "Aucun utilisateur connecté")
            return
        try:
            profile = self.health_system.get_user_profile()
            if profile:
                email, nom, prenom, role, adresse, date_naissance, telephone, genre, groupe_sanguin = profile
                dossier_count = self.health_system.get_dossier_count()
                profile_info = f"Email: {email}\nNom: {nom}\nPrénom: {prenom}\nRôle: {role}\nAdresse: {adresse}\nDate de naissance: {date_naissance}\n"
                profile_info += f"Téléphone: {telephone}\n"
                if role == "patient":
                    profile_info += f"Genre: {genre}\nGroupe sanguin: {groupe_sanguin}\n"
                profile_info += f"Nombre de dossiers: {dossier_count}"
                self.profil_text.config(state=tk.NORMAL)
                self.profil_text.delete("1.0", tk.END)
                self.profil_text.insert(tk.END, profile_info)
                self.profil_text.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Erreur", "Profil non trouvé")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def create_dossier(self):
        try:
            dossier_id = self.health_system.medecin_create_dossier(self.patient_email.get())
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
            if self.health_system.radiologue_add_imaging(self.dossier_id.get(), self.imaging_text.get("1.0", tk.END).strip()):
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
                raise PermissionError("Seuls les radiologues, médecins et patients peuvent voir les résultats d'imagerie")
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
                raise PermissionError("Seuls les laborantins, médecins et patients peuvent voir les résultats d'analyses")
            self.display_results("Résultats d'Analyses", results)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_dossiers(self):
        try:
            if self.health_system.current_role == 'patient':
                records = self.health_system.patient_get_dossiers()
            elif self.health_system.current_role == 'medecin':
                self.health_system.cursor.execute(
                    "SELECT id, patient_email, date_creation FROM dossiers_medicaux WHERE medecin_email = ?",
                    (self.health_system.current_user,)
                )
                records = [{"id": row[0], "patient_email": row[1], "date_creation": row[2]} for row in self.health_system.cursor.fetchall()]
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
                    "SELECT id, patient_email, date_creation FROM dossiers_medicaux WHERE medecin_email = ?",
                    (self.health_system.current_user,)
                )
                dossiers = [{"id": row[0], "patient_email": row[1], "date_creation": row[2]} for row in self.health_system.cursor.fetchall()]
            else:
                dossiers = []
            filtered = [d for d in dossiers if search_text in d['id'].lower() or search_text in d['date_creation'].lower()]
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
                info = f"{patient['nom']} {patient['prenom']} (Email: {patient['patient_email']}) - Dossiers: {dossiers_str}"
                display_list.append({"id": patient['patient_email'], "info": info})
            self.display_results("Mes Patients", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_radiologue_dossiers(self):
        try:
            if self.health_system.current_role != 'radiologue':
                raise PermissionError("Cette fonctionnalité est réservée aux radiologues")
            dossiers = self.health_system.radiologue_get_dossiers()
            display_list = [{"id": d["id"], "info": f"Patient: {d['patient_email']} - Création: {d['date_creation']}"} for d in dossiers]
            self.display_results("Mes Dossiers Traités (Radiologue)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_laborantin_dossiers(self):
        try:
            if self.health_system.current_role != 'laborantin':
                raise PermissionError("Cette fonctionnalité est réservée aux laborantins")
            dossiers = self.health_system.laborantin_get_dossiers()
            display_list = [{"id": d["id"], "info": f"Patient: {d['patient_email']} - Création: {d['date_creation']}"} for d in dossiers]
            self.display_results("Mes Dossiers Traités (Laborantin)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def display_results(self, title, results):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.activity_log(f"Affichage: {title}")
        for idx, item in enumerate(results):
            info = item.get("contenu", item.get("info", f"Date: {item.get('date_creation', '')}"))
            tag = 'even' if idx % 2 == 0 else 'odd'
            self.tree.insert("", tk.END, values=(item.get("id", ""), info), tags=(tag,))

    def update_actions_visibility(self):
        self.medecin_frame.pack_forget()
        self.radiologue_frame.pack_forget()
        self.laborantin_frame.pack_forget()
        if self.health_system.current_role == "medecin":
            self.medecin_frame.pack(fill=tk.X, pady=5)
        elif self.health_system.current_role == "radiologue":
            self.radiologue_frame.pack(fill=tk.X, pady=5)
        elif self.health_system.current_role == "laborantin":
            self.laborantin_frame.pack(fill=tk.X, pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = ABEUI(root)
    root.mainloop()
