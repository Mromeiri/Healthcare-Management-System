#!/usr/bin/env python3
"""
Système de dossiers médicaux avec chiffrement ABE et accès basé sur les rôles, incluant une autorité centrale.
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
# Autorité centrale pour ABE
# --------------------------------------------
class CentralAuthority:
    def __init__(self):
        self.key_dir = "authority_keys"
        os.makedirs(self.key_dir, exist_ok=True)
        master_key_path = os.path.join(self.key_dir, "master_key.bin")
        
        # Charger la clé maître si elle existe, sinon la générer et la sauvegarder
        if os.path.exists(master_key_path):
            with open(master_key_path, "rb") as f:
                self.master_key = f.read()
        else:
            self.master_key = get_random_bytes(32)  # Générer une nouvelle clé maître
            with open(master_key_path, "wb") as f:
                f.write(self.master_key)
        
        # Gestion des clés RSA de l'autorité (inchangée)
        self.authority_public_key_path = os.path.join(self.key_dir, "authority_public.pem")
        self.authority_private_key_path = os.path.join(self.key_dir, "authority_private.pem")
        if not os.path.exists(self.authority_public_key_path):
            private_key, public_key = generate_rsa_keys()
            with open(self.authority_public_key_path, "wb") as f:
                f.write(public_key)
            with open(self.authority_private_key_path, "wb") as f:
                f.write(private_key)
        with open(self.authority_public_key_path, "rb") as f:
            self.authority_public_key = RSA.import_key(f.read())
        with open(self.authority_private_key_path, "rb") as f:
            self.authority_private_key = RSA.import_key(f.read())

    def derive_attribute_key(self, attributes):
        """Dérive une clé pour un ensemble d'attributs à partir de la clé maître."""
        attr_string = "".join(sorted(attributes))
        hash_obj = hashlib.sha256(self.master_key + attr_string.encode())
        return hash_obj.digest()[:16]  # Clé AES de 16 octets

    def generate_user_attribute_key(self, user_attributes):
        """Génère une clé chiffrée pour les attributs de l'utilisateur."""
        attr_key = self.derive_attribute_key(user_attributes)
        encrypted_attr_key = rsa_encrypt(self.authority_public_key, attr_key)
        return encrypted_attr_key

    def get_attribute_key(self, encrypted_attr_key):
        """Déchiffre la clé d'attributs avec la clé privée de l'autorité."""
        return rsa_decrypt(self.authority_private_key, encrypted_attr_key)

# --------------------------------------------
# Chiffrement ABE hybride avec autorité centrale
# --------------------------------------------
class ABEEncryption:
    def __init__(self, central_authority):
        self.central_authority = central_authority

    def encrypt(self, message, policy, rsa_public_key):
        """Chiffre un message avec une politique d'attributs."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        k1 = get_random_bytes(32)
        k2 = get_random_bytes(32)
        session_key = bytes(a ^ b for a, b in zip(k1, k2))
        nonce_msg = get_random_bytes(12)
        cipher_msg = AES.new(session_key, AES.MODE_GCM, nonce=nonce_msg)
        encrypted_message, tag_msg = cipher_msg.encrypt_and_digest(pad(message, AES.block_size))
        policy_key = self.central_authority.derive_attribute_key(policy)
        nonce_key = get_random_bytes(12)
        cipher_key = AES.new(policy_key, AES.MODE_GCM, nonce=nonce_key)
        encrypted_k1, tag_key = cipher_key.encrypt_and_digest(pad(k1, AES.block_size))
        rsa_encrypted_k2 = rsa_encrypt(rsa_public_key, k2)
        return {
            "schema": "Hybrid-ABE-AES-GCM-RSA",
            "nonce_msg": base64.b64encode(nonce_msg).decode('utf-8'),
            "tag_msg": base64.b64encode(tag_msg).decode('utf-8'),
            "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
            "nonce_key": base64.b64encode(nonce_key).decode('utf-8'),
            "tag_key": base64.b64encode(tag_key).decode('utf-8'),
            "encrypted_k1": base64.b64encode(encrypted_k1).decode('utf-8'),
            "rsa_encrypted_k2": base64.b64encode(rsa_encrypted_k2).decode('utf-8'),
            "policy": policy
        }

    def decrypt(self, encrypted_data, user_attributes, rsa_private_key, encrypted_attr_key):
        """Déchiffre un message si les attributs satisfont la politique."""
        try:
            nonce_key = base64.b64decode(encrypted_data["nonce_key"])
            tag_key = base64.b64decode(encrypted_data["tag_key"])
            encrypted_k1 = base64.b64decode(encrypted_data["encrypted_k1"])
            rsa_encrypted_k2 = base64.b64decode(encrypted_data["rsa_encrypted_k2"])
            nonce_msg = base64.b64decode(encrypted_data["nonce_msg"])
            tag_msg = base64.b64decode(encrypted_data["tag_msg"])
            encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
            policy = encrypted_data["policy"]
            if not any(attr in user_attributes for attr in policy):
                raise Exception("Les attributs ne satisfont pas la politique d'accès")
            policy_key = self.central_authority.derive_attribute_key(policy)
            cipher_key = AES.new(policy_key, AES.MODE_GCM, nonce=nonce_key)
            k1_padded = cipher_key.decrypt_and_verify(encrypted_k1, tag_key)
            k1 = unpad(k1_padded, AES.block_size)
            k2 = rsa_decrypt(rsa_private_key, rsa_encrypted_k2)
            session_key = bytes(a ^ b for a, b in zip(k1, k2))
            cipher_msg = AES.new(session_key, AES.MODE_GCM, nonce=nonce_msg)
            padded_message = cipher_msg.decrypt_and_verify(encrypted_message, tag_msg)
            return unpad(padded_message, AES.block_size).decode('utf-8')
        except Exception as e:
            raise Exception(f"Erreur lors du déchiffrement ABE : {str(e)}")

# --------------------------------------------
# Système de gestion des dossiers médicaux
# --------------------------------------------
class HealthRecordSystem:
    def __init__(self, db_name="health_records.db", activity_log_callback=None):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.initialize_database()
        self.current_user = None
        self.current_role = None
        self.current_attributes = []
        self.rsa_keys = {}
        self.key_dir = "keys"
        os.makedirs(self.key_dir, exist_ok=True)
        self.central_authority = CentralAuthority()
        self.abe = ABEEncryption(self.central_authority)
        self.activity_log = activity_log_callback if activity_log_callback else lambda msg: None
        self.user_attribute_keys = {}  # Stockage des clés d'attributs par utilisateur

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
    rsa_private_key_path TEXT NOT NULL,
    attributes TEXT NOT NULL,
    encrypted_attribute_key TEXT NOT NULL
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
        pattern = r"[^@]+@[^@]+\.[^@]+"
        return re.match(pattern, email)

    def is_valid_phone(self, phone):
        return phone.isdigit()

    def encrypt_private_key(self, private_key, password):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted_priv, tag = cipher.encrypt_and_digest(private_key)
        return {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "encrypted_priv": base64.b64encode(encrypted_priv).decode('utf-8')
        }

    def decrypt_private_key(self, encrypted_data, password):
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        encrypted_priv = base64.b64decode(encrypted_data["encrypted_priv"])
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(encrypted_priv, tag)

    def register_user(self, email, nom, prenom, role, password, adresse, date_naissance, attributes, telephone=None, genre=None, groupe_sanguin=None):
        if not self.is_valid_email(email):
            raise ValueError("Email invalide")
        if role not in ['medecin', 'laborantin', 'patient', 'radiologue']:
            raise ValueError("Rôle invalide")
        self.cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        if self.cursor.fetchone():
            raise ValueError("L'utilisateur existe déjà")
        password_hash = self.hash_password(password)
        user_key_dir = os.path.join(self.key_dir, email)
        os.makedirs(user_key_dir, exist_ok=True)
        rsa_private_key, rsa_public_key = generate_rsa_keys()
        rsa_public_key_path = os.path.join(user_key_dir, "rsa_public.pem")
        rsa_private_key_path = os.path.join(user_key_dir, "rsa_private.json")
        with open(rsa_public_key_path, "wb") as f:
            f.write(rsa_public_key)
        encrypted_priv_data = self.encrypt_private_key(rsa_private_key, password)
        with open(rsa_private_key_path, "w") as f:
            json.dump(encrypted_priv_data, f)
        attributes_list = [attr.strip() for attr in attributes.split(",") if attr.strip()]
        if role not in attributes_list:
            attributes_list.insert(0, role)
        if role == "patient":
            for attr in ["consultation", "dossier", "notes_medicales"]:
                if attr not in attributes_list:
                    attributes_list.append(attr)
        attributes_str = ",".join(attributes_list)
        encrypted_attr_key = base64.b64encode(self.central_authority.generate_user_attribute_key(attributes_list)).decode('utf-8')
        self.cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (email, nom, prenom, role, password_hash, adresse, date_naissance, telephone, genre, groupe_sanguin, rsa_public_key_path, rsa_private_key_path, attributes_str, encrypted_attr_key)
        )
        self.conn.commit()
        self.log(f"Utilisateur inscrit : {email} ({role}) avec attributs : {attributes_str}")
        return email

    def login(self, email, password):
        self.cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = self.cursor.fetchone()
        if not user or not self.verify_password(user[4], password):
            self.log(f"Échec de connexion pour {email}")
            return False
        email, _, _, role, _, _, _, _, _, _, rsa_public_key_path, rsa_private_key_path, attributes_str, encrypted_attr_key = user
        with open(rsa_public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        with open(rsa_private_key_path, "r") as f:
            encrypted_priv_data = json.load(f)
        rsa_private_key_bytes = self.decrypt_private_key(encrypted_priv_data, password)
        private_key = RSA.import_key(rsa_private_key_bytes)
        self.rsa_keys[email] = {"public": public_key, "private": private_key}
        self.current_user, self.current_role = email, role
        self.current_attributes = [attr.strip() for attr in attributes_str.split(",")]
        self.user_attribute_keys[email] = base64.b64decode(encrypted_attr_key)
        self.log(f"Connexion réussie : {email} ({role}) avec attributs : {attributes_str}")
        return True

    def logout(self):
        self.log(f"Déconnexion de l'utilisateur {self.current_user}")
        self.current_user = None
        self.current_role = None
        self.current_attributes = []
        self.rsa_keys = {}
        self.user_attribute_keys = {}

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
        self.cursor.execute("SELECT email, nom, prenom, role, adresse, date_naissance, telephone, genre, groupe_sanguin, attributes FROM users WHERE email = ?", (self.current_user,))
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
            raise PermissionError("Seuls les médecins peuvent créer des dossiers")
        self.cursor.execute("SELECT email FROM users WHERE email = ? AND role = 'patient'", (patient_email,))
        if not self.cursor.fetchone():
            raise ValueError("Patient non trouvé")
        
        # Vérifier si un dossier existe déjà pour ce patient avec ce médecin
        self.cursor.execute(
            "SELECT id FROM dossiers_medicaux WHERE patient_email = ? AND medecin_email = ?",
            (patient_email, self.current_user)
        )
        existing_dossier = self.cursor.fetchone()
        if existing_dossier:
            raise ValueError(f"Un dossier existe déjà pour ce patient avec vous : ID {existing_dossier[0]}")
        
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
            raise PermissionError("Seuls les médecins peuvent ajouter des notes")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            raise PermissionError("Accès refusé au dossier")
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
        policy = ["medecin", "patient", "consultation", "dossier", "notes_medicales"]
        encrypted_data_patient = self.abe.encrypt(note_content, policy, self.rsa_keys[patient_email]["public"])
        encrypted_data_medecin = self.abe.encrypt(note_content, policy, self.rsa_keys[medecin_email]["public"])
        note_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO notes_medicales VALUES (?, ?, ?, ?)",
            (note_id, dossier_id, datetime.now().isoformat(), json.dumps({"patient": encrypted_data_patient, "medecin": encrypted_data_medecin}))
        )
        self.conn.commit()
        self.log(f"Note ajoutée par {self.current_user} dans dossier {dossier_id}")
        return True

    def radiologue_add_imaging(self, dossier_id, result_content):
        if self.current_role != 'radiologue':
            raise PermissionError("Seuls les radiologues peuvent ajouter des résultats d'imagerie")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
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
        if self.current_user not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (self.current_user,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[self.current_user] = {"public": RSA.import_key(f.read())}
        policy = ["radiologue", "medecin", "patient", "consultation", "dossier"]
        encrypted_data_patient = self.abe.encrypt(result_content, policy, self.rsa_keys[patient_email]["public"])
        encrypted_data_medecin = self.abe.encrypt(result_content, policy, self.rsa_keys[medecin_email]["public"])
        encrypted_data_radiologue = self.abe.encrypt(result_content, policy, self.rsa_keys[self.current_user]["public"])
        result_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO resultats_imagerie VALUES (?, ?, ?, ?, ?)",
            (result_id, dossier_id, datetime.now().isoformat(), json.dumps({
                "patient": encrypted_data_patient,
                "medecin": encrypted_data_medecin,
                "radiologue": encrypted_data_radiologue
            }), self.current_user)
        )
        self.conn.commit()
        self.log(f"Résultat imagerie ajouté par {self.current_user} dans dossier {dossier_id}")
        return True

    def laborantin_add_lab(self, dossier_id, result_content):
        if self.current_role != 'laborantin':
            raise PermissionError("Seuls les laborantins peuvent ajouter des résultats d'analyses")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier:
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
        if self.current_user not in self.rsa_keys:
            self.cursor.execute("SELECT rsa_public_key_path FROM users WHERE email = ?", (self.current_user,))
            path = self.cursor.fetchone()[0]
            with open(path, "rb") as f:
                self.rsa_keys[self.current_user] = {"public": RSA.import_key(f.read())}
        policy = ["laborantin", "medecin", "patient", "consultation", "dossier"]
        encrypted_data_patient = self.abe.encrypt(result_content, policy, self.rsa_keys[patient_email]["public"])
        encrypted_data_medecin = self.abe.encrypt(result_content, policy, self.rsa_keys[medecin_email]["public"])
        encrypted_data_laborantin = self.abe.encrypt(result_content, policy, self.rsa_keys[self.current_user]["public"])
        result_id = str(uuid.uuid4())
        self.cursor.execute(
            "INSERT INTO resultats_analyses VALUES (?, ?, ?, ?, ?)",
            (result_id, dossier_id, datetime.now().isoformat(), json.dumps({
                "patient": encrypted_data_patient,
                "medecin": encrypted_data_medecin,
                "laborantin": encrypted_data_laborantin
            }), self.current_user)
        )
        self.conn.commit()
        self.log(f"Résultat analyse ajouté par {self.current_user} dans dossier {dossier_id}")
        return True

    def medecin_get_all_notes(self, dossier_id):
        if self.current_role != 'medecin':
            raise PermissionError("Seuls les médecins peuvent voir toutes les notes")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le médecin référent")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM notes_medicales WHERE dossier_id = ?", (dossier_id,))
        for note_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("medecin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": note_id, "date": date, "type": "Note médicale", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note médicale {note_id} pour médecin: {str(e)}")
                continue
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("medecin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat imagerie", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour médecin: {str(e)}")
                continue
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("medecin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat analyse", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour médecin: {str(e)}")
                continue
        return result

    def patient_get_all_notes(self, dossier_id):
        if self.current_role != 'patient':
            raise PermissionError("Seuls les patients peuvent voir toutes les notes")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le patient concerné")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM notes_medicales WHERE dossier_id = ?", (dossier_id,))
        for note_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("patient")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": note_id, "date": date, "type": "Note médicale", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement note médicale {note_id} pour patient: {str(e)}")
                continue
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("patient")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat imagerie", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour patient: {str(e)}")
                continue
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("patient")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat analyse", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour patient: {str(e)}")
                continue
        return result

    def medecin_get_imaging(self, dossier_id):
        if self.current_role != 'medecin':
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le médecin référent")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("medecin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat imagerie", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour médecin: {str(e)}")
                continue
        return result

    def medecin_get_lab(self, dossier_id):
        if self.current_role != 'medecin':
            raise PermissionError("Seuls les médecins peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[1] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le médecin référent")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("medecin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat analyse", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour médecin: {str(e)}")
                continue
        return result

    def patient_get_imaging(self, dossier_id):
        if self.current_role != 'patient':
            raise PermissionError("Seuls les patients peuvent voir les résultats d'imagerie")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le patient concerné")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_imagerie WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("patient")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat imagerie", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour patient: {str(e)}")
                continue
        return result

    def patient_get_lab(self, dossier_id):
        if self.current_role != 'patient':
            raise PermissionError("Seuls les patients peuvent voir les résultats d'analyses")
        self.cursor.execute("SELECT patient_email, medecin_email FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
        dossier = self.cursor.fetchone()
        if not dossier or dossier[0] != self.current_user:
            raise PermissionError("Accès refusé au dossier : vous n'êtes pas le patient concerné")
        result = []
        self.cursor.execute("SELECT id, date, encrypted_data FROM resultats_analyses WHERE dossier_id = ?", (dossier_id,))
        for res_id, date, enc_data in self.cursor.fetchall():
            try:
                data = json.loads(enc_data)
                encrypted_data = data.get("patient")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat analyse", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour patient: {str(e)}")
                continue
        return result

    def radiologue_get_imaging(self, dossier_id):
        if self.current_role != 'radiologue':
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
                encrypted_data = data.get("radiologue")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat imagerie", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement imagerie {res_id} pour radiologue: {str(e)}")
                continue
        return result

    def laborantin_get_lab(self, dossier_id):
        if self.current_role != 'laborantin':
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
                encrypted_data = data.get("laborantin")
                contenu = self.abe.decrypt(encrypted_data, self.current_attributes, self.rsa_keys[self.current_user]["private"], self.user_attribute_keys[self.current_user])
                result.append({"id": res_id, "date": date, "type": "Résultat analyse", "contenu": contenu})
            except Exception as e:
                self.log(f"Erreur déchiffrement analyse {res_id} pour laborantin: {str(e)}")
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
            raise PermissionError("Seuls les patients peuvent voir leurs dossiers")
        self.cursor.execute("SELECT id, patient_email, date_creation FROM dossiers_medicaux WHERE patient_email = ?", (self.current_user,))
        return [{"id": row[0], "patient_email": row[1], "date_creation": row[2]} for row in self.cursor.fetchall()]

    def close(self):
        self.conn.close()

# --------------------------------------------
# Interface graphique (Tkinter)
# --------------------------------------------
class ABEUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Système Dossiers Médicaux avec ABE")
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
        self.attributes = tk.StringVar()
        self.patient_email = tk.StringVar()
        self.dossier_id = tk.StringVar()

        self.health_system = HealthRecordSystem(activity_log_callback=self.activity_log)
        self.theme_mode = "clair"
        
        self.setup_ui()
        self.apply_theme()

    def activity_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

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

        # Create a container frame for login and register sections
        auth_container = ttk.Frame(self.login_tab)
        auth_container.pack(fill=tk.BOTH, expand=True)
        
        # Login section
        login_frame = ttk.LabelFrame(auth_container, text="Connexion", padding=10)
        login_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=10)
        
        self.login_email = tk.StringVar()
        ttk.Label(login_frame, text="Email:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(login_frame, textvariable=self.login_email, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        self.login_password = tk.StringVar()
        ttk.Label(login_frame, text="Mot de passe:").grid(row=1, column=0, sticky="w", pady=5)
        login_pass_entry = ttk.Entry(login_frame, textvariable=self.login_password, show="*", width=30)
        login_pass_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(login_frame, text="Se connecter", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Register section
        register_frame = ttk.LabelFrame(auth_container, text="Inscription", padding=10)
        register_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=10)
        
        ttk.Label(register_frame, text="Email:").grid(row=0, column=0, sticky="w", pady=5)
        self.email_entry = ttk.Entry(register_frame, textvariable=self.email, width=50)
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Nom:").grid(row=1, column=0, sticky="w", pady=5)
        self.nom_entry = ttk.Entry(register_frame, textvariable=self.nom, width=50)
        self.nom_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Prénom:").grid(row=2, column=0, sticky="w", pady=5)
        self.prenom_entry = ttk.Entry(register_frame, textvariable=self.prenom, width=50)
        self.prenom_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Rôle:").grid(row=3, column=0, sticky="w", pady=5)
        self.role_combobox = ttk.Combobox(register_frame, textvariable=self.role, values=["medecin", "laborantin", "patient", "radiologue"])
        self.role_combobox.grid(row=3, column=1, padx=5, pady=5)
        self.role_combobox.bind("<<ComboboxSelected>>", self.update_inscription_fields)
        
        ttk.Label(register_frame, text="Attributs (séparés par des virgules):").grid(row=4, column=0, sticky="w", pady=5)
        self.attributes_entry = ttk.Entry(register_frame, textvariable=self.attributes, width=50)
        self.attributes_entry.grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Adresse:").grid(row=5, column=0, sticky="w", pady=5)
        self.adresse_entry = ttk.Entry(register_frame, textvariable=self.adresse, width=50)
        self.adresse_entry.grid(row=5, column=1, padx=5, pady=5)
        
        ttk.Label(register_frame, text="Date de naissance (YYYY-MM-DD):").grid(row=6, column=0, sticky="w", pady=5)
        self.date_naissance_entry = ttk.Entry(register_frame, textvariable=self.date_naissance, width=50)
        self.date_naissance_entry.grid(row=6, column=1, padx=5, pady=5)
        
        self.telephone_label = ttk.Label(register_frame, text="Téléphone:")
        self.telephone_entry = ttk.Entry(register_frame, textvariable=self.telephone, width=50)
        self.telephone_label.grid(row=7, column=0, sticky="w", pady=5)
        self.telephone_entry.grid(row=7, column=1, padx=5, pady=5)
        
        self.genre_label = ttk.Label(register_frame, text="Genre (M/F):")
        self.genre_entry = ttk.Entry(register_frame, textvariable=self.genre, width=50)
        self.groupe_sanguin_label = ttk.Label(register_frame, text="Groupe sanguin (A/B/AB/O):")
        self.groupe_sanguin_entry = ttk.Entry(register_frame, textvariable=self.groupe_sanguin, width=50)
        
        self.register_password = tk.StringVar()
        ttk.Label(register_frame, text="Mot de passe:").grid(row=10, column=0, sticky="w", pady=5)
        self.register_pass_entry = ttk.Entry(register_frame, textvariable=self.register_password, show="*", width=50)
        self.register_pass_entry.grid(row=10, column=1, padx=5, pady=5)
        
        ttk.Button(register_frame, text="S'inscrire", command=self.register_user).grid(row=11, column=0, columnspan=2, pady=10)
        
        # Log frame for both sections
        self.log_frame = ttk.LabelFrame(self.login_tab, text="Journal d'activité")
        self.log_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)

        # Keep all the original health_tab and profil_tab code EXACTLY as it was
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
        ttk.Button(self.medecin_frame, text="Voir Imagerie", command=self.view_imaging).pack(pady=5)
        ttk.Button(self.medecin_frame, text="Voir Analyses", command=self.view_lab).pack(pady=5)

        self.radiologue_frame = ttk.LabelFrame(self.actions_frame, text="Actions Radiologue")
        ttk.Label(self.radiologue_frame, text="Résultat Imagerie:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.imaging_text = scrolledtext.ScrolledText(self.radiologue_frame, height=5, width=40)
        self.imaging_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.radiologue_frame, text="Ajouter Imagerie", command=self.add_imaging).pack(pady=5)
        ttk.Button(self.radiologue_frame, text="Voir Mes Dossiers Traités", command=self.view_radiologue_dossiers).pack(pady=5)
        ttk.Button(self.radiologue_frame, text="Voir Mes Imagerie", command=self.view_radiologue_imaging).pack(pady=5)

        self.laborantin_frame = ttk.LabelFrame(self.actions_frame, text="Actions Laborantin")
        ttk.Label(self.laborantin_frame, text="Résultat Analyse:").pack(side=tk.TOP, anchor="w", padx=5, pady=5)
        self.lab_text = scrolledtext.ScrolledText(self.laborantin_frame, height=5, width=40)
        self.lab_text.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(self.laborantin_frame, text="Ajouter Analyse", command=self.add_lab).pack(pady=5)
        ttk.Button(self.laborantin_frame, text="Voir Mes Dossiers Traités", command=self.view_laborantin_dossiers).pack(pady=5)
        ttk.Button(self.laborantin_frame, text="Voir Mes Analyses", command=self.view_laborantin_lab).pack(pady=5)

        self.patient_frame = ttk.LabelFrame(self.actions_frame, text="Actions Patient")
        ttk.Button(self.patient_frame, text="Voir Imagerie", command=self.view_imaging).pack(pady=5)
        ttk.Button(self.patient_frame, text="Voir Analyses", command=self.view_lab).pack(pady=5)

        self.common_frame = ttk.Frame(self.actions_frame)
        self.common_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.common_frame, text="ID Dossier:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Entry(self.common_frame, textvariable=self.dossier_id, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        btn_frame = ttk.Frame(self.common_frame)
        btn_frame.pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(btn_frame, text="Voir Toutes Notes", command=self.view_all_notes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Voir Mes Dossiers", command=self.view_dossiers).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Se Déconnecter", command=self.logout).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Supprimer Compte", command=self.delete_account).pack(side=tk.LEFT, padx=2)

        self.result_frame = ttk.LabelFrame(self.health_tab, text="Résultats")
        self.result_frame.place(relx=0, rely=1, anchor="sw", relwidth=1)
        tree_container = ttk.Frame(self.result_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree = ttk.Treeview(tree_container, columns=("id", "type", "info"), show="headings")
        self.tree.heading("id", text="ID")
        self.tree.heading("type", text="Type")
        self.tree.heading("info", text="Informations")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        h_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        h_scroll.pack(side=tk.BOTTOM, fill="x")
        self.tree.configure(xscrollcommand=h_scroll.set)
        self.tree.bind("<Double-1>", self.on_treeview_double_click)

        profil_frame = ttk.Frame(self.profil_tab, padding=10)
        profil_frame.pack(fill=tk.BOTH, expand=True)
        self.profil_text = scrolledtext.ScrolledText(profil_frame, height=10, wrap=tk.WORD)
        self.profil_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.profil_text.config(state=tk.DISABLED)
        ttk.Button(profil_frame, text="Afficher Profil", command=self.display_profile).pack(pady=10)
    
    def update_inscription_fields(self, event=None):
        role = self.role.get()
        self.telephone_label.grid(row=7, column=0, sticky="w", pady=5)
        self.telephone_entry.grid(row=7, column=1, padx=5, pady=5)
        if role == "patient":
            self.genre_label.grid(row=8, column=0, sticky="w", pady=5)
            self.genre_entry.grid(row=8, column=1, padx=5, pady=5)
            self.groupe_sanguin_label.grid(row=9, column=0, sticky="w", pady=5)
            self.groupe_sanguin_entry.grid(row=9, column=1, padx=5, pady=5)
        else:
            self.genre_label.grid_forget()
            self.genre_entry.grid_forget()
            self.groupe_sanguin_label.grid_forget()
            self.groupe_sanguin_entry.grid_forget()

    def display_dossier_popup(self, dossier_id):
        popup = tk.Toplevel(self.root)
        popup.title("Détails du Dossier")
        popup.geometry("600x400")
        info_text = scrolledtext.ScrolledText(popup, width=80, height=20)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        try:
            self.health_system.cursor.execute("SELECT * FROM dossiers_medicaux WHERE id = ?", (dossier_id,))
            dossier = self.health_system.cursor.fetchone()
            if dossier:
                id_dossier, patient_email, medecin_email, date_creation = dossier
                details = f"Dossier ID : {id_dossier}\nDate de création : {date_creation}\n"
                if self.health_system.current_role == "medecin":
                    self.health_system.cursor.execute("SELECT nom, prenom, genre, groupe_sanguin, telephone, adresse FROM users WHERE email = ?", (patient_email,))
                    patient = self.health_system.cursor.fetchone()
                    if patient:
                        nom, prenom, genre, groupe_sanguin, telephone, adresse = patient
                        details += f"\n--- Informations Patient ---\nEmail : {patient_email}\nNom : {nom}\nPrénom : {prenom}\nGenre : {genre}\nGroupe sanguin : {groupe_sanguin}\nTéléphone : {telephone}\nAdresse : {adresse}\n"
                elif self.health_system.current_role == "patient":
                    details += "\nCeci est votre dossier patient.\n"
                else:
                    details += f"\nPatient : {patient_email}\nMédecin : {medecin_email}\n"
                try:
                    if self.health_system.current_role in ["medecin", "patient"]:
                        notes = (self.health_system.medecin_get_all_notes(dossier_id) if self.health_system.current_role == "medecin"
                                 else self.health_system.patient_get_all_notes(dossier_id))
                        if notes:
                            details += "\n--- Toutes les Notes ---\n"
                            for note in notes:
                                note_type = note.get("type", "Type inconnu")
                                note_date = note.get("date", "Date inconnue")
                                note_contenu = note.get("contenu", "Contenu indisponible")
                                details += f"Type : {note_type}\nDate : {note_date}\nContenu : {note_contenu}\n\n"
                        else:
                            details += "\nAucune note disponible.\n"
                    else:
                        details += "\nVous n'avez pas les permissions pour voir les notes de ce dossier.\n"
                except Exception as e:
                    details += f"\nErreur lors de la récupération des notes : {str(e)}\n"
                info_text.insert(tk.END, details)
            else:
                info_text.insert(tk.END, "Dossier introuvable.")
        except Exception as e:
            info_text.insert(tk.END, f"Erreur : {str(e)}")
        info_text.config(state=tk.DISABLED)

    def on_treeview_double_click(self, event):
        selected_item = self.tree.focus()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            if values and values[0]:
                dossier_id = values[0]
                self.display_dossier_popup(dossier_id)

    def toggle_theme(self):
        themes = ["light", "dark", "ocean", "sunset", "minimal"]
        current_index = themes.index(self.theme_mode) if self.theme_mode in themes else 0
        next_index = (current_index + 1) % len(themes)
        self.theme_mode = themes[next_index]
        self.apply_theme()
        self.theme_button.config(text=f"Theme: {self.theme_mode.capitalize()}")

    def apply_theme(self):
        style = ttk.Style()
        
        # Define font settings
        fonts = {
            "heading": ("Segoe UI", 12, "bold"),
            "subheading": ("Segoe UI", 11, "normal"),
            "body": ("Segoe UI", 10, "normal"),
            "button": ("Segoe UI", 10, "normal"),
            "small": ("Segoe UI", 9, "normal")
        }
        
        # Define theme color palettes with modern colors
        themes = {
            "light": {
                "bg": "#ffffff",
                "fg": "#333333",
                "accent": "#4285f4",  # Google Blue
                "secondary": "#f5f5f5",
                "highlight": "#34a853",  # Google Green
                "button_bg": "#4285f4",
                "button_fg": "white",
                "entry_bg": "#ffffff",
                "even_row": "#ffffff",
                "odd_row": "#f8f9fa"
            },
            "dark": {
                "bg": "#121212",  # Material Dark background
                "fg": "#e0e0e0",
                "accent": "#bb86fc",  # Material Purple
                "secondary": "#1e1e1e",
                "highlight": "#03dac6",  # Material Teal
                "button_bg": "#bb86fc",
                "button_fg": "#121212",
                "entry_bg": "#1e1e1e",
                "even_row": "#1e1e1e",
                "odd_row": "#2d2d2d"
            },
            "ocean": {
                "bg": "#011627",  # Night Owl theme inspired
                "fg": "#d6deeb",
                "accent": "#82aaff",
                "secondary": "#0b2942",
                "highlight": "#21c7a8",
                "button_bg": "#82aaff",
                "button_fg": "#011627",
                "entry_bg": "#0b2942",
                "even_row": "#0b2942",
                "odd_row": "#011627"
            },
            "sunset": {
                "bg": "#2d142c",
                "fg": "#ffefd3",
                "accent": "#ee4540",
                "secondary": "#45142c",
                "highlight": "#f9b208",
                "button_bg": "#ee4540",
                "button_fg": "#ffefd3",
                "entry_bg": "#45142c",
                "even_row": "#45142c",
                "odd_row": "#2d142c"
            },
            "minimal": {
                "bg": "#fafafa",
                "fg": "#424242",
                "accent": "#212121",
                "secondary": "#f0f0f0",
                "highlight": "#757575",
                "button_bg": "#212121",
                "button_fg": "#fafafa",
                "entry_bg": "#ffffff",
                "even_row": "#ffffff",
                "odd_row": "#f5f5f5"
            }
        }
        
        colors = themes.get(self.theme_mode, themes["light"])
        
        # Apply the selected theme
        self.root.configure(bg=colors["bg"])
        
        # Choose appropriate base theme
        if self.theme_mode in ["dark", "ocean", "sunset"]:
            style.theme_use('clam')
        else:
            style.theme_use('default')
        
        # Configure styles with color palette and improved fonts
        style.configure("TFrame", background=colors["bg"])
        
        # Label styles with different font sizes
        style.configure("TLabel", 
                    background=colors["bg"], 
                    foreground=colors["fg"],
                    font=fonts["body"])
        
        style.configure("Heading.TLabel", 
                    background=colors["bg"], 
                    foreground=colors["fg"],
                    font=fonts["heading"])
        
        style.configure("Subheading.TLabel", 
                    background=colors["bg"], 
                    foreground=colors["fg"],
                    font=fonts["subheading"])
        
        # Modern button styling with improved font
        style.configure("TButton", 
                    background=colors["button_bg"], 
                    foreground=colors["button_fg"], 
                    font=fonts["button"],
                    borderwidth=0,
                    padding=8)  # Increased padding for better touch targets
        
        style.map("TButton",
                background=[("active", colors["highlight"]), ("pressed", colors["secondary"])],
                relief=[("pressed", "flat")])
        
        # Input fields styling
        style.configure("TEntry", 
                    fieldbackground=colors["entry_bg"], 
                    foreground=colors["fg"],
                    bordercolor=colors["accent"],
                    lightcolor=colors["bg"],
                    darkcolor=colors["bg"],
                    font=fonts["body"])
        
        style.configure("TCombobox", 
                    fieldbackground=colors["entry_bg"], 
                    foreground=colors["fg"],
                    arrowcolor=colors["accent"],
                    font=fonts["body"])
        
        style.map("TCombobox",
                fieldbackground=[("readonly", colors["entry_bg"])],
                selectbackground=[("readonly", colors["accent"])],
                selectforeground=[("readonly", colors["button_fg"])])
        
        # Text widgets with improved font sizes
        self.log_text.config(
            bg=colors["entry_bg"], 
            fg=colors["fg"], 
            insertbackground=colors["accent"],
            font=fonts["body"]
        )
        
        self.profil_text.config(
            bg=colors["entry_bg"], 
            fg=colors["fg"], 
            insertbackground=colors["accent"],
            font=fonts["body"]
        )
        
        # Treeview with improved fonts
        style.configure("Treeview", 
                    background=colors["bg"],
                    foreground=colors["fg"],
                    fieldbackground=colors["bg"],
                    font=fonts["body"])
        
        style.configure("Treeview.Heading", 
                    font=fonts["subheading"])
        
        style.map("Treeview",
                background=[("selected", colors["accent"])],
                foreground=[("selected", colors["button_fg"])])
        
        self.tree.tag_configure('even', background=colors["even_row"])
        self.tree.tag_configure('odd', background=colors["odd_row"])
        
        # Add modern card styling for frames
        style.configure("Card.TFrame", 
                    background=colors["secondary"], 
                    relief="flat",
                    borderwidth=0,
                    padding=10)  # Added padding for better spacing
    # Add this method to initialize the theme system
    def setup_theme_system(self):
        # Add theme selector with modern styling
        self.theme_mode = "light"  # Default theme
        
        theme_frame = ttk.Frame(self.root)
        theme_frame.pack(fill="x", padx=10, pady=(10, 0))
        
        self.theme_button = ttk.Button(
            theme_frame, 
            text="Theme: Light",
            command=self.toggle_theme,
            style="Accent.TButton"
        )
        self.theme_button.pack(side="right")
        
        # Set up custom button style
        style = ttk.Style()
        style.configure("Accent.TButton", 
                    font=("Segoe UI", 9, "bold"))
        
        # Apply the initial theme
        self.apply_theme()
    def register_user(self):
        role = self.role.get()
        if not (self.email.get() and self.nom.get() and self.prenom.get() and role and 
                self.adresse.get() and self.date_naissance.get() and self.register_password.get() and 
                self.telephone.get() and self.attributes.get()):
            messagebox.showerror("Erreur", "Tous les champs obligatoires doivent être remplis (y compris les attributs)")
            return

        email_input = self.email.get().strip()
        if not self.health_system.is_valid_email(email_input):
            messagebox.showerror("Erreur", "L'email fourni n'est pas valide.")
            return

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
                email_input,
                self.nom.get(),
                self.prenom.get(),
                role,
                self.register_password.get(),  # Use the new password field
                self.adresse.get(),
                self.date_naissance.get(),
                self.attributes.get(),
                telephone,
                genre,
                groupe_sanguin
            )
            messagebox.showinfo("Succès", f"Utilisateur inscrit avec l'email {email_input}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def login(self):
        if not (self.login_email.get() and self.login_password.get()):  # Use the new login fields
            messagebox.showerror("Erreur", "Email et mot de passe requis")
            return

        if self.health_system.login(self.login_email.get(), self.login_password.get()):
            messagebox.showinfo("Succès", f"Connecté en tant que {self.health_system.current_role}")
            self.update_actions_visibility()
            self.display_profile()
            
            # Switch to the health_tab
            self.notebook.select(self.health_tab)
        else:
            messagebox.showerror("Erreur", "Email ou mot de passe incorrect")

    
    def logout(self):
        self.health_system.logout()
        self.email.set("")
        self.login_email.set("")
        self.nom.set("")
        self.prenom.set("")
        self.role.set("")
        self.adresse.set("")
        self.date_naissance.set("")
        self.telephone.set("")
        self.genre.set("")
        self.groupe_sanguin.set("")
        self.attributes.set("")
        self.patient_email.set("")
        self.dossier_id.set("")
        self.login_password.set("")
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
        self.notebook.select(self.login_tab)

    def delete_account(self):
        if messagebox.askyesno("Confirmation", "Êtes-vous sûr de vouloir supprimer votre compte ainsi que toutes les informations associées ? Cette action est irréversible."):
            try:
                self.health_system.delete_account()
                self.logout()
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
                email, nom, prenom, role, adresse, date_naissance, telephone, genre, groupe_sanguin, attributes = profile
                dossier_count = self.health_system.get_dossier_count()
                profile_info = f"Email: {email}\nNom: {nom}\nPrénom: {prenom}\nRôle: {role}\nAdresse: {adresse}\nDate de naissance: {date_naissance}\n"
                profile_info += f"Téléphone: {telephone}\nAttributs: {attributes}\n"
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

    def view_all_notes(self):
        if not self.dossier_id.get():
            messagebox.showerror("Erreur", "Veuillez entrer un ID de dossier")
            return
        try:
            if self.health_system.current_role == 'medecin':
                notes = self.health_system.medecin_get_all_notes(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                notes = self.health_system.patient_get_all_notes(self.dossier_id.get())
            else:
                raise PermissionError("Seuls les médecins et patients peuvent voir toutes les notes")
            if not notes:
                messagebox.showinfo("Information", "Aucune note disponible pour ce dossier.")
                self.display_results("Toutes les Notes", [])
            else:
                display_list = [
                    {"id": note["id"], "type": note["type"], "info": f"{note['date']} - {note['contenu'][:50]}..."}
                    for note in notes
                ]
                self.display_results("Toutes les Notes", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des notes : {str(e)}")

    def view_imaging(self):
        if not self.dossier_id.get():
            messagebox.showerror("Erreur", "Veuillez entrer un ID de dossier")
            return
        try:
            if self.health_system.current_role == 'medecin':
                results = self.health_system.medecin_get_imaging(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                results = self.health_system.patient_get_imaging(self.dossier_id.get())
            else:
                raise PermissionError("Seuls les médecins et patients peuvent voir les résultats d'imagerie")
            if not results:
                messagebox.showinfo("Information", "Aucun résultat d'imagerie disponible pour ce dossier.")
                self.display_results("Résultats d'Imagerie", [])
            else:
                display_list = [
                    {"id": res["id"], "type": res["type"], "info": f"{res['date']} - {res['contenu'][:50]}..."}
                    for res in results
                ]
                self.display_results("Résultats d'Imagerie", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des résultats d'imagerie : {str(e)}")

    def view_lab(self):
        if not self.dossier_id.get():
            messagebox.showerror("Erreur", "Veuillez entrer un ID de dossier")
            return
        try:
            if self.health_system.current_role == 'medecin':
                results = self.health_system.medecin_get_lab(self.dossier_id.get())
            elif self.health_system.current_role == 'patient':
                results = self.health_system.patient_get_lab(self.dossier_id.get())
            else:
                raise PermissionError("Seuls les médecins et patients peuvent voir les résultats d'analyses")
            if not results:
                messagebox.showinfo("Information", "Aucun résultat d'analyse disponible pour ce dossier.")
                self.display_results("Résultats d'Analyses", [])
            else:
                display_list = [
                    {"id": res["id"], "type": res["type"], "info": f"{res['date']} - {res['contenu'][:50]}..."}
                    for res in results
                ]
                self.display_results("Résultats d'Analyses", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des résultats d'analyses : {str(e)}")

    def view_radiologue_imaging(self):
        if not self.dossier_id.get():
            messagebox.showerror("Erreur", "Veuillez entrer un ID de dossier")
            return
        try:
            if self.health_system.current_role != 'radiologue':
                raise PermissionError("Seuls les radiologues peuvent voir leurs propres résultats d'imagerie")
            results = self.health_system.radiologue_get_imaging(self.dossier_id.get())
            if not results:
                messagebox.showinfo("Information", "Aucun résultat d'imagerie disponible pour ce dossier.")
                self.display_results("Mes Résultats d'Imagerie", [])
            else:
                display_list = [
                    {"id": res["id"], "type": res["type"], "info": f"{res['date']} - {res['contenu'][:50]}..."}
                    for res in results
                ]
                self.display_results("Mes Résultats d'Imagerie", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des résultats : {str(e)}")

    def view_laborantin_lab(self):
        if not self.dossier_id.get():
            messagebox.showerror("Erreur", "Veuillez entrer un ID de dossier")
            return
        try:
            if self.health_system.current_role != 'laborantin':
                raise PermissionError("Seuls les laborantins peuvent voir leurs propres résultats d'analyses")
            results = self.health_system.laborantin_get_lab(self.dossier_id.get())
            if not results:
                messagebox.showinfo("Information", "Aucun résultat d'analyse disponible pour ce dossier.")
                self.display_results("Mes Résultats d'Analyses", [])
            else:
                display_list = [
                    {"id": res["id"], "type": res["type"], "info": f"{res['date']} - {res['contenu'][:50]}..."}
                    for res in results
                ]
                self.display_results("Mes Résultats d'Analyses", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des résultats : {str(e)}")

    def view_patients(self):
        try:
            if self.health_system.current_role != 'medecin':
                raise PermissionError("Cette fonctionnalité est réservée aux médecins")
            patients = self.health_system.medecin_get_patients_and_dossiers()
            display_list = []
            for patient in patients:
                patient_info = f"{patient['nom']} {patient['prenom']} ({patient['patient_email']})"
                display_list.append({"id": patient['patient_email'], "type": "Patient", "info": patient_info})
                for dossier in patient['dossiers']:
                    dossier_info = f"Dossier du {dossier['date_creation']}"
                    display_list.append({"id": dossier['id'], "type": "Dossier", "info": dossier_info})
            self.display_results("Mes Patients et Dossiers", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def view_dossiers(self):
        try:
            if not self.health_system.current_user:
                raise Exception("Aucun utilisateur connecté")
            if self.health_system.current_role == 'medecin':
                dossiers = self.health_system.medecin_get_patients_and_dossiers()
                display_list = []
                for patient in dossiers:
                    patient_info = f"{patient['nom']} {patient['prenom']} ({patient['patient_email']})"
                    display_list.append({"id": patient['patient_email'], "type": "Patient", "info": patient_info})
                    for dossier in patient['dossiers']:
                        dossier_info = f"Dossier du {dossier['date_creation']}"
                        display_list.append({"id": dossier['id'], "type": "Dossier", "info": dossier_info})
            elif self.health_system.current_role == 'patient':
                dossiers = self.health_system.patient_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']}"}
                    for dossier in dossiers
                ]
            elif self.health_system.current_role == 'radiologue':
                dossiers = self.health_system.radiologue_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                    for dossier in dossiers
                ]
            elif self.health_system.current_role == 'laborantin':
                dossiers = self.health_system.laborantin_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                    for dossier in dossiers
                ]
            else:
                raise PermissionError("Rôle non autorisé à voir les dossiers")
            if not display_list:
                messagebox.showinfo("Information", "Aucun dossier disponible.")
            self.display_results("Mes Dossiers", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des dossiers : {str(e)}")

    def view_radiologue_dossiers(self):
        try:
            if self.health_system.current_role != 'radiologue':
                raise PermissionError("Seuls les radiologues peuvent voir leurs dossiers traités")
            dossiers = self.health_system.radiologue_get_dossiers()
            display_list = [
                {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                for dossier in dossiers
            ]
            if not display_list:
                messagebox.showinfo("Information", "Aucun dossier traité disponible.")
            self.display_results("Mes Dossiers Traités (Radiologue)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des dossiers : {str(e)}")

    def view_laborantin_dossiers(self):
        try:
            if self.health_system.current_role != 'laborantin':
                raise PermissionError("Seuls les laborantins peuvent voir leurs dossiers traités")
            dossiers = self.health_system.laborantin_get_dossiers()
            display_list = [
                {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                for dossier in dossiers
            ]
            if not display_list:
                messagebox.showinfo("Information", "Aucun dossier traité disponible.")
            self.display_results("Mes Dossiers Traités (Laborantin)", display_list)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la récupération des dossiers : {str(e)}")

    def filter_dossiers(self, event=None):
        search_term = self.search_var.get().lower()
        try:
            if not self.health_system.current_user:
                return
            if self.health_system.current_role == 'medecin':
                dossiers = self.health_system.medecin_get_patients_and_dossiers()
                display_list = []
                for patient in dossiers:
                    patient_info = f"{patient['nom']} {patient['prenom']} ({patient['patient_email']})"
                    if search_term in patient_info.lower():
                        display_list.append({"id": patient['patient_email'], "type": "Patient", "info": patient_info})
                    for dossier in patient['dossiers']:
                        dossier_info = f"Dossier du {dossier['date_creation']}"
                        if search_term in dossier_info.lower() or search_term in patient['patient_email'].lower():
                            display_list.append({"id": dossier['id'], "type": "Dossier", "info": dossier_info})
            elif self.health_system.current_role == 'patient':
                dossiers = self.health_system.patient_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']}"}
                    for dossier in dossiers if search_term in dossier['id'].lower() or search_term in dossier['date_creation'].lower()
                ]
            elif self.health_system.current_role == 'radiologue':
                dossiers = self.health_system.radiologue_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                    for dossier in dossiers if search_term in dossier['id'].lower() or search_term in dossier['patient_email'].lower()
                ]
            elif self.health_system.current_role == 'laborantin':
                dossiers = self.health_system.laborantin_get_dossiers()
                display_list = [
                    {"id": dossier['id'], "type": "Dossier", "info": f"Dossier du {dossier['date_creation']} - Patient: {dossier['patient_email']}"}
                    for dossier in dossiers if search_term in dossier['id'].lower() or search_term in dossier['patient_email'].lower()
                ]
            else:
                display_list = []
            self.display_results("Résultats de la Recherche", display_list)
        except Exception as e:
            self.activity_log(f"Erreur lors du filtrage des dossiers : {str(e)}")

    def display_results(self, title, results):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.result_frame.config(text=title)
        if not results:
            self.tree.insert("", "end", values=("", "Aucun résultat", "Aucune donnée disponible"), tags=('even',))
        else:
            for i, result in enumerate(results):
                tag = 'even' if i % 2 == 0 else 'odd'
                try:
                    self.tree.insert("", "end", values=(result["id"], result["type"], result["info"]), tags=(tag,))
                except KeyError as e:
                    self.activity_log(f"Erreur dans les données de résultat : Clé manquante {str(e)}")
                    self.tree.insert("", "end", values=(result.get("id", "ID inconnu"), result.get("type", "Type inconnu"), "Données incomplètes"), tags=(tag,))

    def update_actions_visibility(self):
        for widget in self.actions_frame.winfo_children():
            widget.pack_forget()
        if not self.health_system.current_user:
            return
        role = self.health_system.current_role
        if role == 'medecin':
            self.medecin_frame.pack(fill=tk.X, pady=5)
        elif role == 'radiologue':
            self.radiologue_frame.pack(fill=tk.X, pady=5)
        elif role == 'laborantin':
            self.laborantin_frame.pack(fill=tk.X, pady=5)
        elif role == 'patient':
            self.patient_frame.pack(fill=tk.X, pady=5)
        self.common_frame.pack(fill=tk.X, pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = ABEUI(root)
    root.mainloop()