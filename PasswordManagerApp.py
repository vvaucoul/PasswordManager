import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from ttkthemes import ThemedTk

import os
import string
import random

import pyperclip

from openpyxl import Workbook
import openpyxl

from cryptography.fernet import InvalidToken

from PasswordManager import (
    create_master_password,
    verify_master_password,
    generate_key,
    load_passwords,
    encrypt_password,
    save_passwords,
    decrypt_password,
)

from authentificator import (
    generate_totp_secret,
    display_qr_code
)



class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Gestionnaire de mots de passe")
        self.master.geometry("400x300")
        self.master.resizable(False, False)

        if os.path.exists("icon.ico"):
            self.master.iconbitmap("icon.ico")

        self.master.set_theme("vista")

        self.master = master
        self.master.title("Gestionnaire de mots de passe")
        self.master.geometry("400x200")

        self.master_password_entry = None
        self.site_entry = None
        self.password_entry = None

        self.key = None
        self.passwords = {}

        self.init_ui()

    def init_ui(self):
        self.create_master_password_frame()

    def create_master_password_frame(self):
        frame = ttk.Frame(self.master)
        frame.pack(fill=tk.BOTH, expand=True)

        label = ttk.Label(frame, text="Entrez le mot de passe maître :")
        label.pack(pady=10)

        self.master_password_entry = ttk.Entry(frame, show="*")
        self.master_password_entry.pack()

        submit_button = ttk.Button(
            frame, text="Soumettre", command=self.verify_master_password
        )
        submit_button.pack(pady=10)

    def create_password_manager_frame(self):
        frame = tk.Frame(self.master)
        frame.pack(fill=tk.BOTH, expand=True)

        retrieve_button = tk.Button(
            frame, text="Récupérer", command=self.retrieve_password
        )
        retrieve_button.grid(row=2, column=1, padx=5, pady=5)

        generate_button = tk.Button(
            frame, text="Générer", command=self.generate_and_display_password
        )
        generate_button.grid(row=3, column=0, padx=5, pady=5)

        display_sites_button = tk.Button(
            frame, text="Afficher les sites", command=self.show_sites_table
        )
        display_sites_button.grid(row=3, column=1, padx=5, pady=5)

        export_button = tk.Button(frame, text="Exporter", command=self.export_passwords)
        export_button.grid(row=3, column=2, padx=5, pady=5)

        self.site_entry = tk.Entry(frame)
        self.site_entry.grid(row=0, column=1, padx=5, pady=5)

        password_label = tk.Label(frame, text="Mot de passe :")
        password_label.grid(row=1, column=0, padx=5, pady=5)

        self.password_entry = tk.Entry(frame)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        add_button = tk.Button(frame, text="Ajouter", command=self.add_password)
        add_button.grid(row=2, column=0, padx=5, pady=5)

        retrieve_button = tk.Button(
            frame, text="Récupérer", command=self.retrieve_password
        )
        retrieve_button.grid(row=2, column=1, padx=5, pady=5)

    def check_master_password(self):
        master_password = self.master_password_entry.get()

        if os.path.exists("salt.bin"):
            with open("salt.bin", "rb") as f:
                salt = f.read()
        else:
            master_password, salt = create_master_password()
            with open("salt.bin", "wb") as f:
                f.write(salt)

        if verify_master_password(master_password, salt):
            self.key = generate_key(master_password, salt)
            self.passwords = load_passwords(self.key)
            self.master_password_entry.delete(0, tk.END)
            self.master_password_entry.master.pack_forget()
            self.create_password_manager_frame()
        else:
            messagebox.showerror(
                "Erreur", "Mot de passe maître incorrect. Veuillez réessayer."
            )

    def show_sites_table(self):
        sites_window = tk.Toplevel(self.master)
        sites_window.title("Sites enregistrés")
        sites_window.geometry("300x200")

        tree = ttk.Treeview(sites_window)
        tree["columns"] = "site"
        tree.column("#0", width=0, stretch=tk.NO)
        tree.column("site", anchor=tk.CENTER, width=280)

        tree.heading("#0", text="", anchor=tk.CENTER)
        tree.heading("site", text="Site", anchor=tk.CENTER)

        for site in self.passwords.keys():
            tree.insert(parent="", index=tk.END, iid=None, text="", values=(site,))

        tree.pack(expand=True, fill=tk.BOTH)

    def generate_and_display_password(self, length=12):
        password = self.generate_password(length)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def generate_password(self, length=12):
        """Generate a random password of given length"""
        password_characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choice(password_characters) for i in range(length))
        return password

    def export_passwords(self):
        if not self.passwords:
            messagebox.showerror("Erreur", "Aucun mot de passe à exporter.")
            return

        decrypted_passwords = {
            site: decrypt_password(enc_password, self.key)
            for site, enc_password in self.passwords.items()
        }
        wb = Workbook()
        ws = wb.active
        ws.title = "Mots de passe"

        ws.append(["Site", "Mot de passe"])

        for site, password in decrypted_passwords.items():
            ws.append([site, password])

        file_name = "passwords.xlsx"
        wb.save(file_name)

        messagebox.showinfo(
            "Succès", f"Les mots de passe ont été exportés dans le fichier {file_name}."
        )

    def add_password(self):
        site = self.site_entry.get()
        password = self.password_entry.get()

        if not site or not password:
            messagebox.showerror(
                "Erreur", "Veuillez entrer un site et un mot de passe."
            )
            return

        encrypted_password = encrypt_password(password, self.key)
        self.passwords[site] = encrypted_password
        save_passwords(self.passwords, self.key)
        messagebox.showinfo("Succès", "Le mot de passe a été ajouté.")

        self.site_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def retrieve_password(self):
        site = self.site_entry.get()

        if not site:
            messagebox.showerror("Erreur", "Veuillez entrer le nom du site.")
            return

        encrypted_password = self.passwords.get(site)

        if encrypted_password:
            password = decrypt_password(encrypted_password, self.key)
            pyperclip.copy(password)  # Ajoutez cette ligne pour copier le mot de passe dans le presse-papier
            messagebox.showinfo("Mot de passe récupéré", f"Le mot de passe pour {site} a été copié dans le presse-papier.")
        else:
            messagebox.showerror("Erreur", "Aucun mot de passe trouvé pour ce site.")

    def verify_master_password(self):
        master_password = self.master_password_entry.get()
        if not master_password:
            messagebox.showerror(
                "Erreur", "Le mot de passe maître ne peut pas être vide."
            )
            return

        try:
            with open("salt.bin", "rb") as f:
                salt = f.read()
        except FileNotFoundError:
            master_password, salt = create_master_password()
            with open("salt.bin", "wb") as f:
                f.write(salt)

        if not verify_master_password(master_password, salt):
            messagebox.showerror("Erreur", "Mot de passe maître incorrect.")
        else:
            self.key = generate_key(master_password, salt)
            self.passwords = load_passwords(self.key)
            self.master_password_entry.delete(0, tk.END)
            self.master_password_entry.master.pack_forget()
            self.create_password_manager_frame()

    def run(self):
        self.master.mainloop()


if __name__ == "__main__":
    root = ThemedTk()
    app = PasswordManagerApp(root)
    app.run()
