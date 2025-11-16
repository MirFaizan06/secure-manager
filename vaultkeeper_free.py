"""
VaultKeeper Free - Password & Document Manager
Copyright (c) 2025 Mir Faizan. All rights reserved.
This software is proprietary and confidential.
"""
import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
import shutil
from cryptography.fernet import Fernet
from datetime import datetime

class VaultKeeperFree:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("VaultKeeper Free - Password Manager")
        self.app.geometry("900x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.password_file = "passwords.enc"
        self.docs_file = "documents.json"
        self.docs_folder = "my_documents"
        self.key_file = "secret.key"

        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

        if not os.path.exists(self.docs_folder):
            os.makedirs(self.docs_folder)

        self.passwords = self._load_passwords()
        self.documents = self._load_documents()
        self._build_ui()

    def _load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key

    def _load_passwords(self):
        if os.path.exists(self.password_file):
            try:
                with open(self.password_file, 'rb') as f:
                    encrypted_data = f.read()
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    return json.loads(decrypted_data.decode())
            except:
                return {}
        return {}

    def _save_passwords(self):
        json_data = json.dumps(self.passwords, indent=2)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        with open(self.password_file, 'wb') as f:
            f.write(encrypted_data)

    def _load_documents(self):
        if os.path.exists(self.docs_file):
            try:
                with open(self.docs_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_documents(self):
        with open(self.docs_file, 'w') as f:
            json.dump(self.documents, f, indent=2)

    def _build_ui(self):
        main_frame = ctk.CTkFrame(self.app)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        header_frame = ctk.CTkFrame(main_frame)
        header_frame.pack(fill="x", padx=10, pady=10)

        title_label = ctk.CTkLabel(header_frame, text="🔐 VaultKeeper Free", font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(side="left", padx=20)

        ctk.CTkButton(header_frame, text="⭐ Upgrade to Pro", command=self._show_upgrade, fg_color="gold", text_color="black", hover_color="orange").pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        self.tabview.add("Passwords")
        self.tabview.add("Documents")

        self._build_password_tab()
        self._build_document_tab()

    def _build_password_tab(self):
        tab = self.tabview.tab("Passwords")

        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(input_frame, text="Name:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=5)
        self.pwd_name_entry = ctk.CTkEntry(input_frame, width=250, placeholder_text="App/Website name")
        self.pwd_name_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(input_frame, text="Password:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=10, pady=5)
        self.pwd_password_entry = ctk.CTkEntry(input_frame, width=250, placeholder_text="Password", show="●")
        self.pwd_password_entry.grid(row=1, column=1, padx=10, pady=5)

        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ctk.CTkButton(btn_frame, text="Add", command=self._add_password, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Delete", command=self._delete_password, width=100, fg_color="red").pack(side="left", padx=5)

        self.pwd_scroll_frame = ctk.CTkScrollableFrame(tab, label_text="Saved Passwords")
        self.pwd_scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self._refresh_password_list()

    def _build_document_tab(self):
        tab = self.tabview.tab("Documents")

        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(input_frame, text="Title:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=5)
        self.doc_title_entry = ctk.CTkEntry(input_frame, width=250)
        self.doc_title_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(input_frame, text="Category:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=10, pady=5)
        self.doc_category_entry = ctk.CTkEntry(input_frame, width=250)
        self.doc_category_entry.grid(row=1, column=1, padx=10, pady=5)

        self.doc_file_label = ctk.CTkLabel(input_frame, text="No file selected", text_color="gray")
        self.doc_file_label.grid(row=2, column=0, columnspan=2, pady=5)
        self.selected_file_path = None

        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ctk.CTkButton(btn_frame, text="Choose File", command=self._choose_file, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Add", command=self._add_document, width=100).pack(side="left", padx=5)

        self.doc_scroll_frame = ctk.CTkScrollableFrame(tab, label_text="Saved Documents")
        self.doc_scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self._refresh_document_list()

    def _add_password(self):
        name = self.pwd_name_entry.get().strip()
        password = self.pwd_password_entry.get().strip()

        if not name or not password:
            messagebox.showwarning("Missing Info", "Please enter both name and password!")
            return

        if len(self.passwords) >= 10:
            messagebox.showwarning("Limit Reached", "Free version limited to 10 passwords!\n\nUpgrade to Pro for unlimited passwords and more features!")
            return

        self.passwords[name] = password
        self._save_passwords()
        self._refresh_password_list()
        self.pwd_name_entry.delete(0, 'end')
        self.pwd_password_entry.delete(0, 'end')

    def _delete_password(self):
        name = self.pwd_name_entry.get().strip()
        if name in self.passwords:
            del self.passwords[name]
            self._save_passwords()
            self._refresh_password_list()
            self.pwd_name_entry.delete(0, 'end')

    def _refresh_password_list(self):
        for widget in self.pwd_scroll_frame.winfo_children():
            widget.destroy()

        if not self.passwords:
            ctk.CTkLabel(self.pwd_scroll_frame, text="No passwords saved", text_color="gray").pack(pady=20)
            return

        for name, password in sorted(self.passwords.items()):
            frame = ctk.CTkFrame(self.pwd_scroll_frame)
            frame.pack(fill="x", padx=5, pady=3)

            ctk.CTkLabel(frame, text=name, font=ctk.CTkFont(size=12, weight="bold"), width=200, anchor="w").pack(side="left", padx=10)

            pwd_label = ctk.CTkLabel(frame, text="●●●●●●●●", width=100)
            pwd_label.pack(side="left", padx=5)

            ctk.CTkButton(frame, text="Show", width=50, command=lambda l=pwd_label, p=password: self._toggle_pwd(l, p)).pack(side="left", padx=2)
            ctk.CTkButton(frame, text="Copy", width=50, command=lambda p=password: self._copy(p)).pack(side="left", padx=2)

    def _toggle_pwd(self, label, password):
        label.configure(text=password if label.cget("text") == "●●●●●●●●" else "●●●●●●●●")

    def _copy(self, text):
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!")

    def _choose_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_path = file_path
            self.doc_file_label.configure(text=os.path.basename(file_path), text_color="white")

    def _add_document(self):
        title = self.doc_title_entry.get().strip()
        category = self.doc_category_entry.get().strip()

        if not title or not category or not self.selected_file_path:
            messagebox.showwarning("Missing Info", "Please fill all fields!")
            return

        if len(self.documents) >= 5:
            messagebox.showwarning("Limit Reached", "Free version limited to 5 documents!\n\nUpgrade to Pro for unlimited storage!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{os.path.basename(self.selected_file_path)}"
        shutil.copy2(self.selected_file_path, os.path.join(self.docs_folder, filename))

        self.documents.append({"title": title, "category": category, "filename": filename, "date": datetime.now().strftime("%Y-%m-%d")})
        self._save_documents()
        self._refresh_document_list()
        self.doc_title_entry.delete(0, 'end')
        self.doc_category_entry.delete(0, 'end')
        self.doc_file_label.configure(text="No file selected", text_color="gray")

    def _refresh_document_list(self):
        for widget in self.doc_scroll_frame.winfo_children():
            widget.destroy()

        if not self.documents:
            ctk.CTkLabel(self.doc_scroll_frame, text="No documents saved", text_color="gray").pack(pady=20)
            return

        for doc in self.documents:
            frame = ctk.CTkFrame(self.doc_scroll_frame)
            frame.pack(fill="x", padx=5, pady=3)

            ctk.CTkLabel(frame, text=f"{doc['title']} [{doc['category']}]", anchor="w").pack(side="left", padx=10, fill="x", expand=True)
            ctk.CTkButton(frame, text="Open", width=50, command=lambda f=doc['filename']: os.startfile(os.path.join(self.docs_folder, f))).pack(side="left", padx=2)

    def _show_upgrade(self):
        messagebox.showinfo("Upgrade to Pro", "Visit https://vaultkeeper.com to upgrade!\n\nPro Features:\n• Unlimited passwords & documents\n• Password generator\n• Strength indicator\n• Multiple themes\n• Backup/Restore\n• Categories & tags\n• And much more!")

    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    app = VaultKeeperFree()
    app.run()
