import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
import shutil
from cryptography.fernet import Fernet
import base64
from datetime import datetime

class SecureManager:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Secure Manager - Passwords & Documents")
        self.app.geometry("1000x700")

        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Data files
        self.password_file = "passwords.enc"
        self.docs_file = "documents.json"
        self.docs_folder = "my_documents"
        self.key_file = "secret.key"

        # Initialize encryption key
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

        # Create documents folder
        if not os.path.exists(self.docs_folder):
            os.makedirs(self.docs_folder)

        # Load data
        self.passwords = self._load_passwords()
        self.documents = self._load_documents()

        # Build UI
        self._build_ui()

    def _load_or_create_key(self):
        """Load or create encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key

    def _load_passwords(self):
        """Load encrypted passwords"""
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
        """Save encrypted passwords"""
        json_data = json.dumps(self.passwords, indent=2)
        encrypted_data = self.cipher.encrypt(json_data.encode())
        with open(self.password_file, 'wb') as f:
            f.write(encrypted_data)

    def _load_documents(self):
        """Load documents metadata"""
        if os.path.exists(self.docs_file):
            try:
                with open(self.docs_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_documents(self):
        """Save documents metadata"""
        with open(self.docs_file, 'w') as f:
            json.dump(self.documents, f, indent=2)

    def _build_ui(self):
        """Build the main UI"""
        # Main container
        main_frame = ctk.CTkFrame(self.app)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="🔐 Secure Manager",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=10)

        # Tab view
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabs
        self.tabview.add("Password Manager")
        self.tabview.add("Document Manager")

        # Build Password Manager tab
        self._build_password_tab()

        # Build Document Manager tab
        self._build_document_tab()

    def _build_password_tab(self):
        """Build password manager interface"""
        tab = self.tabview.tab("Password Manager")

        # Input frame
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        # App/Website name
        ctk.CTkLabel(input_frame, text="App/Website Name:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.pwd_name_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Gmail, Facebook, Banking App")
        self.pwd_name_entry.grid(row=0, column=1, padx=10, pady=5)

        # Password
        ctk.CTkLabel(input_frame, text="Password:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.pwd_password_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="Enter password", show="*")
        self.pwd_password_entry.grid(row=1, column=1, padx=10, pady=5)

        # Buttons frame
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ctk.CTkButton(btn_frame, text="Add/Update", command=self._add_password, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Delete", command=self._delete_password, width=120, fg_color="darkred").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear", command=self._clear_password_fields, width=120).pack(side="left", padx=5)

        # Search frame
        search_frame = ctk.CTkFrame(tab)
        search_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(search_frame, text="Search:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.pwd_search_entry = ctk.CTkEntry(search_frame, width=300, placeholder_text="Search by name...")
        self.pwd_search_entry.pack(side="left", padx=5)
        self.pwd_search_entry.bind("<KeyRelease>", lambda e: self._refresh_password_list())

        # Password list frame
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Scrollable frame for passwords
        self.pwd_scroll_frame = ctk.CTkScrollableFrame(list_frame, label_text="Saved Passwords")
        self.pwd_scroll_frame.pack(fill="both", expand=True)

        self._refresh_password_list()

    def _build_document_tab(self):
        """Build document manager interface"""
        tab = self.tabview.tab("Document Manager")

        # Input frame
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        # Title
        ctk.CTkLabel(input_frame, text="Document Title:", font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.doc_title_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Tax Returns 2024")
        self.doc_title_entry.grid(row=0, column=1, padx=10, pady=5)

        # Category
        ctk.CTkLabel(input_frame, text="Category:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.doc_category_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Personal, Work, Finance")
        self.doc_category_entry.grid(row=1, column=1, padx=10, pady=5)

        # File path
        ctk.CTkLabel(input_frame, text="File:", font=ctk.CTkFont(size=12)).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.doc_file_label = ctk.CTkLabel(input_frame, text="No file selected", text_color="gray")
        self.doc_file_label.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        self.selected_file_path = None

        # Buttons frame
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ctk.CTkButton(btn_frame, text="Choose File", command=self._choose_file, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Add Document", command=self._add_document, width=120).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Clear", command=self._clear_document_fields, width=120).pack(side="left", padx=5)

        # Search frame
        search_frame = ctk.CTkFrame(tab)
        search_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(search_frame, text="Search:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.doc_search_entry = ctk.CTkEntry(search_frame, width=300, placeholder_text="Search by title or category...")
        self.doc_search_entry.pack(side="left", padx=5)
        self.doc_search_entry.bind("<KeyRelease>", lambda e: self._refresh_document_list())

        # Document list frame
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Scrollable frame for documents
        self.doc_scroll_frame = ctk.CTkScrollableFrame(list_frame, label_text="Saved Documents")
        self.doc_scroll_frame.pack(fill="both", expand=True)

        self._refresh_document_list()

    def _add_password(self):
        """Add or update a password"""
        name = self.pwd_name_entry.get().strip()
        password = self.pwd_password_entry.get().strip()

        if not name or not password:
            messagebox.showwarning("Missing Info", "Please enter both name and password!")
            return

        self.passwords[name] = password
        self._save_passwords()
        self._refresh_password_list()
        self._clear_password_fields()
        messagebox.showinfo("Success", f"Password for '{name}' saved successfully!")

    def _delete_password(self):
        """Delete a password"""
        name = self.pwd_name_entry.get().strip()

        if not name:
            messagebox.showwarning("Missing Info", "Please enter the name to delete!")
            return

        if name in self.passwords:
            del self.passwords[name]
            self._save_passwords()
            self._refresh_password_list()
            self._clear_password_fields()
            messagebox.showinfo("Success", f"Password for '{name}' deleted!")
        else:
            messagebox.showwarning("Not Found", f"No password found for '{name}'!")

    def _clear_password_fields(self):
        """Clear password input fields"""
        self.pwd_name_entry.delete(0, 'end')
        self.pwd_password_entry.delete(0, 'end')

    def _refresh_password_list(self):
        """Refresh the password list display"""
        # Clear existing widgets
        for widget in self.pwd_scroll_frame.winfo_children():
            widget.destroy()

        # Get search query
        search_query = self.pwd_search_entry.get().lower() if hasattr(self, 'pwd_search_entry') else ""

        # Filter passwords
        filtered_passwords = {k: v for k, v in self.passwords.items() if search_query in k.lower()}

        if not filtered_passwords:
            ctk.CTkLabel(self.pwd_scroll_frame, text="No passwords saved yet", text_color="gray").pack(pady=20)
            return

        # Display each password
        for idx, (name, password) in enumerate(sorted(filtered_passwords.items())):
            pwd_frame = ctk.CTkFrame(self.pwd_scroll_frame)
            pwd_frame.pack(fill="x", padx=5, pady=5)

            # Name
            ctk.CTkLabel(pwd_frame, text=name, font=ctk.CTkFont(size=13, weight="bold"), anchor="w", width=250).pack(side="left", padx=10, pady=5)

            # Password (hidden)
            pwd_label = ctk.CTkLabel(pwd_frame, text="••••••••", anchor="w", width=150)
            pwd_label.pack(side="left", padx=5)

            # Show/Hide button
            show_btn = ctk.CTkButton(
                pwd_frame,
                text="Show",
                width=60,
                command=lambda l=pwd_label, p=password: self._toggle_password(l, p)
            )
            show_btn.pack(side="left", padx=5)

            # Copy button
            ctk.CTkButton(
                pwd_frame,
                text="Copy",
                width=60,
                command=lambda p=password: self._copy_to_clipboard(p)
            ).pack(side="left", padx=5)

            # Edit button
            ctk.CTkButton(
                pwd_frame,
                text="Edit",
                width=60,
                command=lambda n=name, p=password: self._edit_password(n, p)
            ).pack(side="left", padx=5)

    def _toggle_password(self, label, password):
        """Toggle password visibility"""
        if label.cget("text") == "••••••••":
            label.configure(text=password)
        else:
            label.configure(text="••••••••")

    def _copy_to_clipboard(self, password):
        """Copy password to clipboard"""
        self.app.clipboard_clear()
        self.app.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def _edit_password(self, name, password):
        """Load password into edit fields"""
        self.pwd_name_entry.delete(0, 'end')
        self.pwd_name_entry.insert(0, name)
        self.pwd_password_entry.delete(0, 'end')
        self.pwd_password_entry.insert(0, password)

    def _choose_file(self):
        """Choose a file to add to documents"""
        file_path = filedialog.askopenfilename(
            title="Select a document",
            filetypes=[("All Files", "*.*")]
        )

        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            self.doc_file_label.configure(text=filename, text_color="white")

    def _add_document(self):
        """Add a document"""
        title = self.doc_title_entry.get().strip()
        category = self.doc_category_entry.get().strip()

        if not title or not category or not self.selected_file_path:
            messagebox.showwarning("Missing Info", "Please fill in all fields and choose a file!")
            return

        # Create unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_filename = os.path.basename(self.selected_file_path)
        file_extension = os.path.splitext(original_filename)[1]
        new_filename = f"{timestamp}_{original_filename}"
        destination = os.path.join(self.docs_folder, new_filename)

        # Copy file
        shutil.copy2(self.selected_file_path, destination)

        # Save metadata
        doc_info = {
            "title": title,
            "category": category,
            "filename": new_filename,
            "original_filename": original_filename,
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.documents.append(doc_info)
        self._save_documents()
        self._refresh_document_list()
        self._clear_document_fields()
        messagebox.showinfo("Success", f"Document '{title}' added successfully!")

    def _clear_document_fields(self):
        """Clear document input fields"""
        self.doc_title_entry.delete(0, 'end')
        self.doc_category_entry.delete(0, 'end')
        self.doc_file_label.configure(text="No file selected", text_color="gray")
        self.selected_file_path = None

    def _refresh_document_list(self):
        """Refresh the document list display"""
        # Clear existing widgets
        for widget in self.doc_scroll_frame.winfo_children():
            widget.destroy()

        # Get search query
        search_query = self.doc_search_entry.get().lower() if hasattr(self, 'doc_search_entry') else ""

        # Filter documents
        filtered_docs = [d for d in self.documents if search_query in d['title'].lower() or search_query in d['category'].lower()]

        if not filtered_docs:
            ctk.CTkLabel(self.doc_scroll_frame, text="No documents saved yet", text_color="gray").pack(pady=20)
            return

        # Display each document
        for idx, doc in enumerate(filtered_docs):
            doc_frame = ctk.CTkFrame(self.doc_scroll_frame)
            doc_frame.pack(fill="x", padx=5, pady=5)

            # Document info
            info_text = f"📄 {doc['title']}\nCategory: {doc['category']} | Added: {doc['date_added']}"
            ctk.CTkLabel(doc_frame, text=info_text, anchor="w", justify="left").pack(side="left", padx=10, pady=5, fill="x", expand=True)

            # Open button
            ctk.CTkButton(
                doc_frame,
                text="Open",
                width=60,
                command=lambda f=doc['filename']: self._open_document(f)
            ).pack(side="left", padx=5)

            # Delete button
            ctk.CTkButton(
                doc_frame,
                text="Delete",
                width=60,
                fg_color="darkred",
                command=lambda d=doc: self._delete_document(d)
            ).pack(side="left", padx=5)

    def _open_document(self, filename):
        """Open a document"""
        file_path = os.path.join(self.docs_folder, filename)
        if os.path.exists(file_path):
            os.startfile(file_path)
        else:
            messagebox.showerror("Error", "File not found!")

    def _delete_document(self, doc):
        """Delete a document"""
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{doc['title']}'?"):
            # Delete file
            file_path = os.path.join(self.docs_folder, doc['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)

            # Remove from metadata
            self.documents.remove(doc)
            self._save_documents()
            self._refresh_document_list()
            messagebox.showinfo("Success", "Document deleted!")

    def run(self):
        """Run the application"""
        self.app.mainloop()

if __name__ == "__main__":
    app = SecureManager()
    app.run()
