import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
import shutil
from cryptography.fernet import Fernet
from datetime import datetime
import random
import string
import re
import zipfile

class SecureManager:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Secure Manager Pro - Passwords & Documents")
        self.app.geometry("1200x800")

        # Theme configurations
        self.themes = {
            "Dark": {"mode": "dark", "color": "blue"},
            "Light": {"mode": "light", "color": "blue"},
            "Neon": {"mode": "dark", "color": "green"},
            "Dev": {"mode": "dark", "color": "dark-blue"},
            "Ocean": {"mode": "dark", "color": "blue"}
        }
        self.current_theme = "Dark"

        # Set initial theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Data files
        self.password_file = "passwords.enc"
        self.docs_file = "documents.json"
        self.docs_folder = "my_documents"
        self.key_file = "secret.key"
        self.settings_file = "settings.json"

        # Initialize encryption key
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

        # Create documents folder
        if not os.path.exists(self.docs_folder):
            os.makedirs(self.docs_folder)

        # Load data
        self.passwords = self._load_passwords()
        self.documents = self._load_documents()
        self.settings = self._load_settings()

        # Password visibility states
        self.pwd_visible = False

        # Build UI
        self._build_ui()

        # Apply saved theme
        if "theme" in self.settings:
            self._apply_theme(self.settings["theme"])

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

    def _load_settings(self):
        """Load settings"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_settings(self):
        """Save settings"""
        with open(self.settings_file, 'w') as f:
            json.dump(self.settings, f, indent=2)

    def _check_password_strength(self, password):
        """Check password strength and return score"""
        if not password:
            return "None", 0

        score = 0
        feedback = []

        # Length check
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1

        # Determine strength
        if score <= 2:
            return "Weak", score
        elif score <= 4:
            return "Medium", score
        elif score <= 6:
            return "Strong", score
        else:
            return "Very Strong", score

    def _generate_password(self, length=16, use_symbols=True, use_numbers=True, use_upper=True, use_lower=True):
        """Generate a random password"""
        chars = ""
        if use_lower:
            chars += string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_numbers:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not chars:
            chars = string.ascii_letters + string.digits

        password = ''.join(random.choice(chars) for _ in range(length))
        return password

    def _build_ui(self):
        """Build the main UI"""
        # Main container
        main_frame = ctk.CTkFrame(self.app)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Header with title and theme selector
        header_frame = ctk.CTkFrame(main_frame)
        header_frame.pack(fill="x", padx=10, pady=10)

        title_label = ctk.CTkLabel(
            header_frame,
            text="🔐 Secure Manager Pro",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(side="left", padx=20)

        # Theme selector
        theme_label = ctk.CTkLabel(header_frame, text="Theme:", font=ctk.CTkFont(size=12))
        theme_label.pack(side="right", padx=5)

        self.theme_menu = ctk.CTkOptionMenu(
            header_frame,
            values=list(self.themes.keys()),
            command=self._apply_theme,
            width=120
        )
        self.theme_menu.set(self.current_theme)
        self.theme_menu.pack(side="right", padx=10)

        # Backup/Restore buttons
        ctk.CTkButton(
            header_frame,
            text="💾 Backup",
            command=self._backup_data,
            width=100,
            fg_color="green",
            hover_color="darkgreen"
        ).pack(side="right", padx=5)

        ctk.CTkButton(
            header_frame,
            text="📥 Restore",
            command=self._restore_data,
            width=100,
            fg_color="orange",
            hover_color="darkorange"
        ).pack(side="right", padx=5)

        # Tab view
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabs
        self.tabview.add("Password Manager")
        self.tabview.add("Document Manager")
        self.tabview.add("Settings")

        # Build tabs
        self._build_password_tab()
        self._build_document_tab()
        self._build_settings_tab()

    def _build_password_tab(self):
        """Build enhanced password manager interface"""
        tab = self.tabview.tab("Password Manager")

        # Input frame
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        # Row 1: Name and Category
        row1 = ctk.CTkFrame(input_frame)
        row1.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(row1, text="App/Website:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.pwd_name_entry = ctk.CTkEntry(row1, width=250, placeholder_text="e.g., Gmail, Facebook")
        self.pwd_name_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(row1, text="Category:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.pwd_category_entry = ctk.CTkEntry(row1, width=150, placeholder_text="e.g., Social, Work")
        self.pwd_category_entry.grid(row=0, column=3, padx=10, pady=5)

        # Row 2: Password with visibility toggle
        row2 = ctk.CTkFrame(input_frame)
        row2.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(row2, text="Password:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=5, sticky="w")

        pwd_input_frame = ctk.CTkFrame(row2)
        pwd_input_frame.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.pwd_password_entry = ctk.CTkEntry(pwd_input_frame, width=250, placeholder_text="Enter password", show="●")
        self.pwd_password_entry.pack(side="left", padx=(0, 5))
        self.pwd_password_entry.bind("<KeyRelease>", self._update_password_strength)

        self.pwd_toggle_btn = ctk.CTkButton(
            pwd_input_frame,
            text="👁",
            width=35,
            command=self._toggle_password_visibility,
            font=ctk.CTkFont(size=16)
        )
        self.pwd_toggle_btn.pack(side="left", padx=2)

        # Password strength indicator
        self.pwd_strength_label = ctk.CTkLabel(row2, text="Strength: None", font=ctk.CTkFont(size=11))
        self.pwd_strength_label.grid(row=0, column=2, padx=10, pady=5)

        self.pwd_strength_bar = ctk.CTkProgressBar(row2, width=100)
        self.pwd_strength_bar.set(0)
        self.pwd_strength_bar.grid(row=0, column=3, padx=10, pady=5)

        # Row 3: Username/Email (optional)
        row3 = ctk.CTkFrame(input_frame)
        row3.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(row3, text="Username/Email:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.pwd_username_entry = ctk.CTkEntry(row3, width=250, placeholder_text="Optional")
        self.pwd_username_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(row3, text="Notes:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.pwd_notes_entry = ctk.CTkEntry(row3, width=250, placeholder_text="Optional notes")
        self.pwd_notes_entry.grid(row=0, column=3, padx=10, pady=5)

        # Password Generator Section
        gen_frame = ctk.CTkFrame(input_frame)
        gen_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(gen_frame, text="🎲 Password Generator", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=10)

        ctk.CTkLabel(gen_frame, text="Length:").pack(side="left", padx=5)
        self.gen_length = ctk.CTkEntry(gen_frame, width=50)
        self.gen_length.insert(0, "16")
        self.gen_length.pack(side="left", padx=5)

        self.gen_upper = ctk.CTkCheckBox(gen_frame, text="A-Z", width=60)
        self.gen_upper.select()
        self.gen_upper.pack(side="left", padx=2)

        self.gen_lower = ctk.CTkCheckBox(gen_frame, text="a-z", width=60)
        self.gen_lower.select()
        self.gen_lower.pack(side="left", padx=2)

        self.gen_numbers = ctk.CTkCheckBox(gen_frame, text="0-9", width=60)
        self.gen_numbers.select()
        self.gen_numbers.pack(side="left", padx=2)

        self.gen_symbols = ctk.CTkCheckBox(gen_frame, text="!@#", width=60)
        self.gen_symbols.select()
        self.gen_symbols.pack(side="left", padx=2)

        ctk.CTkButton(
            gen_frame,
            text="Generate",
            command=self._generate_and_fill_password,
            width=100,
            fg_color="purple",
            hover_color="darkviolet"
        ).pack(side="left", padx=10)

        # Buttons frame
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(btn_frame, text="➕ Add/Update", command=self._add_password, width=120, height=35,
                     fg_color="green", hover_color="darkgreen").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑 Delete", command=self._delete_password, width=120, height=35,
                     fg_color="darkred", hover_color="red").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔄 Clear", command=self._clear_password_fields, width=120, height=35).pack(side="left", padx=5)

        # Search and filter frame
        search_frame = ctk.CTkFrame(tab)
        search_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(search_frame, text="🔍 Search:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.pwd_search_entry = ctk.CTkEntry(search_frame, width=250, placeholder_text="Search by name, category, or username...")
        self.pwd_search_entry.pack(side="left", padx=5)
        self.pwd_search_entry.bind("<KeyRelease>", lambda e: self._refresh_password_list())

        ctk.CTkLabel(search_frame, text="Filter by:", font=ctk.CTkFont(size=12)).pack(side="left", padx=20)
        self.pwd_filter_menu = ctk.CTkOptionMenu(
            search_frame,
            values=["All", "Recent", "By Category"],
            command=lambda x: self._refresh_password_list(),
            width=120
        )
        self.pwd_filter_menu.set("All")
        self.pwd_filter_menu.pack(side="left", padx=5)

        # Password list frame
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Scrollable frame for passwords
        self.pwd_scroll_frame = ctk.CTkScrollableFrame(list_frame, label_text="📋 Saved Passwords")
        self.pwd_scroll_frame.pack(fill="both", expand=True)

        self._refresh_password_list()

    def _toggle_password_visibility(self):
        """Toggle password visibility in input field"""
        if self.pwd_visible:
            self.pwd_password_entry.configure(show="●")
            self.pwd_toggle_btn.configure(text="👁")
            self.pwd_visible = False
        else:
            self.pwd_password_entry.configure(show="")
            self.pwd_toggle_btn.configure(text="🙈")
            self.pwd_visible = True

    def _update_password_strength(self, event=None):
        """Update password strength indicator"""
        password = self.pwd_password_entry.get()
        strength, score = self._check_password_strength(password)

        # Update label
        self.pwd_strength_label.configure(text=f"Strength: {strength}")

        # Update progress bar and color
        progress = min(score / 7, 1.0)
        self.pwd_strength_bar.set(progress)

        # Color coding
        if strength == "Weak":
            self.pwd_strength_label.configure(text_color="red")
        elif strength == "Medium":
            self.pwd_strength_label.configure(text_color="orange")
        elif strength == "Strong":
            self.pwd_strength_label.configure(text_color="yellow")
        elif strength == "Very Strong":
            self.pwd_strength_label.configure(text_color="green")
        else:
            self.pwd_strength_label.configure(text_color="gray")

    def _generate_and_fill_password(self):
        """Generate password and fill it in the entry"""
        try:
            length = int(self.gen_length.get())
            length = max(4, min(128, length))  # Limit between 4 and 128
        except:
            length = 16

        password = self._generate_password(
            length=length,
            use_symbols=self.gen_symbols.get() == 1,
            use_numbers=self.gen_numbers.get() == 1,
            use_upper=self.gen_upper.get() == 1,
            use_lower=self.gen_lower.get() == 1
        )

        self.pwd_password_entry.delete(0, 'end')
        self.pwd_password_entry.insert(0, password)
        self._update_password_strength()

        # Briefly show the password
        self.pwd_password_entry.configure(show="")
        self.pwd_toggle_btn.configure(text="🙈")
        self.pwd_visible = True

    def _add_password(self):
        """Add or update a password with enhanced data"""
        name = self.pwd_name_entry.get().strip()
        password = self.pwd_password_entry.get().strip()
        category = self.pwd_category_entry.get().strip() or "Uncategorized"
        username = self.pwd_username_entry.get().strip()
        notes = self.pwd_notes_entry.get().strip()

        if not name or not password:
            messagebox.showwarning("Missing Info", "Please enter both name and password!")
            return

        strength, score = self._check_password_strength(password)

        self.passwords[name] = {
            "password": password,
            "category": category,
            "username": username,
            "notes": notes,
            "strength": strength,
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "date_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self._save_passwords()
        self._refresh_password_list()
        self._clear_password_fields()
        messagebox.showinfo("Success", f"Password for '{name}' saved successfully!\nStrength: {strength}")

    def _delete_password(self):
        """Delete a password"""
        name = self.pwd_name_entry.get().strip()

        if not name:
            messagebox.showwarning("Missing Info", "Please enter the name to delete!")
            return

        if name in self.passwords:
            if messagebox.askyesno("Confirm Delete", f"Delete password for '{name}'?"):
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
        self.pwd_category_entry.delete(0, 'end')
        self.pwd_username_entry.delete(0, 'end')
        self.pwd_notes_entry.delete(0, 'end')
        self.pwd_strength_label.configure(text="Strength: None", text_color="gray")
        self.pwd_strength_bar.set(0)

    def _refresh_password_list(self):
        """Refresh the password list display with filters"""
        # Clear existing widgets
        for widget in self.pwd_scroll_frame.winfo_children():
            widget.destroy()

        # Get search query and filter
        search_query = self.pwd_search_entry.get().lower() if hasattr(self, 'pwd_search_entry') else ""
        filter_mode = self.pwd_filter_menu.get() if hasattr(self, 'pwd_filter_menu') else "All"

        # Filter passwords
        filtered_passwords = {}
        for name, data in self.passwords.items():
            # Handle old format (string) and new format (dict)
            if isinstance(data, str):
                # Convert old format to new format
                data = {
                    "password": data,
                    "category": "Uncategorized",
                    "username": "",
                    "notes": "",
                    "strength": "Unknown",
                    "date_added": "Unknown",
                    "date_modified": "Unknown"
                }
                self.passwords[name] = data

            # Apply search filter
            search_match = (
                search_query in name.lower() or
                search_query in data.get("category", "").lower() or
                search_query in data.get("username", "").lower()
            )

            if search_match:
                filtered_passwords[name] = data

        # Apply category filter
        if filter_mode == "Recent":
            # Sort by date and take top 10
            filtered_passwords = dict(sorted(
                filtered_passwords.items(),
                key=lambda x: x[1].get("date_modified", ""),
                reverse=True
            )[:10])

        if not filtered_passwords:
            ctk.CTkLabel(
                self.pwd_scroll_frame,
                text="No passwords found" if search_query else "No passwords saved yet",
                text_color="gray",
                font=ctk.CTkFont(size=13)
            ).pack(pady=20)
            return

        # Display each password
        for idx, (name, data) in enumerate(sorted(filtered_passwords.items())):
            pwd_frame = ctk.CTkFrame(self.pwd_scroll_frame)
            pwd_frame.pack(fill="x", padx=5, pady=5)

            # Left side - Info
            info_frame = ctk.CTkFrame(pwd_frame)
            info_frame.pack(side="left", fill="x", expand=True, padx=10, pady=5)

            # Name and category
            name_text = f"🔑 {name}"
            if data.get("category"):
                name_text += f" [{data['category']}]"

            ctk.CTkLabel(
                info_frame,
                text=name_text,
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w", padx=5)

            # Username if exists
            if data.get("username"):
                ctk.CTkLabel(
                    info_frame,
                    text=f"👤 {data['username']}",
                    font=ctk.CTkFont(size=11),
                    anchor="w",
                    text_color="gray"
                ).pack(anchor="w", padx=5)

            # Password strength and date
            meta_text = f"Strength: {data.get('strength', 'Unknown')} | Added: {data.get('date_added', 'Unknown')}"
            ctk.CTkLabel(
                info_frame,
                text=meta_text,
                font=ctk.CTkFont(size=10),
                anchor="w",
                text_color="gray"
            ).pack(anchor="w", padx=5)

            # Right side - Buttons
            btn_frame = ctk.CTkFrame(pwd_frame)
            btn_frame.pack(side="right", padx=5)

            # Password display (hidden)
            pwd_label = ctk.CTkLabel(btn_frame, text="●●●●●●●●", width=100)
            pwd_label.pack(side="left", padx=5)

            # Show/Hide button
            ctk.CTkButton(
                btn_frame,
                text="👁",
                width=40,
                command=lambda l=pwd_label, p=data["password"]: self._toggle_password_in_list(l, p)
            ).pack(side="left", padx=2)

            # Copy button
            ctk.CTkButton(
                btn_frame,
                text="📋",
                width=40,
                command=lambda p=data["password"]: self._copy_to_clipboard(p)
            ).pack(side="left", padx=2)

            # Edit button
            ctk.CTkButton(
                btn_frame,
                text="✏",
                width=40,
                command=lambda n=name, d=data: self._edit_password(n, d)
            ).pack(side="left", padx=2)

    def _toggle_password_in_list(self, label, password):
        """Toggle password visibility in list"""
        if label.cget("text") == "●●●●●●●●":
            label.configure(text=password)
        else:
            label.configure(text="●●●●●●●●")

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        messagebox.showinfo("Copied", "Copied to clipboard!", parent=self.app)

    def _edit_password(self, name, data):
        """Load password into edit fields"""
        self.pwd_name_entry.delete(0, 'end')
        self.pwd_name_entry.insert(0, name)

        self.pwd_password_entry.delete(0, 'end')
        self.pwd_password_entry.insert(0, data["password"])

        self.pwd_category_entry.delete(0, 'end')
        self.pwd_category_entry.insert(0, data.get("category", ""))

        self.pwd_username_entry.delete(0, 'end')
        self.pwd_username_entry.insert(0, data.get("username", ""))

        self.pwd_notes_entry.delete(0, 'end')
        self.pwd_notes_entry.insert(0, data.get("notes", ""))

        self._update_password_strength()

    def _build_document_tab(self):
        """Build document manager interface"""
        tab = self.tabview.tab("Document Manager")

        # Input frame
        input_frame = ctk.CTkFrame(tab)
        input_frame.pack(fill="x", padx=10, pady=10)

        # Title
        ctk.CTkLabel(input_frame, text="Document Title:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.doc_title_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Tax Returns 2024")
        self.doc_title_entry.grid(row=0, column=1, padx=10, pady=5)

        # Category
        ctk.CTkLabel(input_frame, text="Category:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.doc_category_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Personal, Work, Finance")
        self.doc_category_entry.grid(row=1, column=1, padx=10, pady=5)

        # File path
        ctk.CTkLabel(input_frame, text="File:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.doc_file_label = ctk.CTkLabel(input_frame, text="No file selected", text_color="gray")
        self.doc_file_label.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        self.selected_file_path = None

        # Buttons frame
        btn_frame = ctk.CTkFrame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ctk.CTkButton(btn_frame, text="📁 Choose File", command=self._choose_file, width=120, height=35).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="➕ Add Document", command=self._add_document, width=120, height=35,
                     fg_color="green", hover_color="darkgreen").pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🔄 Clear", command=self._clear_document_fields, width=120, height=35).pack(side="left", padx=5)

        # Search frame
        search_frame = ctk.CTkFrame(tab)
        search_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(search_frame, text="🔍 Search:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.doc_search_entry = ctk.CTkEntry(search_frame, width=300, placeholder_text="Search by title or category...")
        self.doc_search_entry.pack(side="left", padx=5)
        self.doc_search_entry.bind("<KeyRelease>", lambda e: self._refresh_document_list())

        # Document list frame
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Scrollable frame for documents
        self.doc_scroll_frame = ctk.CTkScrollableFrame(list_frame, label_text="📁 Saved Documents")
        self.doc_scroll_frame.pack(fill="both", expand=True)

        self._refresh_document_list()

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

        # Get file size
        file_size = os.path.getsize(destination)
        file_size_str = self._format_file_size(file_size)

        # Save metadata
        doc_info = {
            "title": title,
            "category": category,
            "filename": new_filename,
            "original_filename": original_filename,
            "file_size": file_size_str,
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.documents.append(doc_info)
        self._save_documents()
        self._refresh_document_list()
        self._clear_document_fields()
        messagebox.showinfo("Success", f"Document '{title}' added successfully!")

    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

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
        filtered_docs = [d for d in self.documents if
                        search_query in d['title'].lower() or
                        search_query in d['category'].lower()]

        if not filtered_docs:
            ctk.CTkLabel(
                self.doc_scroll_frame,
                text="No documents found" if search_query else "No documents saved yet",
                text_color="gray",
                font=ctk.CTkFont(size=13)
            ).pack(pady=20)
            return

        # Display each document
        for idx, doc in enumerate(filtered_docs):
            doc_frame = ctk.CTkFrame(self.doc_scroll_frame)
            doc_frame.pack(fill="x", padx=5, pady=5)

            # Document info
            info_text = f"📄 {doc['title']}\n"
            info_text += f"Category: {doc['category']} | "
            info_text += f"Size: {doc.get('file_size', 'Unknown')} | "
            info_text += f"Added: {doc['date_added']}"

            ctk.CTkLabel(
                doc_frame,
                text=info_text,
                anchor="w",
                justify="left",
                font=ctk.CTkFont(size=12)
            ).pack(side="left", padx=10, pady=5, fill="x", expand=True)

            # Buttons
            btn_frame = ctk.CTkFrame(doc_frame)
            btn_frame.pack(side="right", padx=5)

            ctk.CTkButton(
                btn_frame,
                text="📂 Open",
                width=70,
                command=lambda f=doc['filename']: self._open_document(f)
            ).pack(side="left", padx=2)

            ctk.CTkButton(
                btn_frame,
                text="🗑 Delete",
                width=70,
                fg_color="darkred",
                hover_color="red",
                command=lambda d=doc: self._delete_document(d)
            ).pack(side="left", padx=2)

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

    def _build_settings_tab(self):
        """Build settings interface"""
        tab = self.tabview.tab("Settings")

        settings_frame = ctk.CTkFrame(tab)
        settings_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            settings_frame,
            text="⚙ Settings & Information",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)

        # Stats frame
        stats_frame = ctk.CTkFrame(settings_frame)
        stats_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(stats_frame, text="📊 Statistics", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        stats_text = f"Total Passwords: {len(self.passwords)}\n"
        stats_text += f"Total Documents: {len(self.documents)}\n"

        # Calculate password strength distribution
        strength_counts = {"Weak": 0, "Medium": 0, "Strong": 0, "Very Strong": 0, "Unknown": 0}
        for name, data in self.passwords.items():
            if isinstance(data, dict):
                strength = data.get("strength", "Unknown")
                strength_counts[strength] = strength_counts.get(strength, 0) + 1

        stats_text += f"\nPassword Strength Distribution:\n"
        for strength, count in strength_counts.items():
            if count > 0:
                stats_text += f"  {strength}: {count}\n"

        ctk.CTkLabel(
            stats_frame,
            text=stats_text,
            font=ctk.CTkFont(size=13),
            justify="left"
        ).pack(pady=10, padx=20)

        # About frame
        about_frame = ctk.CTkFrame(settings_frame)
        about_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(about_frame, text="ℹ About", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        about_text = "Secure Manager Pro v2.0\n\n"
        about_text += "A modern password and document manager\n"
        about_text += "with encryption and advanced features.\n\n"
        about_text += "Features:\n"
        about_text += "• Encrypted password storage\n"
        about_text += "• Password strength analyzer\n"
        about_text += "• Password generator\n"
        about_text += "• Document manager\n"
        about_text += "• Multiple themes\n"
        about_text += "• Backup & Restore\n"

        ctk.CTkLabel(
            about_frame,
            text=about_text,
            font=ctk.CTkFont(size=12),
            justify="left"
        ).pack(pady=10, padx=20)

    def _apply_theme(self, theme_name):
        """Apply selected theme"""
        self.current_theme = theme_name
        theme = self.themes.get(theme_name, self.themes["Dark"])

        ctk.set_appearance_mode(theme["mode"])
        ctk.set_default_color_theme(theme["color"])

        # Save theme preference
        self.settings["theme"] = theme_name
        self._save_settings()

        # Show notification
        messagebox.showinfo("Theme Changed", f"Theme changed to {theme_name}!\nRestart the app to see all changes.")

    def _backup_data(self):
        """Backup all data to a zip file"""
        backup_path = filedialog.asksaveasfilename(
            title="Save Backup",
            defaultextension=".zip",
            filetypes=[("Zip files", "*.zip")],
            initialfile=f"SecureManager_Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        )

        if not backup_path:
            return

        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add password file
                if os.path.exists(self.password_file):
                    zipf.write(self.password_file)

                # Add documents metadata
                if os.path.exists(self.docs_file):
                    zipf.write(self.docs_file)

                # Add secret key
                if os.path.exists(self.key_file):
                    zipf.write(self.key_file)

                # Add settings
                if os.path.exists(self.settings_file):
                    zipf.write(self.settings_file)

                # Add all documents
                if os.path.exists(self.docs_folder):
                    for root, dirs, files in os.walk(self.docs_folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path)
                            zipf.write(file_path, arcname)

            messagebox.showinfo("Success", f"Backup created successfully!\n\nLocation: {backup_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {str(e)}")

    def _restore_data(self):
        """Restore data from a backup zip file"""
        if not messagebox.askyesno("Confirm Restore",
                                   "This will replace all current data!\n\nMake sure you have a backup of your current data.\n\nContinue?"):
            return

        backup_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Zip files", "*.zip")]
        )

        if not backup_path:
            return

        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall()

            # Reload data
            self.passwords = self._load_passwords()
            self.documents = self._load_documents()
            self.settings = self._load_settings()

            # Refresh UI
            self._refresh_password_list()
            self._refresh_document_list()

            messagebox.showinfo("Success", "Data restored successfully!\n\nPlease restart the app.")
        except Exception as e:
            messagebox.showerror("Error", f"Restore failed: {str(e)}")

    def run(self):
        """Run the application"""
        self.app.mainloop()

if __name__ == "__main__":
    app = SecureManager()
    app.run()
