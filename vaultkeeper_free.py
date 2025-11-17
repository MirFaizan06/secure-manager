"""
VaultKeeper Free - Password & Document Manager
Copyright (c) 2025 The NxT LvL. All rights reserved.
This software is proprietary and confidential.
"""
import customtkinter as ctk
from tkinter import filedialog, messagebox
import json
import os
import sys
import shutil
from cryptography.fernet import Fernet
from datetime import datetime
try:
    from PIL import Image
except ImportError:
    Image = None

class VaultKeeperFree:
    def __init__(self):
        # Initialize main application window with enhanced styling
        self.app = ctk.CTk()
        self.app.title("VaultKeeper Free - Password Manager")
        self.app.geometry("1000x700")
        self.app.minsize(900, 600)
        
        # Enhanced color scheme and appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Set window icon
        self._set_window_icon()
        
        # Initialize data storage paths
        self._initialize_data_paths()
        
        # Load encryption and data
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self.passwords = self._load_passwords()
        self.documents = self._load_documents()
        
        # Build enhanced UI
        self._build_ui()

    def _set_window_icon(self):
        """Set window icon with enhanced error handling"""
        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(os.path.dirname(sys.executable), 'assets', 'app.ico')
            else:
                icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'app.ico')

            if os.path.exists(icon_path):
                self.app.iconbitmap(icon_path)
        except Exception:
            # Silently continue if icon loading fails
            pass

    def _initialize_data_paths(self):
        """Initialize all data storage paths with proper structure"""
        self.data_dir = os.path.join(os.path.expanduser("~"), "Documents", "VaultKeeper Free Data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.password_file = os.path.join(self.data_dir, "passwords.enc")
        self.docs_file = os.path.join(self.data_dir, "documents.json")
        self.docs_folder = os.path.join(self.data_dir, "my_documents")
        self.key_file = os.path.join(self.data_dir, "secret.key")

        if not os.path.exists(self.docs_folder):
            os.makedirs(self.docs_folder)

    def _load_or_create_key(self):
        """Load existing encryption key or create new one with enhanced error handling"""
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    return f.read()
            except PermissionError:
                messagebox.showerror(
                    "Permission Error", 
                    f"Cannot read {self.key_file}\n\nPlease run as administrator or check file permissions."
                )
                raise
        else:
            try:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                return key
            except PermissionError:
                messagebox.showerror(
                    "Permission Error",
                    f"Cannot create {self.key_file}\n\nPlease run from a writable location or as administrator."
                )
                raise

    def _load_passwords(self):
        """Load encrypted passwords from file"""
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
        """Save passwords with encryption"""
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
        """Build the main application UI with enhanced structure and styling"""
        # Main container with modern styling
        main_container = ctk.CTkFrame(self.app, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Header section with premium styling
        self._build_header(main_container)
        
        # Tab view for main functionality
        self._build_tab_view(main_container)

    def _build_header(self, parent):
        """Build the application header with enhanced visual design"""
        header_frame = ctk.CTkFrame(parent, height=80, corner_radius=12)
        header_frame.pack(fill="x", padx=10, pady=(10, 5))
        header_frame.pack_propagate(False)
        
        # Application title with improved typography
        title_label = ctk.CTkLabel(
            header_frame, 
            text="🔐 VaultKeeper Free", 
            font=ctk.CTkFont(size=26, weight="bold", family="Segoe UI"),
            text_color="#2CC985"
        )
        title_label.pack(side="left", padx=25, pady=20)
        
        # Upgrade button with premium styling
        upgrade_btn = ctk.CTkButton(
            header_frame,
            text="⭐ Upgrade to Pro",
            command=self._show_upgrade,
            width=140,
            height=35,
            fg_color="gold",
            hover_color="#FFD700",
            text_color="black",
            font=ctk.CTkFont(weight="bold", size=13),
            corner_radius=8
        )
        upgrade_btn.pack(side="right", padx=25, pady=20)

    def _build_tab_view(self, parent):
        """Build the main tab view with enhanced styling"""
        self.tabview = ctk.CTkTabview(
            parent,
            segmented_button_fg_color="#2B2B2B",
            segmented_button_selected_color="#1F6AA5",
            segmented_button_selected_hover_color="#144870",
            corner_radius=12
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        # Add tabs
        self.tabview.add("Passwords")
        self.tabview.add("Documents")
        
        # Build tab contents
        self._build_password_tab()
        self._build_document_tab()

    def _build_password_tab(self):
        """Build the passwords tab with enhanced layout and styling"""
        tab = self.tabview.tab("Passwords")
        
        # Input section with card-like design
        input_card = ctk.CTkFrame(tab, corner_radius=12)
        input_card.pack(fill="x", padx=15, pady=15)
        
        # Section title
        section_title = ctk.CTkLabel(
            input_card,
            text="Add New Password",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        section_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Input fields grid
        input_grid = ctk.CTkFrame(input_card, fg_color="transparent")
        input_grid.pack(fill="x", padx=20, pady=(0, 15))
        
        # Name field
        ctk.CTkLabel(
            input_grid, 
            text="Service Name:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=(0, 10), pady=8, sticky="w")
        
        self.pwd_name_entry = ctk.CTkEntry(
            input_grid, 
            width=300,
            height=35,
            placeholder_text="e.g., Gmail, Facebook, Bank...",
            corner_radius=8
        )
        self.pwd_name_entry.grid(row=0, column=1, padx=(0, 20), pady=8, sticky="ew")
        
        # Password field
        ctk.CTkLabel(
            input_grid, 
            text="Password:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=1, column=0, padx=(0, 10), pady=8, sticky="w")
        
        self.pwd_password_entry = ctk.CTkEntry(
            input_grid, 
            width=300,
            height=35,
            placeholder_text="Enter your password",
            show="●",
            corner_radius=8
        )
        self.pwd_password_entry.grid(row=1, column=1, padx=(0, 20), pady=8, sticky="ew")
        
        # Configure grid weights
        input_grid.columnconfigure(1, weight=1)
        
        # Action buttons
        btn_container = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_container.pack(fill="x", padx=20, pady=(5, 15))
        
        ctk.CTkButton(
            btn_container,
            text="➕ Add Password",
            command=self._add_password,
            width=120,
            height=35,
            fg_color="#2CC985",
            hover_color="#25A56A",
            corner_radius=8,
            font=ctk.CTkFont(weight="bold")
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_container,
            text="🗑️ Delete",
            command=self._delete_password,
            width=100,
            height=35,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            corner_radius=8,
            font=ctk.CTkFont(weight="bold")
        ).pack(side="left")
        
        # Password list section
        list_card = ctk.CTkFrame(tab, corner_radius=12)
        list_card.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        list_title = ctk.CTkLabel(
            list_card,
            text="🔒 Saved Passwords",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        list_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        self.pwd_scroll_frame = ctk.CTkScrollableFrame(
            list_card, 
            fg_color="transparent",
            corner_radius=8
        )
        self.pwd_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._refresh_password_list()

    def _build_document_tab(self):
        """Build the documents tab with enhanced layout and styling"""
        tab = self.tabview.tab("Documents")
        
        # Input section
        input_card = ctk.CTkFrame(tab, corner_radius=12)
        input_card.pack(fill="x", padx=15, pady=15)
        
        # Section title
        section_title = ctk.CTkLabel(
            input_card,
            text="Add New Document",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        section_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Input fields grid
        input_grid = ctk.CTkFrame(input_card, fg_color="transparent")
        input_grid.pack(fill="x", padx=20, pady=(0, 15))
        
        # Title field
        ctk.CTkLabel(
            input_grid, 
            text="Document Title:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=(0, 10), pady=8, sticky="w")
        
        self.doc_title_entry = ctk.CTkEntry(
            input_grid, 
            width=300,
            height=35,
            placeholder_text="Enter document title",
            corner_radius=8
        )
        self.doc_title_entry.grid(row=0, column=1, padx=(0, 20), pady=8, sticky="ew")
        
        # Category field
        ctk.CTkLabel(
            input_grid, 
            text="Category:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=1, column=0, padx=(0, 10), pady=8, sticky="w")
        
        self.doc_category_entry = ctk.CTkEntry(
            input_grid, 
            width=300,
            height=35,
            placeholder_text="e.g., Work, Personal, Financial...",
            corner_radius=8
        )
        self.doc_category_entry.grid(row=1, column=1, padx=(0, 20), pady=8, sticky="ew")
        
        # File selection
        file_frame = ctk.CTkFrame(input_grid, fg_color="transparent")
        file_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=12)
        
        ctk.CTkLabel(
            file_frame, 
            text="Selected File:",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left")
        
        self.doc_file_label = ctk.CTkLabel(
            file_frame, 
            text="No file selected",
            text_color="gray",
            font=ctk.CTkFont(size=12)
        )
        self.doc_file_label.pack(side="left", padx=(10, 20))
        
        self.selected_file_path = None
        
        # Configure grid weights
        input_grid.columnconfigure(1, weight=1)
        
        # Action buttons
        btn_container = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_container.pack(fill="x", padx=20, pady=(5, 15))
        
        ctk.CTkButton(
            btn_container,
            text="📁 Choose File",
            command=self._choose_file,
            width=120,
            height=35,
            fg_color="#3498DB",
            hover_color="#2980B9",
            corner_radius=8,
            font=ctk.CTkFont(weight="bold")
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_container,
            text="➕ Add Document",
            command=self._add_document,
            width=120,
            height=35,
            fg_color="#2CC985",
            hover_color="#25A56A",
            corner_radius=8,
            font=ctk.CTkFont(weight="bold")
        ).pack(side="left")
        
        # Document list section
        list_card = ctk.CTkFrame(tab, corner_radius=12)
        list_card.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        list_title = ctk.CTkLabel(
            list_card,
            text="📁 Saved Documents",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        list_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        self.doc_scroll_frame = ctk.CTkScrollableFrame(
            list_card, 
            fg_color="transparent",
            corner_radius=8
        )
        self.doc_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._refresh_document_list()

    def _add_password(self):
        """Add new password with validation"""
        name = self.pwd_name_entry.get().strip()
        password = self.pwd_password_entry.get().strip()

        if not name or not password:
            messagebox.showwarning("Missing Information", "Please enter both service name and password!")
            return

        if len(self.passwords) >= 10:
            messagebox.showwarning(
                "Limit Reached", 
                "Free version limited to 10 passwords!\n\nUpgrade to Pro for unlimited passwords and premium features!"
            )
            return

        self.passwords[name] = password
        self._save_passwords()
        self._refresh_password_list()
        
        # Clear input fields
        self.pwd_name_entry.delete(0, 'end')
        self.pwd_password_entry.delete(0, 'end')
        
        # Show success feedback
        messagebox.showinfo("Success", f"Password for '{name}' added successfully!")

    def _delete_password(self):
        """Delete selected password"""
        name = self.pwd_name_entry.get().strip()
        if not name:
            messagebox.showwarning("Missing Information", "Please enter a service name to delete!")
            return
            
        if name in self.passwords:
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for '{name}'?"):
                del self.passwords[name]
                self._save_passwords()
                self._refresh_password_list()
                self.pwd_name_entry.delete(0, 'end')
                messagebox.showinfo("Success", f"Password for '{name}' deleted successfully!")
        else:
            messagebox.showwarning("Not Found", f"No password found for '{name}'!")

    def _refresh_password_list(self):
        """Refresh the password list display with enhanced styling"""
        # Clear existing widgets
        for widget in self.pwd_scroll_frame.winfo_children():
            widget.destroy()

        # Show empty state if no passwords
        if not self.passwords:
            empty_label = ctk.CTkLabel(
                self.pwd_scroll_frame, 
                text="No passwords saved yet\nAdd your first password above!",
                text_color="gray",
                font=ctk.CTkFont(size=13),
                justify="center"
            )
            empty_label.pack(expand=True, pady=40)
            return

        # Display passwords in styled cards
        for name, password in sorted(self.passwords.items()):
            password_card = ctk.CTkFrame(self.pwd_scroll_frame, corner_radius=10)
            password_card.pack(fill="x", padx=5, pady=4)
            
            # Password info section
            info_frame = ctk.CTkFrame(password_card, fg_color="transparent")
            info_frame.pack(fill="x", padx=15, pady=10)
            
            # Service name
            name_label = ctk.CTkLabel(
                info_frame,
                text=name,
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="w"
            )
            name_label.pack(side="left", fill="x", expand=True)
            
            # Password display with toggle
            pwd_display = ctk.CTkLabel(
                info_frame,
                text="●●●●●●●●",
                font=ctk.CTkFont(size=12, family="Consolas"),
                text_color="gray"
            )
            pwd_display.pack(side="left", padx=(20, 10))
            
            # Action buttons
            action_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            action_frame.pack(side="right")
            
            ctk.CTkButton(
                action_frame,
                text="👁️ Show",
                width=70,
                height=28,
                command=lambda l=pwd_display, p=password: self._toggle_password_visibility(l, p),
                fg_color="#3498DB",
                hover_color="#2980B9",
                corner_radius=6,
                font=ctk.CTkFont(size=11)
            ).pack(side="left", padx=2)
            
            ctk.CTkButton(
                action_frame,
                text="📋 Copy",
                width=70,
                height=28,
                command=lambda p=password: self._copy_to_clipboard(p),
                fg_color="#2CC985",
                hover_color="#25A56A",
                corner_radius=6,
                font=ctk.CTkFont(size=11)
            ).pack(side="left", padx=2)

    def _toggle_password_visibility(self, label, password):
        """Toggle password visibility between masked and plain text"""
        if label.cget("text") == "●●●●●●●●":
            label.configure(text=password, text_color="white")
        else:
            label.configure(text="●●●●●●●●", text_color="gray")

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard with feedback"""
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        # Show subtle feedback instead of messagebox
        original_title = self.app.title()
        self.app.title("VaultKeeper Free - ✓ Copied!")
        self.app.after(1000, lambda: self.app.title(original_title))

    def _choose_file(self):
        """Open file dialog for document selection"""
        file_path = filedialog.askopenfilename(
            title="Select Document",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            self.doc_file_label.configure(text=filename, text_color="#2CC985")

    def _add_document(self):
        """Add new document with validation"""
        title = self.doc_title_entry.get().strip()
        category = self.doc_category_entry.get().strip()

        if not title or not category or not self.selected_file_path:
            messagebox.showwarning("Missing Information", "Please fill all fields and select a file!")
            return

        if len(self.documents) >= 5:
            messagebox.showwarning(
                "Limit Reached", 
                "Free version limited to 5 documents!\n\nUpgrade to Pro for unlimited storage and advanced features!"
            )
            return

        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_name = os.path.basename(self.selected_file_path)
        filename = f"{timestamp}_{original_name}"
        
        # Copy file to documents folder
        destination_path = os.path.join(self.docs_folder, filename)
        shutil.copy2(self.selected_file_path, destination_path)

        # Add to documents list
        self.documents.append({
            "title": title, 
            "category": category, 
            "filename": filename,
            "original_name": original_name,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        
        self._save_documents()
        self._refresh_document_list()
        
        # Clear input fields
        self.doc_title_entry.delete(0, 'end')
        self.doc_category_entry.delete(0, 'end')
        self.doc_file_label.configure(text="No file selected", text_color="gray")
        self.selected_file_path = None
        
        messagebox.showinfo("Success", f"Document '{title}' added successfully!")

    def _refresh_document_list(self):
        """Refresh the document list display with enhanced styling"""
        # Clear existing widgets
        for widget in self.doc_scroll_frame.winfo_children():
            widget.destroy()

        # Show empty state if no documents
        if not self.documents:
            empty_label = ctk.CTkLabel(
                self.doc_scroll_frame, 
                text="No documents saved yet\nAdd your first document above!",
                text_color="gray",
                font=ctk.CTkFont(size=13),
                justify="center"
            )
            empty_label.pack(expand=True, pady=40)
            return

        # Display documents in styled cards
        for doc in self.documents:
            doc_card = ctk.CTkFrame(self.doc_scroll_frame, corner_radius=10)
            doc_card.pack(fill="x", padx=5, pady=4)
            
            # Document info section
            info_frame = ctk.CTkFrame(doc_card, fg_color="transparent")
            info_frame.pack(fill="x", padx=15, pady=12)
            
            # Left section - Title and metadata
            left_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            left_frame.pack(side="left", fill="x", expand=True)
            
            # Document title
            title_label = ctk.CTkLabel(
                left_frame,
                text=doc['title'],
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="w"
            )
            title_label.pack(anchor="w")
            
            # Metadata (category and date)
            meta_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
            meta_frame.pack(anchor="w", pady=(2, 0))
            
            ctk.CTkLabel(
                meta_frame,
                text=f"📁 {doc['category']}",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(side="left")
            
            ctk.CTkLabel(
                meta_frame,
                text=f" • 📅 {doc['date']}",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(side="left", padx=(8, 0))
            
            ctk.CTkLabel(
                meta_frame,
                text=f" • 📄 {doc['original_name']}",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(side="left", padx=(8, 0))
            
            # Action button
            ctk.CTkButton(
                info_frame,
                text="📂 Open",
                width=80,
                height=32,
                command=lambda f=doc['filename']: self._open_document(f),
                fg_color="#3498DB",
                hover_color="#2980B9",
                corner_radius=8,
                font=ctk.CTkFont(weight="bold", size=12)
            ).pack(side="right", padx=(10, 0))

    def _open_document(self, filename):
        """Open document in default application"""
        try:
            file_path = os.path.join(self.docs_folder, filename)
            if os.path.exists(file_path):
                os.startfile(file_path)
            else:
                messagebox.showerror("Error", "Document file not found!")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open document: {str(e)}")

    def _show_upgrade(self):
        """Show upgrade to Pro information"""
        pro_features = [
            "• Unlimited passwords & documents",
            "• Advanced password generator", 
            "• Password strength indicator",
            "• Multiple themes & customization",
            "• Backup & restore functionality",
            "• Categories & tags organization",
            "• Priority customer support",
            "• And much more!"
        ]
        
        messagebox.showinfo(
            "🚀 Upgrade to VaultKeeper Pro", 
            "Unlock the full potential of secure password management!\n\n"
            "Visit: https://vault-keeper.netlify.app\n\n"
            "Pro Features:\n" + "\n".join(pro_features)
        )

    def run(self):
        """Start the application main loop"""
        self.app.mainloop()

if __name__ == "__main__":
    app = VaultKeeperFree()
    app.run()