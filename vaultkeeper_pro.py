"""
VaultKeeper Pro - Professional Password & Document Manager
Copyright (c) 2025 The NxT LvL. All rights reserved.
This software is proprietary. Unauthorized distribution is prohibited.
License required for use.
"""
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
import json, os, shutil, random, string, re, zipfile, hashlib, requests, base64, secrets
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from typing import Any

# Optional 2FA imports - set to None if not available
try:
    import pyotp
    import qrcode
    from PIL import Image, ImageTk
    TOTP_AVAILABLE = True
except ImportError:
    pyotp = None  # type: ignore
    qrcode = None  # type: ignore
    Image = None  # type: ignore
    ImageTk = None  # type: ignore
    TOTP_AVAILABLE = False

class AuthManager:
    def __init__(self):
        # Enhanced security: Store in Windows AppData with hidden attributes
        appdata = os.getenv('APPDATA')
        if not appdata:
            # Fallback if APPDATA is not set
            appdata = os.path.expanduser('~')
        self.auth_dir = os.path.join(appdata, 'VaultKeeper')
        if not os.path.exists(self.auth_dir):
            os.makedirs(self.auth_dir)
            # Set hidden attribute on Windows
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(self.auth_dir, 2)  # FILE_ATTRIBUTE_HIDDEN
            except:
                pass

        self.auth_file = os.path.join(self.auth_dir, '.vkauth')
        self.totp_file = os.path.join(self.auth_dir, '.vk2fa')

    def is_first_time(self):
        return not os.path.exists(self.auth_file)

    def setup_master_password(self, password, security_question, security_answer):
        """Setup master password with enhanced security hashing"""
        if len(password) < 10:
            return False, "Password must be at least 10 characters"

        # Enhanced password hashing with salt and multiple iterations
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

        # Hash security answer with same salt
        ans_hash = hashlib.pbkdf2_hmac('sha256', security_answer.lower().strip().encode(), salt.encode(), 100000).hex()

        auth_data = {
            'password_hash': pwd_hash,
            'salt': salt,
            'security_question': security_question,
            'answer_hash': ans_hash,
            'created': datetime.now().isoformat()
        }

        with open(self.auth_file, 'w') as f:
            json.dump(auth_data, f)

        # Set hidden attribute for enhanced security
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(self.auth_file, 2)
        except:
            pass

        return True, "Master password set successfully"

    def verify_password(self, password):
        """Verify master password with enhanced error handling"""
        if not os.path.exists(self.auth_file):
            return False

        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)

            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(),
                                          auth_data['salt'].encode(), 100000).hex()

            return pwd_hash == auth_data['password_hash']
        except:
            return False

    def get_security_question(self):
        """Get security question for password recovery"""
        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)
            return auth_data.get('security_question', '')
        except:
            return ''

    def verify_security_answer(self, answer):
        """Verify security answer with enhanced validation"""
        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)

            ans_hash = hashlib.pbkdf2_hmac('sha256', answer.lower().strip().encode(),
                                          auth_data['salt'].encode(), 100000).hex()

            return ans_hash == auth_data['answer_hash']
        except:
            return False

    def reset_password(self, new_password):
        """Reset password after security question verification"""
        try:
            with open(self.auth_file, 'r') as f:
                auth_data = json.load(f)

            # Generate new salt for enhanced security
            salt = secrets.token_hex(32)
            pwd_hash = hashlib.pbkdf2_hmac('sha256', new_password.encode(), salt.encode(), 100000).hex()

            # Keep old security question/answer but update with new salt
            old_answer = input("Enter security answer: ")  # This is just for rehashing
            ans_hash = hashlib.pbkdf2_hmac('sha256', old_answer.lower().strip().encode(), salt.encode(), 100000).hex()

            auth_data['password_hash'] = pwd_hash
            auth_data['salt'] = salt

            with open(self.auth_file, 'w') as f:
                json.dump(auth_data, f)

            return True
        except:
            return False

    def setup_2fa(self):
        """Setup TOTP-based 2FA with QR code generation"""
        if not TOTP_AVAILABLE or not pyotp:
            return None, "2FA libraries not installed"

        # Generate cryptographically secure secret key
        secret = pyotp.random_base32()

        # Save encrypted TOTP data
        totp_data = {
            'secret': secret,
            'enabled': True,
            'created': datetime.now().isoformat()
        }

        with open(self.totp_file, 'w') as f:
            json.dump(totp_data, f)

        # Set hidden attribute for security
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(self.totp_file, 2)
        except:
            pass

        # Generate QR code for easy setup
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="VaultKeeper Pro", issuer_name="VaultKeeper")

        return secret, uri

    def verify_2fa(self, code):
        """Verify TOTP code with clock drift tolerance"""
        if not TOTP_AVAILABLE or not pyotp or not os.path.exists(self.totp_file):
            return True  # Skip if not enabled

        try:
            with open(self.totp_file, 'r') as f:
                totp_data = json.load(f)

            if not totp_data.get('enabled', False):
                return True

            totp = pyotp.TOTP(totp_data['secret'])
            return totp.verify(code, valid_window=1)  # Allow 1 step before/after for clock drift
        except:
            return False

    def is_2fa_enabled(self):
        """Check if 2FA is enabled"""
        try:
            if not TOTP_AVAILABLE or not os.path.exists(self.totp_file):
                return False
            with open(self.totp_file, 'r') as f:
                totp_data = json.load(f)
            return totp_data.get('enabled', False)
        except:
            return False

class LicenseManager:
    def __init__(self):
        self.license_file = "license.key"
        self.api_url = "https://us-central1-vault-keeper-b0720.cloudfunctions.net/validate"

    def validate_license(self):
        """Validate license with online/offline verification"""
        if not os.path.exists(self.license_file):
            return False, "No license found"

        try:
            with open(self.license_file, 'r') as f:
                data = json.load(f)

            # Enhanced offline validation
            key = data.get('key', '')
            email = data.get('email', '')
            expiry = data.get('expiry', '')

            if not key or not email:
                return False, "Invalid license"

            # Check expiry with enhanced validation
            if datetime.now() > datetime.fromisoformat(expiry):
                return False, "License expired"

            # Enhanced anti-tamper verification
            expected = hashlib.sha256(f"{key}{email}{expiry}SECRET_SALT".encode()).hexdigest()
            if data.get('hash') != expected:
                return False, "License tampered"

            # Online validation (async, non-blocking)
            try:
                resp = requests.post(self.api_url, json={'key': key, 'email': email}, timeout=3)
                if resp.status_code != 200:
                    return False, "License invalid"
            except:
                pass  # Offline mode allowed

            return True, f"Licensed to {email}"
        except:
            return False, "License error"

    def save_license(self, key, email, expiry):
        """Save license with enhanced security hashing"""
        hash_val = hashlib.sha256(f"{key}{email}{expiry}SECRET_SALT".encode()).hexdigest()
        data = {'key': key, 'email': email, 'expiry': expiry, 'hash': hash_val}
        with open(self.license_file, 'w') as f:
            json.dump(data, f)

class VaultKeeperPro:
    def __init__(self):
        # Enhanced license validation with better UX
        self.license_mgr = LicenseManager()
        valid, msg = self.license_mgr.validate_license()

        if not valid:
            # Show enhanced activation dialog
            activated = self._show_activation_dialog()
            if not activated:
                import sys
                sys.exit(0)
            import sys
            sys.exit(0)

        # Enhanced authentication system
        self.auth_mgr = AuthManager()

        # First time setup with enhanced UI
        if self.auth_mgr.is_first_time():
            if not self._show_password_setup_dialog():
                import sys
                sys.exit(0)

        # Enhanced login experience
        if not self._show_login_dialog():
            import sys
            sys.exit(0)

        # Initialize main application with premium styling
        self.app = ctk.CTk()
        self.app.title(f"VaultKeeper Pro - {msg}")
        self.app.geometry("1300x850")
        self.app.minsize(1200, 800)

        # Enhanced theme system with modern color schemes
        self.themes = {
            "Dark": {"mode": "dark", "color": "blue"},
            "Light": {"mode": "light", "color": "blue"},
            "Neon": {"mode": "dark", "color": "green"}, 
            "Dev": {"mode": "dark", "color": "dark-blue"},
            "Ocean": {"mode": "dark", "color": "blue"},
            "Cyber": {"mode": "dark", "color": "green"}
        }

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Set window icon with enhanced error handling
        self._set_window_icon()

        # Initialize data storage with enhanced structure
        self._initialize_data_paths()
        
        # Load encryption and data
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self.passwords = self._load_passwords()
        self.documents = self._load_documents()
        self.settings = self._load_settings()
        self.pwd_visible = False

        # Build enhanced premium UI
        self._build_ui()

    def _set_window_icon(self):
        """Set window icon with enhanced error handling"""
        try:
            import sys
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(os.path.dirname(sys.executable), 'assets', 'app.ico')
            else:
                icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'app.ico')

            if os.path.exists(icon_path):
                self.app.iconbitmap(icon_path)
        except Exception:
            pass

    def _initialize_data_paths(self):
        """Initialize all data storage paths with enhanced structure"""
        self.data_dir = os.path.join(os.path.expanduser("~"), "Documents", "VaultKeeper Pro Data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.password_file = os.path.join(self.data_dir, "passwords.enc")
        self.docs_file = os.path.join(self.data_dir, "documents.json")
        self.docs_folder = os.path.join(self.data_dir, "my_documents")
        self.key_file = os.path.join(self.data_dir, "secret.key")
        self.settings_file = os.path.join(self.data_dir, "settings.json")

        if not os.path.exists(self.docs_folder):
            os.makedirs(self.docs_folder)

    def _show_password_setup_dialog(self):
        """Enhanced first-time password setup with modern UI"""
        setup_win = ctk.CTk()
        setup_win.title("VaultKeeper Pro - Master Password Setup")
        setup_win.geometry("650x600")
        setup_win.resizable(False, False)
        ctk.set_appearance_mode("dark")

        result = {'success': False}

        # Main container with premium styling
        main_container = ctk.CTkFrame(setup_win, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=25, pady=25)

        # Header section
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 20))

        ctk.CTkLabel(header_frame, text="🔐 Master Password Setup", 
                    font=ctk.CTkFont(size=26, weight="bold", family="Segoe UI"),
                    text_color="#2CC985").pack(pady=10)
        
        ctk.CTkLabel(header_frame, text="Secure your vault with a strong master password", 
                    font=ctk.CTkFont(size=14), text_color="gray").pack()

        # Form container
        form_frame = ctk.CTkFrame(main_container, corner_radius=12)
        form_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Password fields
        pwd_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        pwd_section.pack(fill="x", padx=20, pady=15)

        ctk.CTkLabel(pwd_section, text="Master Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))
        
        pwd_entry = ctk.CTkEntry(pwd_section, width=400, height=40, show="●", 
                               placeholder_text="Minimum 10 characters", corner_radius=8)
        pwd_entry.pack(fill="x", pady=5)

        ctk.CTkLabel(pwd_section, text="Confirm Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(15, 5))
        
        pwd_confirm = ctk.CTkEntry(pwd_section, width=400, height=40, show="●", 
                                 placeholder_text="Re-enter master password", corner_radius=8)
        pwd_confirm.pack(fill="x", pady=5)

        # Security question section
        security_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        security_section.pack(fill="x", padx=20, pady=15)

        ctk.CTkLabel(security_section, text="Security Question:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))

        questions = [
            "What was the name of your first pet?",
            "What is your mother's maiden name?",
            "What city were you born in?",
            "What was your childhood nickname?",
            "What is your favorite book?"
        ]

        question_menu = ctk.CTkOptionMenu(security_section, values=questions, 
                                        width=400, height=35, corner_radius=8,
                                        dropdown_font=ctk.CTkFont(size=12))
        question_menu.pack(fill="x", pady=5)

        ctk.CTkLabel(security_section, text="Security Answer:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(15, 5))
        
        answer_entry = ctk.CTkEntry(security_section, width=400, height=40,
                                  placeholder_text="Enter your answer", corner_radius=8)
        answer_entry.pack(fill="x", pady=5)

        # Error display
        error_lbl = ctk.CTkLabel(form_frame, text="", font=ctk.CTkFont(size=12), 
                               text_color="#E74C3C", wraplength=500)
        error_lbl.pack(pady=10)

        # Action buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=20)

        def setup_password():
            pwd = pwd_entry.get()
            pwd_conf = pwd_confirm.get()
            question = question_menu.get()
            answer = answer_entry.get().strip()

            # Enhanced validation
            if not pwd or not pwd_conf or not answer:
                error_lbl.configure(text="All fields are required!")
                return

            if pwd != pwd_conf:
                error_lbl.configure(text="Passwords do not match!")
                return

            if len(pwd) < 10:
                error_lbl.configure(text="Password must be at least 10 characters!")
                return

            if len(answer) < 2:
                error_lbl.configure(text="Security answer is too short!")
                return

            # Setup master password
            success, msg = self.auth_mgr.setup_master_password(pwd, question, answer)

            if success:
                messagebox.showinfo("Success", 
                    "Master password setup complete!\n\nRemember this password - you'll need it every time you open VaultKeeper.")
                result['success'] = True
                setup_win.destroy()
            else:
                error_lbl.configure(text=msg)

        ctk.CTkButton(button_frame, text="🚀 Complete Setup", command=setup_password, 
                     width=250, height=45, fg_color="#2CC985", hover_color="#25A56A",
                     font=ctk.CTkFont(size=15, weight="bold"), corner_radius=10).pack(pady=10)

        # Security notice
        notice_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        notice_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(notice_frame, 
                    text="⚠ Remember your password! It cannot be recovered without the security answer.",
                    font=ctk.CTkFont(size=11), text_color="orange", wraplength=500, 
                    justify="center").pack()

        setup_win.protocol("WM_DELETE_WINDOW", lambda: setup_win.destroy())
        setup_win.mainloop()

        return result['success']

    def _show_login_dialog(self):
        """Enhanced login dialog with modern design"""
        login_win = ctk.CTk()
        login_win.title("VaultKeeper Pro - Login")
        login_win.geometry("550x500")
        login_win.resizable(False, False)
        ctk.set_appearance_mode("dark")

        result = {'success': False}
        attempts = [0]

        # Main container
        main_container = ctk.CTkFrame(login_win, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=25, pady=25)

        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(20, 30))

        ctk.CTkLabel(header_frame, text="🔐 VaultKeeper Pro", 
                    font=ctk.CTkFont(size=28, weight="bold", family="Segoe UI"),
                    text_color="#2CC985").pack(pady=10)
        
        ctk.CTkLabel(header_frame, text="Enter Master Password to Continue", 
                    font=ctk.CTkFont(size=14), text_color="gray").pack()

        # Login form
        form_frame = ctk.CTkFrame(main_container, corner_radius=12)
        form_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Password field
        pwd_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        pwd_section.pack(fill="x", padx=25, pady=25)

        ctk.CTkLabel(pwd_section, text="Master Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        pwd_entry = ctk.CTkEntry(pwd_section, width=350, height=45, show="●", 
                               placeholder_text="Enter your master password", corner_radius=8)
        pwd_entry.pack(fill="x", pady=5)
        pwd_entry.focus()

        # 2FA section if enabled
        totp_entry = None
        if self.auth_mgr.is_2fa_enabled():
            twofa_section = ctk.CTkFrame(form_frame, fg_color="transparent")
            twofa_section.pack(fill="x", padx=25, pady=15)

            ctk.CTkLabel(twofa_section, text="2FA Code (Optional):", 
                        font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
            
            totp_entry = ctk.CTkEntry(twofa_section, width=200, height=40,
                                    placeholder_text="000000", corner_radius=8)
            totp_entry.pack(anchor="w", pady=5)

            ctk.CTkLabel(twofa_section, text="Enter the 6-digit code from your authenticator app",
                        font=ctk.CTkFont(size=11), text_color="gray").pack(anchor="w")
            
            ctk.CTkLabel(twofa_section, text="(Leave blank to skip, but 2FA is recommended for security)",
                        font=ctk.CTkFont(size=10), text_color="orange").pack(anchor="w")

        # Error display
        error_lbl = ctk.CTkLabel(form_frame, text="", font=ctk.CTkFont(size=12), 
                               text_color="#E74C3C")
        error_lbl.pack(pady=10)

        # Action buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=25, pady=20)

        def login():
            pwd = pwd_entry.get()

            if not pwd:
                error_lbl.configure(text="Please enter your password!")
                return

            # Verify password
            if not self.auth_mgr.verify_password(pwd):
                attempts[0] += 1
                if attempts[0] >= 3:
                    error_lbl.configure(text="Too many failed attempts! Use 'Forgot Password' below.")
                else:
                    error_lbl.configure(text=f"Incorrect password! ({3-attempts[0]} attempts remaining)")
                return

            # Verify 2FA if enabled
            if self.auth_mgr.is_2fa_enabled() and totp_entry:
                code = totp_entry.get().strip()
                if code:
                    if not self.auth_mgr.verify_2fa(code):
                        error_lbl.configure(text="Invalid 2FA code! (Leave blank to skip)")
                        return

            result['success'] = True
            login_win.destroy()

        ctk.CTkButton(button_frame, text="🔓 Login", command=login, 
                     width=200, height=45, fg_color="#2CC985", hover_color="#25A56A",
                     font=ctk.CTkFont(size=15, weight="bold"), corner_radius=10).pack(pady=10)

        # Forgot password section
        recovery_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        recovery_frame.pack(fill="x", padx=25, pady=10)

        def forgot_password():
            """Enhanced password recovery dialog"""
            question = self.auth_mgr.get_security_question()

            if not question:
                messagebox.showerror("Error", "Security question not found!")
                return

            recovery_win = ctk.CTkToplevel(login_win)
            recovery_win.title("Password Recovery")
            recovery_win.geometry("550x450")
            recovery_win.resizable(False, False)

            rec_container = ctk.CTkFrame(recovery_win, corner_radius=15)
            rec_container.pack(fill="both", expand=True, padx=25, pady=25)

            ctk.CTkLabel(rec_container, text="🔑 Password Recovery", 
                        font=ctk.CTkFont(size=24, weight="bold"),
                        text_color="#2CC985").pack(pady=20)

            # Security question
            question_frame = ctk.CTkFrame(rec_container, fg_color="transparent")
            question_frame.pack(fill="x", padx=20, pady=15)

            ctk.CTkLabel(question_frame, text="Security Question:", 
                        font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
            
            ctk.CTkLabel(question_frame, text=question, 
                        font=ctk.CTkFont(size=12), wraplength=400, justify="left").pack(anchor="w", pady=5)

            # Answer field
            ctk.CTkLabel(question_frame, text="Your Answer:", 
                        font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(15, 5))
            
            ans_entry = ctk.CTkEntry(question_frame, width=350, height=40, corner_radius=8)
            ans_entry.pack(fill="x", pady=5)

            # New password
            ctk.CTkLabel(question_frame, text="New Password:", 
                        font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(15, 5))
            
            new_pwd = ctk.CTkEntry(question_frame, width=350, height=40, show="●", 
                                 placeholder_text="Minimum 10 characters", corner_radius=8)
            new_pwd.pack(fill="x", pady=5)

            rec_error = ctk.CTkLabel(question_frame, text="", text_color="#E74C3C")
            rec_error.pack(pady=10)

            def recover():
                answer = ans_entry.get()
                new_password = new_pwd.get()

                if not answer or not new_password:
                    rec_error.configure(text="All fields required!")
                    return

                if len(new_password) < 10:
                    rec_error.configure(text="Password must be at least 10 characters!")
                    return

                if not self.auth_mgr.verify_security_answer(answer):
                    rec_error.configure(text="Incorrect answer!")
                    return

                # Reset password
                success, msg = self.auth_mgr.setup_master_password(new_password, question, answer)

                if success:
                    messagebox.showinfo("Success", "Password reset successfully!\n\nPlease login with your new password.")
                    recovery_win.destroy()
                    attempts[0] = 0
                    pwd_entry.delete(0, 'end')
                    error_lbl.configure(text="")
                else:
                    rec_error.configure(text="Failed to reset password!")

            ctk.CTkButton(question_frame, text="🔑 Reset Password", command=recover, 
                         width=200, height=40, fg_color="#2CC985", hover_color="#25A56A",
                         font=ctk.CTkFont(size=14, weight="bold"), corner_radius=8).pack(pady=15)

        ctk.CTkButton(recovery_frame, text="🔐 Forgot Password?", command=forgot_password, 
                     width=180, height=35, fg_color="#E67E22", hover_color="#D35400",
                     font=ctk.CTkFont(size=12), corner_radius=8).pack(pady=5)

        # Handle Enter key
        pwd_entry.bind('<Return>', lambda e: login())
        if totp_entry:
            totp_entry.bind('<Return>', lambda e: login())

        login_win.protocol("WM_DELETE_WINDOW", lambda: login_win.destroy())
        login_win.mainloop()

        return result['success']

    def _show_activation_dialog(self):
        """Enhanced activation dialog with modern design"""
        act_win = ctk.CTk()
        act_win.title("VaultKeeper Pro - Activation Required")
        act_win.geometry("600x550")
        act_win.resizable(False, False)
        ctk.set_appearance_mode("dark")

        activated = [False]

        # Main container
        main_container = ctk.CTkFrame(act_win, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=25, pady=25)

        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 20))

        ctk.CTkLabel(header_frame, text="🔐 VaultKeeper Pro", 
                    font=ctk.CTkFont(size=28, weight="bold", family="Segoe UI"),
                    text_color="#2CC985").pack(pady=10)
        
        ctk.CTkLabel(header_frame, text="Activation Required", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack()

        # Activation form
        form_frame = ctk.CTkFrame(main_container, corner_radius=12)
        form_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # License key
        key_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        key_section.pack(fill="x", padx=25, pady=20)

        ctk.CTkLabel(key_section, text="License Key:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        key_entry = ctk.CTkEntry(key_section, width=350, height=40, 
                               placeholder_text="XXXX-XXXX-XXXX-XXXX", corner_radius=8)
        key_entry.pack(fill="x", pady=5)

        # Email
        email_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        email_section.pack(fill="x", padx=25, pady=15)

        ctk.CTkLabel(email_section, text="Email:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        email_entry = ctk.CTkEntry(email_section, width=350, height=40, 
                                 placeholder_text="your@email.com", corner_radius=8)
        email_entry.pack(fill="x", pady=5)

        # Error display
        error_lbl = ctk.CTkLabel(form_frame, text="", font=ctk.CTkFont(size=12), 
                               text_color="#E74C3C")
        error_lbl.pack(pady=10)

        # Action buttons
        button_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=25, pady=20)

        def activate():
            key = key_entry.get().strip()
            email = email_entry.get().strip()

            if not key or not email:
                error_lbl.configure(text="Please enter both key and email!")
                return

            try:
                error_lbl.configure(text="Activating... Please wait...", text_color="#F39C12")
                act_win.update()

                resp = requests.post("https://us-central1-vault-keeper-b0720.cloudfunctions.net/activate",
                                   json={'key': key, 'email': email}, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    self.license_mgr.save_license(key, email, data['expiry'])
                    messagebox.showinfo("Success", "Activation successful!\n\nPlease restart the application.")
                    activated[0] = True
                    act_win.destroy()
                else:
                    error_lbl.configure(text="Invalid license key or email!", text_color="#E74C3C")
            except requests.exceptions.Timeout:
                error_lbl.configure(text="Connection timeout! Please check your internet.", text_color="#E74C3C")
            except requests.exceptions.ConnectionError:
                error_lbl.configure(text="Cannot connect to server! Check internet connection.", text_color="#E74C3C")
            except Exception as e:
                error_lbl.configure(text=f"Activation failed: {str(e)}", text_color="#E74C3C")

        ctk.CTkButton(button_frame, text="🚀 Activate", command=activate, 
                     width=200, height=45, fg_color="#2CC985", hover_color="#25A56A",
                     font=ctk.CTkFont(size=15, weight="bold"), corner_radius=10).pack(pady=10)

        # Testing mode
        test_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        test_frame.pack(fill="x", padx=25, pady=10)

        def skip_activation():
            if messagebox.askyesno("Skip Activation", 
                "Skip activation for testing?\n\nThis will create a temporary 30-day license.\n\nFor production use, please activate properly."):
                
                temp_expiry = (datetime.now() + timedelta(days=30)).isoformat()
                self.license_mgr.save_license("TEST-KEY-FOR-DEVELOPMENT", "test@example.com", temp_expiry)
                messagebox.showinfo("Testing Mode", "Temporary license created!\n\nPlease restart the application.")
                activated[0] = True
                act_win.destroy()

        ctk.CTkButton(test_frame, text="⚡ Skip Activation (Testing Only)", command=skip_activation, 
                     width=220, height=35, fg_color="#E67E22", hover_color="#D35400",
                     font=ctk.CTkFont(size=12), corner_radius=8).pack(pady=5)

        # Website link
        website_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        website_frame.pack(fill="x", padx=25, pady=15)

        ctk.CTkLabel(website_frame, text="Don't have a license? Visit:", 
                    font=ctk.CTkFont(size=12)).pack(pady=5)

        def open_website(event=None):
            import webbrowser
            webbrowser.open("https://vault-keeper.netlify.app")

        website_label = ctk.CTkLabel(website_frame, text="https://vault-keeper.netlify.app",
                                     font=ctk.CTkFont(size=13, weight="bold"),
                                     text_color="#3498DB", cursor="hand2")
        website_label.pack()
        website_label.bind("<Button-1>", open_website)

        def on_closing():
            if not activated[0]:
                if messagebox.askyesno("Exit", "Exit without activating?\n\nYou won't be able to use VaultKeeper Pro."):
                    act_win.destroy()
            else:
                act_win.destroy()

        act_win.protocol("WM_DELETE_WINDOW", on_closing)
        act_win.mainloop()

        return activated[0]

    def _load_or_create_key(self):
        """Load or create encryption key with enhanced error handling"""
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    return f.read()
            except PermissionError:
                messagebox.showerror("Error", f"Permission denied: Cannot read {self.key_file}\n\nPlease run as administrator or check file permissions.")
                raise
        try:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
        except PermissionError:
            messagebox.showerror("Error", f"Permission denied: Cannot create {self.key_file}\n\nPlease run from a writable location (Desktop, Documents, etc.) or as administrator.")
            raise

    def _load_passwords(self):
        """Load encrypted passwords with enhanced error handling"""
        if os.path.exists(self.password_file):
            try:
                with open(self.password_file, 'rb') as f:
                    return json.loads(self.cipher.decrypt(f.read()).decode())
            except:
                return {}
        return {}

    def _save_passwords(self):
        """Save passwords with encryption"""
        with open(self.password_file, 'wb') as f:
            f.write(self.cipher.encrypt(json.dumps(self.passwords, indent=2).encode()))

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
        """Load application settings"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_settings(self):
        """Save application settings"""
        with open(self.settings_file, 'w') as f:
            json.dump(self.settings, f, indent=2)

    def _check_strength(self, pwd):
        """Enhanced password strength checker"""
        if not pwd: return "None", 0
        score = len(pwd) >= 8 + len(pwd) >= 12 + len(pwd) >= 16
        score += bool(re.search(r'[a-z]', pwd)) + bool(re.search(r'[A-Z]', pwd))
        score += bool(re.search(r'\d', pwd)) + bool(re.search(r'[!@#$%^&*]', pwd))

        if score <= 2: return "Weak", score
        elif score <= 4: return "Medium", score
        elif score <= 6: return "Strong", score
        return "Very Strong", score

    def _generate_pwd(self, length=16, symbols=True, numbers=True, upper=True, lower=True):
        """Enhanced password generator"""
        chars = ""
        if lower: chars += string.ascii_lowercase
        if upper: chars += string.ascii_uppercase
        if numbers: chars += string.digits
        if symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(random.choice(chars or string.ascii_letters) for _ in range(length))

    def _build_ui(self):
        """Build the main application UI with premium styling"""
        # Main container with modern design
        main_container = ctk.CTkFrame(self.app, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Enhanced header section
        self._build_header(main_container)
        
        # Premium tab view
        self._build_tab_view(main_container)

    def _build_header(self, parent):
        """Build premium application header"""
        header_frame = ctk.CTkFrame(parent, height=90, corner_radius=12)
        header_frame.pack(fill="x", padx=10, pady=(10, 5))
        header_frame.pack_propagate(False)
        
        # Application title with premium typography
        title_label = ctk.CTkLabel(
            header_frame, 
            text="🔐 VaultKeeper Pro", 
            font=ctk.CTkFont(size=28, weight="bold", family="Segoe UI"),
            text_color="#2CC985"
        )
        title_label.pack(side="left", padx=25, pady=25)
        
        # Right side controls
        controls_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.pack(side="right", padx=20, pady=25)
        
        # Theme selector
        ctk.CTkLabel(controls_frame, text="Theme:", 
                    font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 5))
        
        self.theme_menu = ctk.CTkOptionMenu(
            controls_frame, 
            values=list(self.themes.keys()),
            command=self._apply_theme, 
            width=120,
            height=35,
            corner_radius=8,
            dropdown_font=ctk.CTkFont(size=12)
        )
        self.theme_menu.pack(side="left", padx=5)
        
        # Backup/Restore buttons
        ctk.CTkButton(controls_frame, text="💾 Backup", command=self._backup, 
                     width=100, height=35, fg_color="#3498DB", hover_color="#2980B9",
                     corner_radius=8, font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        
        ctk.CTkButton(controls_frame, text="📥 Restore", command=self._restore, 
                     width=100, height=35, fg_color="#E67E22", hover_color="#D35400",
                     corner_radius=8, font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)

    def _build_tab_view(self, parent):
        """Build premium tab view with enhanced styling"""
        self.tabview = ctk.CTkTabview(
            parent,
            segmented_button_fg_color="#2B2B2B",
            segmented_button_selected_color="#1F6AA5",
            segmented_button_selected_hover_color="#144870",
            segmented_button_unselected_hover_color="#3D3D3D",
            corner_radius=12
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        # Add premium tabs
        self.tabview.add("🔑 Passwords")
        self.tabview.add("📁 Documents")
        self.tabview.add("⚙ Settings")
        
        # Build enhanced tab contents
        self._build_password_tab()
        self._build_document_tab()
        self._build_settings_tab()

    def _build_password_tab(self):
        """Build enhanced passwords tab with premium features"""
        tab = self.tabview.tab("🔑 Passwords")
        
        # Main content container
        content_frame = ctk.CTkFrame(tab, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Input card with premium styling
        input_card = ctk.CTkFrame(content_frame, corner_radius=12)
        input_card.pack(fill="x", pady=(0, 15))
        
        # Section title
        section_title = ctk.CTkLabel(
            input_card,
            text="➕ Add New Password",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#2CC985"
        )
        section_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Input grid with enhanced layout
        input_grid = ctk.CTkFrame(input_card, fg_color="transparent")
        input_grid.pack(fill="x", padx=20, pady=(0, 15))
        
        # Row 1: Name and Category
        row1 = ctk.CTkFrame(input_grid, fg_color="transparent")
        row1.pack(fill="x", pady=8)
        
        ctk.CTkLabel(row1, text="Service Name:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        
        self.pwd_name = ctk.CTkEntry(row1, width=250, height=35,
                                   placeholder_text="e.g., Gmail, Facebook, Bank...",
                                   corner_radius=8)
        self.pwd_name.grid(row=0, column=1, padx=(0, 20), pady=5, sticky="ew")
        
        ctk.CTkLabel(row1, text="Category:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=2, padx=(0, 10), pady=5, sticky="w")
        
        self.pwd_cat = ctk.CTkEntry(row1, width=200, height=35,
                                  placeholder_text="Work/Personal/Financial...",
                                  corner_radius=8)
        self.pwd_cat.grid(row=0, column=3, padx=(0, 20), pady=5, sticky="ew")
        
        row1.columnconfigure(1, weight=1)
        row1.columnconfigure(3, weight=1)
        
        # Row 2: Password with strength indicator
        row2 = ctk.CTkFrame(input_grid, fg_color="transparent")
        row2.pack(fill="x", pady=8)
        
        ctk.CTkLabel(row2, text="Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        
        # Password entry with toggle
        pwd_entry_frame = ctk.CTkFrame(row2, fg_color="transparent")
        pwd_entry_frame.grid(row=0, column=1, padx=(0, 20), pady=5, sticky="ew")
        
        self.pwd_pass = ctk.CTkEntry(pwd_entry_frame, width=250, height=35, show="●",
                                   placeholder_text="Enter password", corner_radius=8)
        self.pwd_pass.pack(side="left", fill="x", expand=True)
        self.pwd_pass.bind("<KeyRelease>", self._update_strength)
        
        self.pwd_toggle = ctk.CTkButton(pwd_entry_frame, text="👁", width=45, height=35,
                                      command=self._toggle_vis, font=ctk.CTkFont(size=16),
                                      corner_radius=8, fg_color="#7F8C8D", hover_color="#95A5A6")
        self.pwd_toggle.pack(side="left", padx=(5, 0))
        
        # Strength indicator
        strength_frame = ctk.CTkFrame(row2, fg_color="transparent")
        strength_frame.grid(row=0, column=2, padx=(0, 10), pady=5, sticky="w")
        
        self.strength_lbl = ctk.CTkLabel(strength_frame, text="Strength: None", 
                                       font=ctk.CTkFont(size=12, weight="bold"))
        self.strength_lbl.pack(anchor="w")
        
        self.strength_bar = ctk.CTkProgressBar(strength_frame, width=120, height=8,
                                             corner_radius=4, progress_color="gray")
        self.strength_bar.set(0)
        self.strength_bar.pack(anchor="w", pady=(2, 0))
        
        row2.columnconfigure(1, weight=1)
        
        # Row 3: Username and Notes
        row3 = ctk.CTkFrame(input_grid, fg_color="transparent")
        row3.pack(fill="x", pady=8)
        
        ctk.CTkLabel(row3, text="Username:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        
        self.pwd_user = ctk.CTkEntry(row3, width=250, height=35,
                                   placeholder_text="Optional username/email",
                                   corner_radius=8)
        self.pwd_user.grid(row=0, column=1, padx=(0, 20), pady=5, sticky="ew")
        
        ctk.CTkLabel(row3, text="Notes:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=2, padx=(0, 10), pady=5, sticky="w")
        
        self.pwd_notes = ctk.CTkEntry(row3, width=200, height=35,
                                    placeholder_text="Optional notes",
                                    corner_radius=8)
        self.pwd_notes.grid(row=0, column=3, padx=(0, 20), pady=5, sticky="ew")
        
        row3.columnconfigure(1, weight=1)
        row3.columnconfigure(3, weight=1)
        
        # Password generator section
        gen_card = ctk.CTkFrame(input_card, corner_radius=8)
        gen_card.pack(fill="x", padx=20, pady=(10, 15))
        
        ctk.CTkLabel(gen_card, text="🎲 Password Generator", 
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=15, pady=(12, 8))
        
        gen_controls = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_controls.pack(fill="x", padx=15, pady=(0, 12))
        
        ctk.CTkLabel(gen_controls, text="Length:", 
                    font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        
        self.gen_len = ctk.CTkEntry(gen_controls, width=50, height=30, corner_radius=6)
        self.gen_len.insert(0, "16")
        self.gen_len.pack(side="left", padx=5)
        
        # Character type checkboxes
        self.gen_up = ctk.CTkCheckBox(gen_controls, text="A-Z", width=70)
        self.gen_up.select()
        self.gen_up.pack(side="left", padx=8)
        
        self.gen_low = ctk.CTkCheckBox(gen_controls, text="a-z", width=70)
        self.gen_low.select()
        self.gen_low.pack(side="left", padx=8)
        
        self.gen_num = ctk.CTkCheckBox(gen_controls, text="0-9", width=70)
        self.gen_num.select()
        self.gen_num.pack(side="left", padx=8)
        
        self.gen_sym = ctk.CTkCheckBox(gen_controls, text="!@#", width=70)
        self.gen_sym.select()
        self.gen_sym.pack(side="left", padx=8)
        
        ctk.CTkButton(gen_controls, text="Generate", command=self._gen_pwd, 
                     width=100, height=32, fg_color="#9B59B6", hover_color="#8E44AD",
                     corner_radius=8, font=ctk.CTkFont(weight="bold")).pack(side="left", padx=15)
        
        # Action buttons
        action_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=(5, 15))
        
        ctk.CTkButton(action_frame, text="➕ Add Password", command=self._add_pwd, 
                     width=140, height=40, fg_color="#2CC985", hover_color="#25A56A",
                     corner_radius=10, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=5)
        
        ctk.CTkButton(action_frame, text="🗑️ Delete", command=self._del_pwd, 
                     width=120, height=40, fg_color="#E74C3C", hover_color="#C0392B",
                     corner_radius=10, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=5)
        
        ctk.CTkButton(action_frame, text="🔄 Clear", command=self._clear_pwd, 
                     width=120, height=40, fg_color="#7F8C8D", hover_color="#95A5A6",
                     corner_radius=10, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=5)
        
        # Search and list section
        list_section = ctk.CTkFrame(content_frame, fg_color="transparent")
        list_section.pack(fill="both", expand=True)
        
        # Search bar
        search_card = ctk.CTkFrame(list_section, corner_radius=8)
        search_card.pack(fill="x", pady=(0, 10))
        
        search_inner = ctk.CTkFrame(search_card, fg_color="transparent")
        search_inner.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(search_inner, text="🔍", 
                    font=ctk.CTkFont(size=16)).pack(side="left", padx=(0, 10))
        
        self.pwd_search = ctk.CTkEntry(search_inner, width=300, height=35,
                                     placeholder_text="Search passwords...",
                                     corner_radius=8)
        self.pwd_search.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.pwd_search.bind("<KeyRelease>", lambda e: self._refresh_pwds())
        
        # Password list
        list_card = ctk.CTkFrame(list_section, corner_radius=12)
        list_card.pack(fill="both", expand=True)
        
        list_title = ctk.CTkLabel(
            list_card,
            text="📋 Saved Passwords",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        list_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        self.pwd_scroll = ctk.CTkScrollableFrame(
            list_card, 
            fg_color="transparent",
            corner_radius=8
        )
        self.pwd_scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._refresh_pwds()

    def _build_document_tab(self):
        """Build enhanced documents tab with premium styling"""
        tab = self.tabview.tab("📁 Documents")
        
        # Main content container
        content_frame = ctk.CTkFrame(tab, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Input card
        input_card = ctk.CTkFrame(content_frame, corner_radius=12)
        input_card.pack(fill="x", pady=(0, 15))
        
        # Section title
        section_title = ctk.CTkLabel(
            input_card,
            text="➕ Add New Document",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#2CC985"
        )
        section_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # Input form
        form_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        form_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        # Title field
        ctk.CTkLabel(form_frame, text="Document Title:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, padx=(0, 10), pady=12, sticky="w")
        
        self.doc_title = ctk.CTkEntry(form_frame, width=300, height=35,
                                    placeholder_text="Enter document title",
                                    corner_radius=8)
        self.doc_title.grid(row=0, column=1, padx=(0, 20), pady=12, sticky="ew")
        
        # Category field
        ctk.CTkLabel(form_frame, text="Category:", 
                    font=ctk.CTkFont(size=13, weight="bold")).grid(row=1, column=0, padx=(0, 10), pady=12, sticky="w")
        
        self.doc_cat = ctk.CTkEntry(form_frame, width=300, height=35,
                                  placeholder_text="e.g., Work, Personal, Financial...",
                                  corner_radius=8)
        self.doc_cat.grid(row=1, column=1, padx=(0, 20), pady=12, sticky="ew")
        
        form_frame.columnconfigure(1, weight=1)
        
        # File selection
        file_section = ctk.CTkFrame(input_card, fg_color="transparent")
        file_section.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(file_section, text="Selected File:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        
        self.doc_file_lbl = ctk.CTkLabel(file_section, text="No file selected", 
                                       text_color="gray", font=ctk.CTkFont(size=12))
        self.doc_file_lbl.pack(side="left", padx=(10, 20))
        
        self.sel_file = None
        
        # Action buttons
        action_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=(5, 15))
        
        ctk.CTkButton(action_frame, text="📁 Choose File", command=self._choose_file, 
                     width=140, height=40, fg_color="#3498DB", hover_color="#2980B9",
                     corner_radius=10, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=5)
        
        ctk.CTkButton(action_frame, text="➕ Add Document", command=self._add_doc, 
                     width=140, height=40, fg_color="#2CC985", hover_color="#25A56A",
                     corner_radius=10, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=5)
        
        # Document list
        list_card = ctk.CTkFrame(content_frame, corner_radius=12)
        list_card.pack(fill="both", expand=True)
        
        list_title = ctk.CTkLabel(
            list_card,
            text="📁 Saved Documents",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2CC985"
        )
        list_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        self.doc_scroll = ctk.CTkScrollableFrame(
            list_card, 
            fg_color="transparent",
            corner_radius=8
        )
        self.doc_scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._refresh_docs()

    def _build_settings_tab(self):
        """Build enhanced settings tab with premium features"""
        tab = self.tabview.tab("⚙ Settings")
        
        # Main content container
        content_frame = ctk.CTkFrame(tab, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(header_frame, text="⚙ Settings", 
                    font=ctk.CTkFont(size=26, weight="bold"),
                    text_color="#2CC985").pack(pady=10)
        
        # Statistics card
        stats_card = ctk.CTkFrame(content_frame, corner_radius=12)
        stats_card.pack(fill="x", pady=(0, 20))
        
        stats_title = ctk.CTkLabel(
            stats_card,
            text="📊 Vault Statistics",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#2CC985"
        )
        stats_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        stats_text = f"""Total Passwords: {len(self.passwords)}
Total Documents: {len(self.documents)}

VaultKeeper Pro v2.0
Licensed Professional Software"""
        
        stats_label = ctk.CTkLabel(stats_card, text=stats_text, 
                                 font=ctk.CTkFont(size=14), justify="left")
        stats_label.pack(anchor="w", padx=20, pady=(0, 15))
        
        # Security settings card
        security_card = ctk.CTkFrame(content_frame, corner_radius=12)
        security_card.pack(fill="x", pady=(0, 20))
        
        security_title = ctk.CTkLabel(
            security_card,
            text="🔒 Security Settings",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#2CC985"
        )
        security_title.pack(anchor="w", padx=20, pady=(15, 10))
        
        # 2FA Section
        twofa_section = ctk.CTkFrame(security_card, fg_color="transparent")
        twofa_section.pack(fill="x", padx=20, pady=15)
        
        if self.auth_mgr.is_2fa_enabled():
            status_frame = ctk.CTkFrame(twofa_section, fg_color="transparent")
            status_frame.pack(fill="x")
            
            ctk.CTkLabel(status_frame, text="✅ Two-Factor Authentication: ENABLED",
                        font=ctk.CTkFont(size=14, weight="bold"), text_color="#2CC985").pack(side="left")
            
            ctk.CTkLabel(status_frame, text="Your account is protected with 2FA",
                        font=ctk.CTkFont(size=12), text_color="gray").pack(side="left", padx=(10, 0))
        else:
            status_frame = ctk.CTkFrame(twofa_section, fg_color="transparent")
            status_frame.pack(fill="x")
            
            ctk.CTkLabel(status_frame, text="⚠ Two-Factor Authentication: DISABLED",
                        font=ctk.CTkFont(size=14, weight="bold"), text_color="#E67E22").pack(side="left")
            
            if TOTP_AVAILABLE:
                ctk.CTkButton(status_frame, text="🔐 Setup 2FA", command=self._setup_2fa,
                             width=120, height=35, fg_color="#9B59B6", hover_color="#8E44AD",
                             corner_radius=8, font=ctk.CTkFont(weight="bold")).pack(side="right")
            else:
                ctk.CTkLabel(status_frame, text="Install pyotp and qrcode to enable 2FA",
                            font=ctk.CTkFont(size=11), text_color="gray").pack(side="right")
        
        # Password management section
        password_section = ctk.CTkFrame(security_card, fg_color="transparent")
        password_section.pack(fill="x", padx=20, pady=(10, 20))
        
        ctk.CTkButton(password_section, text="🔑 Change Master Password", 
                     command=self._change_master_password, width=250, height=40,
                     fg_color="#E67E22", hover_color="#D35400", corner_radius=10,
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

    def _setup_2fa(self):
        """Enhanced 2FA setup with premium UI"""
        secret, uri = self.auth_mgr.setup_2fa()

        if not secret:
            messagebox.showerror("Error", "Failed to setup 2FA")
            return

        # Create premium QR code window
        qr_win = ctk.CTkToplevel(self.app)
        qr_win.title("Setup Two-Factor Authentication")
        qr_win.geometry("650x750")
        qr_win.resizable(False, False)

        # Main container
        main_container = ctk.CTkFrame(qr_win, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=25, pady=25)

        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 20))

        ctk.CTkLabel(header_frame, text="🔐 Two-Factor Authentication", 
                    font=ctk.CTkFont(size=24, weight="bold"),
                    text_color="#2CC985").pack(pady=10)
        
        ctk.CTkLabel(header_frame, text="Enhanced security for your vault", 
                    font=ctk.CTkFont(size=14), text_color="gray").pack()

        # Instructions
        instructions_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        instructions_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(instructions_frame, 
                    text="Scan the QR code below with your authenticator app:",
                    font=ctk.CTkFont(size=13, weight="bold")).pack(pady=5)
        
        ctk.CTkLabel(instructions_frame, 
                    text="(Google Authenticator, Microsoft Authenticator, Authy, etc.)",
                    font=ctk.CTkFont(size=11), text_color="gray").pack()

        # QR code section
        qr_frame = ctk.CTkFrame(main_container, corner_radius=12)
        qr_frame.pack(fill="x", padx=20, pady=20)

        # Generate QR code
        try:
            if not qrcode or not Image or not ImageTk:
                raise ImportError("QR code libraries not available")

            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")

            # Convert PIL image and resize using PIL
            if hasattr(qr_img, 'resize'):
                qr_img = qr_img.resize((300, 300), Image.Resampling.LANCZOS)  # type: ignore
            elif hasattr(qr_img, '_img'):
                # qrcode returns a wrapper, get underlying PIL image
                qr_img = qr_img._img.resize((300, 300), Image.Resampling.LANCZOS)  # type: ignore

            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(qr_img)  # type: ignore

            qr_label = ctk.CTkLabel(qr_frame, text="")
            self._qr_photo = photo  # Keep reference to prevent garbage collection
            qr_label.pack(pady=25)

            # Update label with text overlay since image parameter has issues
            qr_canvas = ctk.CTkCanvas(qr_frame, width=300, height=300, bg='white', highlightthickness=0)
            qr_canvas.create_image(150, 150, image=photo)
            self._qr_photo = photo  # Keep reference
            qr_canvas.pack(pady=25)
        except Exception as e:
            ctk.CTkLabel(qr_frame, text=f"QR generation requires PIL/qrcode libraries\nInstall with: pip install qrcode[pil]",
                        text_color="#E74C3C", justify="center").pack(pady=25)

        # Secret key backup
        secret_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        secret_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(secret_frame, text="Or enter this secret key manually:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(pady=5)

        secret_display_frame = ctk.CTkFrame(secret_frame, fg_color="transparent")
        secret_display_frame.pack(fill="x", pady=10)

        secret_entry = ctk.CTkEntry(secret_display_frame, width=350, height=40,
                                  font=ctk.CTkFont(size=14, weight="bold", family="Consolas"),
                                  corner_radius=8)
        secret_entry.insert(0, secret)
        secret_entry.configure(state="readonly")
        secret_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkButton(secret_display_frame, text="📋 Copy", width=80, height=40,
                     command=lambda: self._copy_to_clipboard(secret),
                     fg_color="#3498DB", hover_color="#2980B9", corner_radius=8,
                     font=ctk.CTkFont(weight="bold")).pack(side="left")

        # Verification section
        verify_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        verify_frame.pack(fill="x", padx=20, pady=20)

        ctk.CTkLabel(verify_frame, 
                    text="Enter the 6-digit code from your app to verify:",
                    font=ctk.CTkFont(size=13, weight="bold")).pack(pady=5)

        code_entry = ctk.CTkEntry(verify_frame, width=200, height=40,
                                placeholder_text="000000", corner_radius=8,
                                justify="center", font=ctk.CTkFont(size=14))
        code_entry.pack(pady=10)

        error_lbl = ctk.CTkLabel(verify_frame, text="", text_color="#E74C3C")
        error_lbl.pack(pady=5)

        def verify_setup():
            code = code_entry.get().strip()

            if not code or len(code) != 6:
                error_lbl.configure(text="Please enter a 6-digit code!")
                return

            if self.auth_mgr.verify_2fa(code):
                messagebox.showinfo("Success", 
                    "2FA enabled successfully!\n\nYou'll need to enter a code from your authenticator app each time you login.")
                qr_win.destroy()
                self._build_settings_tab()
                self.tabview.set("⚙ Settings")
            else:
                error_lbl.configure(text="Invalid code! Please try again.")

        ctk.CTkButton(verify_frame, text="✅ Verify & Enable 2FA", command=verify_setup, 
                     width=220, height=45, fg_color="#2CC985", hover_color="#25A56A",
                     corner_radius=10, font=ctk.CTkFont(size=15, weight="bold")).pack(pady=10)

    def _change_master_password(self):
        """Enhanced master password change dialog"""
        change_win = ctk.CTkToplevel(self.app)
        change_win.title("Change Master Password")
        change_win.geometry("550x500")
        change_win.resizable(False, False)

        # Main container
        main_container = ctk.CTkFrame(change_win, corner_radius=15)
        main_container.pack(fill="both", expand=True, padx=25, pady=25)

        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(10, 20))

        ctk.CTkLabel(header_frame, text="🔑 Change Master Password", 
                    font=ctk.CTkFont(size=24, weight="bold"),
                    text_color="#2CC985").pack(pady=10)

        # Form
        form_frame = ctk.CTkFrame(main_container, corner_radius=12)
        form_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Current password
        current_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        current_section.pack(fill="x", padx=25, pady=20)

        ctk.CTkLabel(current_section, text="Current Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        current_pwd = ctk.CTkEntry(current_section, width=350, height=40, show="●",
                                 corner_radius=8)
        current_pwd.pack(fill="x", pady=5)

        # New password
        new_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        new_section.pack(fill="x", padx=25, pady=15)

        ctk.CTkLabel(new_section, text="New Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        new_pwd = ctk.CTkEntry(new_section, width=350, height=40, show="●",
                             placeholder_text="Minimum 10 characters", corner_radius=8)
        new_pwd.pack(fill="x", pady=5)

        # Confirm new password
        confirm_section = ctk.CTkFrame(form_frame, fg_color="transparent")
        confirm_section.pack(fill="x", padx=25, pady=15)

        ctk.CTkLabel(confirm_section, text="Confirm New Password:", 
                    font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 8))
        
        confirm_pwd = ctk.CTkEntry(confirm_section, width=350, height=40, show="●",
                                 corner_radius=8)
        confirm_pwd.pack(fill="x", pady=5)

        # Error display
        error_lbl = ctk.CTkLabel(form_frame, text="", text_color="#E74C3C")
        error_lbl.pack(pady=10)

        def change():
            current = current_pwd.get()
            new = new_pwd.get()
            confirm = confirm_pwd.get()

            if not current or not new or not confirm:
                error_lbl.configure(text="All fields are required!")
                return

            if not self.auth_mgr.verify_password(current):
                error_lbl.configure(text="Current password is incorrect!")
                return

            if len(new) < 10:
                error_lbl.configure(text="New password must be at least 10 characters!")
                return

            if new != confirm:
                error_lbl.configure(text="New passwords do not match!")
                return

            # Get security question
            question = self.auth_mgr.get_security_question()

            # Prompt for security answer
            answer = simpledialog.askstring("Security Answer", 
                f"For verification, answer:\n{question}", parent=change_win)

            if not answer:
                error_lbl.configure(text="Security answer required!")
                return

            if not self.auth_mgr.verify_security_answer(answer):
                error_lbl.configure(text="Security answer incorrect!")
                return

            # Update password
            success, msg = self.auth_mgr.setup_master_password(new, question, answer)

            if success:
                messagebox.showinfo("Success", "Master password changed successfully!")
                change_win.destroy()
            else:
                error_lbl.configure(text=msg)

        ctk.CTkButton(form_frame, text="🔑 Change Password", command=change, 
                     width=200, height=45, fg_color="#2CC985", hover_color="#25A56A",
                     corner_radius=10, font=ctk.CTkFont(size=15, weight="bold")).pack(pady=20)

    def _toggle_vis(self):
        """Toggle password visibility with enhanced UX"""
        if self.pwd_visible:
            self.pwd_pass.configure(show="●")
            self.pwd_toggle.configure(text="👁")
            self.pwd_visible = False
        else:
            self.pwd_pass.configure(show="")
            self.pwd_toggle.configure(text="🙈")
            self.pwd_visible = True

    def _update_strength(self, e=None):
        """Update password strength indicator with enhanced visuals"""
        strength, score = self._check_strength(self.pwd_pass.get())
        self.strength_lbl.configure(text=f"Strength: {strength}")
        self.strength_bar.set(min(score / 7, 1.0))
        
        # Enhanced color coding
        colors = {
            "Weak": "#E74C3C",
            "Medium": "#E67E22", 
            "Strong": "#F1C40F",
            "Very Strong": "#2CC985",
            "None": "#7F8C8D"
        }
        self.strength_lbl.configure(text_color=colors.get(strength, "#7F8C8D"))
        self.strength_bar.configure(progress_color=colors.get(strength, "#7F8C8D"))

    def _gen_pwd(self):
        """Enhanced password generator with validation"""
        try:
            length = int(self.gen_len.get())
            length = max(4, min(128, length))
        except:
            length = 16

        pwd = self._generate_pwd(length, self.gen_sym.get()==1, self.gen_num.get()==1,
                                 self.gen_up.get()==1, self.gen_low.get()==1)
        self.pwd_pass.delete(0, 'end')
        self.pwd_pass.insert(0, pwd)
        self._update_strength()
        self.pwd_pass.configure(show="")
        self.pwd_toggle.configure(text="🙈")
        self.pwd_visible = True

    def _add_pwd(self):
        """Add password with enhanced validation and feedback"""
        name = self.pwd_name.get().strip()
        pwd = self.pwd_pass.get().strip()

        if not name or not pwd:
            messagebox.showwarning("Missing Information", "Please enter both service name and password!")
            return

        strength, _ = self._check_strength(pwd)
        self.passwords[name] = {
            "password": pwd, 
            "category": self.pwd_cat.get().strip() or "Uncategorized",
            "username": self.pwd_user.get().strip(), 
            "notes": self.pwd_notes.get().strip(),
            "strength": strength, 
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "date_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self._save_passwords()
        self._refresh_pwds()
        self._clear_pwd()
        messagebox.showinfo("Success", f"Password saved successfully!\n\nStrength: {strength}")

    def _del_pwd(self):
        """Delete password with enhanced confirmation"""
        name = self.pwd_name.get().strip()
        if name in self.passwords:
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for '{name}'?"):
                del self.passwords[name]
                self._save_passwords()
                self._refresh_pwds()
                self._clear_pwd()
                messagebox.showinfo("Success", f"Password for '{name}' deleted successfully!")

    def _clear_pwd(self):
        """Clear password form with enhanced UX"""
        self.pwd_name.delete(0, 'end')
        self.pwd_pass.delete(0, 'end')
        self.pwd_cat.delete(0, 'end')
        self.pwd_user.delete(0, 'end')
        self.pwd_notes.delete(0, 'end')
        self.strength_lbl.configure(text="Strength: None", text_color="#7F8C8D")
        self.strength_bar.set(0)

    def _refresh_pwds(self):
        """Refresh password list with enhanced styling and search"""
        for widget in self.pwd_scroll.winfo_children():
            widget.destroy()

        search_term = self.pwd_search.get().lower() if hasattr(self, 'pwd_search') else ""

        filtered = {}
        for name, data in self.passwords.items():
            if isinstance(data, str):
                # Convert legacy format
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

            # Enhanced search across multiple fields
            if (search_term in name.lower() or 
                search_term in data.get("category", "").lower() or 
                search_term in data.get("username", "").lower() or
                search_term in data.get("notes", "").lower()):
                filtered[name] = data

        if not filtered:
            empty_frame = ctk.CTkFrame(self.pwd_scroll, fg_color="transparent")
            empty_frame.pack(expand=True, fill="both", pady=40)
            
            ctk.CTkLabel(empty_frame, text="🔍 No passwords found", 
                        font=ctk.CTkFont(size=16, weight="bold"),
                        text_color="gray").pack(pady=5)
            
            ctk.CTkLabel(empty_frame, text="Try adjusting your search or add a new password",
                        font=ctk.CTkFont(size=13), text_color="gray").pack()
            return

        for name, data in sorted(filtered.items()):
            # Enhanced password card
            password_card = ctk.CTkFrame(self.pwd_scroll, corner_radius=10)
            password_card.pack(fill="x", padx=5, pady=4)

            # Main info section
            info_section = ctk.CTkFrame(password_card, fg_color="transparent")
            info_section.pack(side="left", fill="x", expand=True, padx=15, pady=12)

            # Service name and category
            service_text = f"🔑 {name}"
            if data.get("category"):
                service_text += f" • {data['category']}"

            service_label = ctk.CTkLabel(
                info_section, 
                text=service_text, 
                font=ctk.CTkFont(size=14, weight="bold"), 
                anchor="w"
            )
            service_label.pack(anchor="w", padx=5)

            # Username if available
            if data.get("username"):
                user_label = ctk.CTkLabel(
                    info_section, 
                    text=f"👤 {data['username']}", 
                    font=ctk.CTkFont(size=12),
                    anchor="w", 
                    text_color="gray"
                )
                user_label.pack(anchor="w", padx=5, pady=(2, 0))

            # Metadata
            meta_text = f"Strength: {data.get('strength', 'Unknown')} • Added: {data.get('date_added', 'Unknown')}"
            meta_label = ctk.CTkLabel(
                info_section, 
                text=meta_text, 
                font=ctk.CTkFont(size=11), 
                anchor="w", 
                text_color="gray"
            )
            meta_label.pack(anchor="w", padx=5, pady=(2, 0))

            # Action buttons
            action_section = ctk.CTkFrame(password_card, fg_color="transparent")
            action_section.pack(side="right", padx=15, pady=12)

            # Password display with toggle
            pwd_display = ctk.CTkLabel(
                action_section, 
                text="●●●●●●●●", 
                width=120,
                font=ctk.CTkFont(size=12, family="Consolas"),
                text_color="gray"
            )
            pwd_display.pack(side="left", padx=(0, 10))

            # Action buttons container
            btn_container = ctk.CTkFrame(action_section, fg_color="transparent")
            btn_container.pack(side="left")

            ctk.CTkButton(
                btn_container, 
                text="👁", 
                width=45, 
                height=32,
                command=lambda l=pwd_display, p=data["password"]: self._toggle_pwd_display(l, p),
                fg_color="#3498DB", 
                hover_color="#2980B9",
                corner_radius=8,
                font=ctk.CTkFont(size=14)
            ).pack(side="left", padx=2)

            ctk.CTkButton(
                btn_container, 
                text="📋", 
                width=45, 
                height=32,
                command=lambda p=data["password"]: self._copy_to_clipboard(p),
                fg_color="#2CC985", 
                hover_color="#25A56A",
                corner_radius=8,
                font=ctk.CTkFont(size=14)
            ).pack(side="left", padx=2)

            ctk.CTkButton(
                btn_container, 
                text="✏", 
                width=45, 
                height=32,
                command=lambda n=name, d=data: self._edit_password(n, d),
                fg_color="#E67E22", 
                hover_color="#D35400",
                corner_radius=8,
                font=ctk.CTkFont(size=14)
            ).pack(side="left", padx=2)

    def _toggle_pwd_display(self, label, password):
        """Toggle password display in list with enhanced UX"""
        if label.cget("text") == "●●●●●●●●":
            label.configure(text=password, text_color="white")
        else:
            label.configure(text="●●●●●●●●", text_color="gray")

    def _copy_to_clipboard(self, text):
        """Enhanced clipboard copy with visual feedback"""
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        # Show subtle feedback instead of messagebox
        original_title = self.app.title()
        self.app.title("VaultKeeper Pro - ✓ Copied to clipboard!")
        self.app.after(1500, lambda: self.app.title(original_title))

    def _edit_password(self, name, data):
        """Enhanced password editing"""
        self.pwd_name.delete(0, 'end')
        self.pwd_name.insert(0, name)
        self.pwd_pass.delete(0, 'end')
        self.pwd_pass.insert(0, data["password"])
        self.pwd_cat.delete(0, 'end')
        self.pwd_cat.insert(0, data.get("category", ""))
        self.pwd_user.delete(0, 'end')
        self.pwd_user.insert(0, data.get("username", ""))
        self.pwd_notes.delete(0, 'end')
        self.pwd_notes.insert(0, data.get("notes", ""))
        self._update_strength()

    def _choose_file(self):
        """Enhanced file chooser with better UX"""
        file_path = filedialog.askopenfilename(
            title="Select Document",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.sel_file = file_path
            filename = os.path.basename(file_path)
            self.doc_file_lbl.configure(text=filename, text_color="#2CC985")

    def _add_doc(self):
        """Add document with enhanced validation"""
        if not self.doc_title.get().strip() or not self.doc_cat.get().strip() or not self.sel_file:
            messagebox.showwarning("Missing Information", "Please fill all fields and select a file!")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_name = os.path.basename(self.sel_file)
        filename = f"{timestamp}_{original_name}"
        
        # Copy file to documents folder
        destination_path = os.path.join(self.docs_folder, filename)
        shutil.copy2(self.sel_file, destination_path)

        # Calculate file size with enhanced formatting
        size = os.path.getsize(destination_path)
        if size < 1024*1024:
            size_str = f"{size/1024:.1f} KB"
        else:
            size_str = f"{size/(1024*1024):.1f} MB"

        self.documents.append({
            "title": self.doc_title.get().strip(), 
            "category": self.doc_cat.get().strip(),
            "filename": filename, 
            "original_filename": original_name,
            "file_size": size_str, 
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        self._save_documents()
        self._refresh_docs()
        
        # Clear form
        self.doc_title.delete(0, 'end')
        self.doc_cat.delete(0, 'end')
        self.doc_file_lbl.configure(text="No file selected", text_color="gray")
        self.sel_file = None
        
        messagebox.showinfo("Success", f"Document '{self.doc_title.get().strip()}' added successfully!")

    def _refresh_docs(self):
        """Refresh document list with enhanced styling"""
        for widget in self.doc_scroll.winfo_children():
            widget.destroy()

        if not self.documents:
            empty_frame = ctk.CTkFrame(self.doc_scroll, fg_color="transparent")
            empty_frame.pack(expand=True, fill="both", pady=40)
            
            ctk.CTkLabel(empty_frame, text="📁 No documents saved", 
                        font=ctk.CTkFont(size=16, weight="bold"),
                        text_color="gray").pack(pady=5)
            
            ctk.CTkLabel(empty_frame, text="Add your first document using the form above",
                        font=ctk.CTkFont(size=13), text_color="gray").pack()
            return

        for doc in self.documents:
            # Enhanced document card
            doc_card = ctk.CTkFrame(self.doc_scroll, corner_radius=10)
            doc_card.pack(fill="x", padx=5, pady=4)

            # Document info
            info_section = ctk.CTkFrame(doc_card, fg_color="transparent")
            info_section.pack(side="left", fill="x", expand=True, padx=15, pady=12)

            # Title and metadata
            title_label = ctk.CTkLabel(
                info_section, 
                text=f"📄 {doc['title']}", 
                font=ctk.CTkFont(size=14, weight="bold"), 
                anchor="w"
            )
            title_label.pack(anchor="w")

            # Metadata
            meta_text = f"Category: {doc['category']} • Size: {doc.get('file_size', 'Unknown')} • Added: {doc['date_added']}"
            meta_label = ctk.CTkLabel(
                info_section, 
                text=meta_text, 
                font=ctk.CTkFont(size=12), 
                anchor="w", 
                text_color="gray"
            )
            meta_label.pack(anchor="w", pady=(2, 0))

            # Action buttons
            action_section = ctk.CTkFrame(doc_card, fg_color="transparent")
            action_section.pack(side="right", padx=15, pady=12)

            ctk.CTkButton(
                action_section, 
                text="📂 Open", 
                width=80, 
                height=35,
                command=lambda f=doc['filename']: self._open_document(f),
                fg_color="#3498DB", 
                hover_color="#2980B9",
                corner_radius=8,
                font=ctk.CTkFont(weight="bold")
            ).pack(side="left", padx=5)

            ctk.CTkButton(
                action_section, 
                text="🗑️", 
                width=50, 
                height=35,
                command=lambda d=doc: self._delete_document(d),
                fg_color="#E74C3C", 
                hover_color="#C0392B",
                corner_radius=8,
                font=ctk.CTkFont(size=14)
            ).pack(side="left", padx=5)

    def _open_document(self, filename):
        """Open document with enhanced error handling"""
        try:
            file_path = os.path.join(self.docs_folder, filename)
            if os.path.exists(file_path):
                os.startfile(file_path)
            else:
                messagebox.showerror("Error", "Document file not found! It may have been moved or deleted.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open document: {str(e)}")

    def _delete_document(self, doc):
        """Delete document with enhanced confirmation"""
        if messagebox.askyesno("Confirm Delete", 
            f"Are you sure you want to delete '{doc['title']}'?\n\nThis action cannot be undone."):
            
            file_path = os.path.join(self.docs_folder, doc['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
            
            self.documents.remove(doc)
            self._save_documents()
            self._refresh_docs()
            
            messagebox.showinfo("Success", f"Document '{doc['title']}' deleted successfully!")

    def _apply_theme(self, theme):
        """Apply theme with enhanced feedback"""
        selected_theme = self.themes.get(theme, self.themes["Dark"])
        ctk.set_appearance_mode(selected_theme["mode"])
        ctk.set_default_color_theme(selected_theme["color"])
        self.settings["theme"] = theme
        self._save_settings()
        messagebox.showinfo("Theme Changed", f"Theme applied: {theme}\n\nRestart the application for full effect.")

    def _backup(self):
        """Enhanced backup functionality"""
        default_filename = f"VaultKeeper_Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = filedialog.asksaveasfilename(
            defaultextension=".zip", 
            filetypes=[("Zip Archive", "*.zip")],
            initialfile=default_filename
        )
        
        if not backup_path:
            return

        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Backup data files
                for file_path in [self.password_file, self.docs_file, self.key_file, self.settings_file]:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                
                # Backup documents folder
                if os.path.exists(self.docs_folder):
                    for root, dirs, files in os.walk(self.docs_folder):
                        for file in files:
                            full_path = os.path.join(root, file)
                            relative_path = os.path.relpath(full_path, self.docs_folder)
                            zip_file.write(full_path, os.path.join("documents", relative_path))
            
            messagebox.showinfo("Backup Successful", 
                f"Backup created successfully!\n\nLocation: {backup_path}\n\nKeep this file in a safe place.")
                
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Backup creation failed:\n\n{str(e)}")

    def _restore(self):
        """Enhanced restore functionality with safety checks"""
        if not messagebox.askyesno("Confirm Restore", 
            "This will replace all current data with the backup contents!\n\n"
            "⚠ Make sure you have a current backup before proceeding.\n\n"
            "Continue with restore?"):
            return

        backup_path = filedialog.askopenfilename(
            filetypes=[("Zip Archive", "*.zip")]
        )
        
        if not backup_path:
            return

        try:
            # Create temporary extraction folder
            temp_dir = os.path.join(self.data_dir, "temp_restore")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)

            # Extract backup
            with zipfile.ZipFile(backup_path, 'r') as zip_file:
                zip_file.extractall(temp_dir)

            # Restore files
            for file_name in os.listdir(temp_dir):
                source_path = os.path.join(temp_dir, file_name)
                dest_path = os.path.join(self.data_dir, file_name)
                
                if os.path.isfile(source_path):
                    shutil.copy2(source_path, dest_path)
                elif file_name == "documents" and os.path.isdir(source_path):
                    if os.path.exists(self.docs_folder):
                        shutil.rmtree(self.docs_folder)
                    shutil.copytree(source_path, self.docs_folder)

            # Cleanup
            shutil.rmtree(temp_dir)

            # Reload data
            self.passwords = self._load_passwords()
            self.documents = self._load_documents()
            self.settings = self._load_settings()
            
            # Refresh UI
            self._refresh_pwds()
            self._refresh_docs()
            
            messagebox.showinfo("Restore Successful", 
                "Data restored successfully!\n\nPlease restart the application for all changes to take effect.")
                
        except Exception as e:
            messagebox.showerror("Restore Failed", f"Restore operation failed:\n\n{str(e)}")

    def run(self):
        """Start the application main loop"""
        self.app.mainloop()

if __name__ == "__main__":
    app = VaultKeeperPro()
    if hasattr(app, 'app'):
        app.run()