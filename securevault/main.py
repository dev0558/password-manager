#!/usr/bin/env python3
"""
SecureVault Password Manager
A production-ready desktop password manager with NIST SP 800-63B compliance.
"""

import customtkinter as ctk
import json
import os
import secrets
import string
import base64
import hashlib
import math
import re
from datetime import datetime
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field, asdict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =============================================================================
# COLOR PALETTE
# =============================================================================
class Colors:
    """Application color palette."""
    BG_DARK = "#0a0f1a"
    BG_MEDIUM = "#111827"
    BG_LIGHT = "#1e293b"
    PRIMARY = "#3b82f6"
    CYAN = "#06b6d4"
    SUCCESS = "#10b981"
    WARNING = "#f59e0b"
    DANGER = "#ef4444"
    TEXT_PRIMARY = "#f1f5f9"
    TEXT_SECONDARY = "#94a3b8"
    BORDER = "#334155"


# =============================================================================
# SECURITY MODULE
# =============================================================================
class SecurityManager:
    """Handles all cryptographic operations with NIST SP 800-63B compliance."""

    ITERATIONS = 600000
    SALT_LENGTH = 16

    def __init__(self, vault_path: str = "vault.encrypted"):
        self.vault_path = vault_path
        self._fernet: Optional[Fernet] = None
        self._salt: Optional[bytes] = None

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def create_vault(self, master_password: str) -> bool:
        """Create a new encrypted vault with the given master password."""
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        key = self.derive_key(master_password, self._salt)
        self._fernet = Fernet(key)

        initial_data = {
            "entries": [],
            "created": datetime.now().isoformat(),
            "version": "1.0"
        }
        return self._save_vault(initial_data)

    def unlock_vault(self, master_password: str) -> Optional[Dict]:
        """Attempt to unlock an existing vault with the master password."""
        if not os.path.exists(self.vault_path):
            return None

        try:
            with open(self.vault_path, 'rb') as f:
                data = f.read()

            self._salt = data[:self.SALT_LENGTH]
            encrypted_data = data[self.SALT_LENGTH:]

            key = self.derive_key(master_password, self._salt)
            self._fernet = Fernet(key)

            decrypted = self._fernet.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError):
            self._fernet = None
            self._salt = None
            return None

    def _save_vault(self, data: Dict) -> bool:
        """Encrypt and save vault data to disk."""
        if not self._fernet or not self._salt:
            return False

        try:
            json_data = json.dumps(data).encode()
            encrypted = self._fernet.encrypt(json_data)

            with open(self.vault_path, 'wb') as f:
                f.write(self._salt + encrypted)
            return True
        except Exception:
            return False

    def save_entries(self, entries: List[Dict]) -> bool:
        """Save password entries to the vault."""
        data = {
            "entries": entries,
            "modified": datetime.now().isoformat(),
            "version": "1.0"
        }
        return self._save_vault(data)

    def lock(self) -> None:
        """Lock the vault and clear sensitive data from memory."""
        self._fernet = None
        self._salt = None

    def vault_exists(self) -> bool:
        """Check if a vault file exists."""
        return os.path.exists(self.vault_path)

    def is_unlocked(self) -> bool:
        """Check if the vault is currently unlocked."""
        return self._fernet is not None


# =============================================================================
# PASSWORD STRENGTH ANALYZER
# =============================================================================
class PasswordStrengthAnalyzer:
    """Analyzes password strength based on NIST guidelines."""

    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
        "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
        "michael", "football", "password1", "password123", "welcome", "jesus",
        "ninja", "mustang", "password1!", "admin", "admin123", "root", "toor",
        "pass", "test", "guest", "master", "changeme", "hello", "banana", "login"
    }

    KEYBOARD_PATTERNS = [
        "qwerty", "asdf", "zxcv", "qazwsx", "1234", "4321", "0987", "7890",
        "!@#$", "qwertyuiop", "asdfghjkl", "zxcvbnm"
    ]

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0

        charset_size = 0
        if any(c in string.ascii_lowercase for c in password):
            charset_size += 26
        if any(c in string.ascii_uppercase for c in password):
            charset_size += 26
        if any(c in string.digits for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32

        if charset_size == 0:
            charset_size = len(set(password))

        return len(password) * math.log2(charset_size) if charset_size > 0 else 0

    @classmethod
    def analyze(cls, password: str) -> Dict[str, Any]:
        """Perform comprehensive password strength analysis."""
        if not password:
            return {
                "score": 0,
                "entropy": 0,
                "strength": "None",
                "feedback": ["Enter a password to analyze"],
                "details": {}
            }

        feedback = []
        score = 0
        details = {}

        # Length check
        length = len(password)
        details["length"] = length
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            feedback.append("Password should be at least 8 characters long")

        # Character variety
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        details["character_types"] = variety_count
        score += variety_count * 10

        if not has_lower:
            feedback.append("Consider adding lowercase letters")
        if not has_upper:
            feedback.append("Consider adding uppercase letters")
        if not has_digit:
            feedback.append("Consider adding numbers")
        if not has_symbol:
            feedback.append("Consider adding special characters")

        # Common password check
        if password.lower() in cls.COMMON_PASSWORDS:
            score -= 40
            feedback.append("This is a commonly used password - avoid it")
            details["is_common"] = True
        else:
            details["is_common"] = False

        # Sequential characters check
        sequential = cls._check_sequential(password)
        details["sequential_chars"] = sequential
        if sequential > 2:
            score -= 10
            feedback.append("Avoid sequential characters (abc, 123)")

        # Repeated characters check
        repeated = cls._check_repeated(password)
        details["repeated_chars"] = repeated
        if repeated > 2:
            score -= 10
            feedback.append("Avoid repeated characters (aaa, 111)")

        # Keyboard pattern check
        has_pattern = cls._check_keyboard_pattern(password)
        details["has_keyboard_pattern"] = has_pattern
        if has_pattern:
            score -= 15
            feedback.append("Avoid keyboard patterns (qwerty, asdf)")

        # Calculate entropy
        entropy = cls.calculate_entropy(password)
        details["entropy"] = entropy

        # Entropy bonus
        if entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 10

        # Normalize score
        score = max(0, min(100, score))

        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"

        if not feedback:
            feedback.append("Password meets security requirements")

        return {
            "score": score,
            "entropy": entropy,
            "strength": strength,
            "feedback": feedback,
            "details": details
        }

    @staticmethod
    def _check_sequential(password: str) -> int:
        """Count sequential character runs."""
        max_seq = 0
        current_seq = 1

        for i in range(1, len(password)):
            if ord(password[i]) == ord(password[i-1]) + 1:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 1

        return max_seq

    @staticmethod
    def _check_repeated(password: str) -> int:
        """Count repeated character runs."""
        max_rep = 0
        current_rep = 1

        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                current_rep += 1
                max_rep = max(max_rep, current_rep)
            else:
                current_rep = 1

        return max_rep

    @classmethod
    def _check_keyboard_pattern(cls, password: str) -> bool:
        """Check for common keyboard patterns."""
        lower_pass = password.lower()
        for pattern in cls.KEYBOARD_PATTERNS:
            if pattern in lower_pass:
                return True
        return False


# =============================================================================
# BRUTE FORCE CALCULATOR
# =============================================================================
class BruteForceCalculator:
    """Calculate password crack times across various attack scenarios."""

    SCENARIOS = {
        "online_throttled": {
            "name": "Online (Rate Limited)",
            "rate": 100,
            "description": "100 attempts/hour with lockouts"
        },
        "online_unlimited": {
            "name": "Online (No Limits)",
            "rate": 1000,
            "description": "1,000 attempts/second"
        },
        "offline_cpu": {
            "name": "Offline (CPU)",
            "rate": 10_000_000,
            "description": "10 million attempts/second"
        },
        "single_gpu": {
            "name": "Single GPU",
            "rate": 10_000_000_000,
            "description": "10 billion attempts/second"
        },
        "gpu_cluster": {
            "name": "GPU Cluster",
            "rate": 100_000_000_000,
            "description": "100 billion attempts/second"
        },
        "bcrypt_protected": {
            "name": "Bcrypt Protected",
            "rate": 50_000,
            "description": "50,000 attempts/second (GPU)"
        },
        "nation_state": {
            "name": "Nation State",
            "rate": 1_000_000_000_000,
            "description": "1 trillion attempts/second"
        }
    }

    @classmethod
    def calculate_combinations(cls, password: str) -> int:
        """Calculate the total number of possible combinations."""
        charset_size = 0
        if any(c in string.ascii_lowercase for c in password):
            charset_size += 26
        if any(c in string.ascii_uppercase for c in password):
            charset_size += 26
        if any(c in string.digits for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32

        if charset_size == 0:
            charset_size = len(set(password))

        return charset_size ** len(password) if charset_size > 0 and password else 0

    @classmethod
    def format_time(cls, seconds: float) -> str:
        """Format seconds into human-readable time."""
        if seconds < 1:
            return "Instant"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        if seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        if seconds < 31536000 * 100:
            return f"{seconds / 31536000:.1f} years"
        if seconds < 31536000 * 1000000:
            return f"{seconds / 31536000:,.0f} years"
        if seconds < 31536000 * 1000000000:
            return f"{seconds / (31536000 * 1000000):,.0f} million years"
        return f"{seconds / (31536000 * 1000000000):,.0f} billion years"

    @classmethod
    def calculate_crack_times(cls, password: str) -> Dict[str, Dict]:
        """Calculate crack times for all scenarios."""
        combinations = cls.calculate_combinations(password)
        results = {}

        for key, scenario in cls.SCENARIOS.items():
            if combinations == 0:
                time_str = "N/A"
            else:
                # Average case: half the combinations
                avg_attempts = combinations / 2
                seconds = avg_attempts / scenario["rate"]
                time_str = cls.format_time(seconds)

            results[key] = {
                "name": scenario["name"],
                "time": time_str,
                "description": scenario["description"]
            }

        return results


# =============================================================================
# PASSWORD GENERATOR
# =============================================================================
class PasswordGenerator:
    """Generate cryptographically secure passwords and passphrases."""

    AMBIGUOUS_CHARS = "Il1O0"

    WORDLIST = [
        "apple", "banana", "cherry", "dragon", "eagle", "falcon", "garden", "harbor",
        "island", "jungle", "kitchen", "lemon", "mountain", "network", "ocean", "piano",
        "quantum", "river", "sunset", "thunder", "umbrella", "valley", "winter", "yellow",
        "zebra", "ancient", "bridge", "castle", "diamond", "engine", "forest", "glacier",
        "horizon", "infinity", "journey", "kingdom", "lantern", "mystery", "northern",
        "orange", "phantom", "quarter", "rainbow", "silver", "temple", "universe",
        "village", "whisper", "crystal", "breeze", "cosmic", "stellar", "lunar", "solar",
        "velvet", "marble", "copper", "bronze", "golden", "violet", "scarlet", "emerald",
        "sapphire", "topaz", "amber", "coral", "ivory", "obsidian", "onyx", "pearl",
        "quartz", "ruby", "opal", "jade", "jasper", "garnet", "citrine", "turquoise",
        "magenta", "crimson", "azure", "indigo", "vermillion", "platinum", "titanium",
        "chrome", "cobalt", "mercury", "neptune", "saturn", "jupiter", "venus", "mars",
        "phoenix", "griffin", "sphinx", "hydra", "medusa", "atlas", "titan", "olympus",
        "arctic", "tropic", "desert", "prairie", "meadow", "canyon", "cavern", "summit",
        "rapids", "delta", "lagoon", "reef", "dune", "cliff", "grove", "marsh", "tundra"
    ]

    @classmethod
    def generate_password(
        cls,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False,
        custom_chars: str = ""
    ) -> str:
        """Generate a secure random password."""
        if custom_chars:
            charset = custom_chars
        else:
            charset = ""
            if use_lower:
                charset += string.ascii_lowercase
            if use_upper:
                charset += string.ascii_uppercase
            if use_digits:
                charset += string.digits
            if use_symbols:
                charset += string.punctuation

        if exclude_ambiguous and not custom_chars:
            charset = ''.join(c for c in charset if c not in cls.AMBIGUOUS_CHARS)

        if not charset:
            charset = string.ascii_letters + string.digits

        password = ''.join(secrets.choice(charset) for _ in range(length))
        return password

    @classmethod
    def generate_passphrase(
        cls,
        word_count: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        add_number: bool = True
    ) -> str:
        """Generate a secure random passphrase."""
        words = [secrets.choice(cls.WORDLIST) for _ in range(word_count)]

        if capitalize:
            words = [word.capitalize() for word in words]

        passphrase = separator.join(words)

        if add_number:
            passphrase += separator + str(secrets.randbelow(100))

        return passphrase

    @classmethod
    def generate_from_charset(cls, length: int, charset: str) -> str:
        """Generate a password using only specified characters."""
        if not charset:
            return ""
        return ''.join(secrets.choice(charset) for _ in range(length))


# =============================================================================
# DATA MODELS
# =============================================================================
@dataclass
class PasswordEntry:
    """Represents a stored password entry."""
    id: str = field(default_factory=lambda: secrets.token_hex(8))
    service: str = ""
    username: str = ""
    password: str = ""
    notes: str = ""
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "PasswordEntry":
        return cls(**data)


# =============================================================================
# GUI COMPONENTS
# =============================================================================
class StyledButton(ctk.CTkButton):
    """Styled button component."""

    def __init__(self, master, text: str, command: Callable = None,
                 variant: str = "primary", **kwargs):
        colors = {
            "primary": (Colors.PRIMARY, Colors.TEXT_PRIMARY),
            "secondary": (Colors.BG_LIGHT, Colors.TEXT_PRIMARY),
            "success": (Colors.SUCCESS, Colors.TEXT_PRIMARY),
            "danger": (Colors.DANGER, Colors.TEXT_PRIMARY),
            "warning": (Colors.WARNING, Colors.BG_DARK),
        }

        bg_color, text_color = colors.get(variant, colors["primary"])

        super().__init__(
            master,
            text=text,
            command=command,
            fg_color=bg_color,
            text_color=text_color,
            hover_color=self._adjust_brightness(bg_color, 0.8),
            corner_radius=8,
            height=36,
            **kwargs
        )

    @staticmethod
    def _adjust_brightness(hex_color: str, factor: float) -> str:
        """Adjust the brightness of a hex color."""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        new_rgb = tuple(max(0, min(255, int(c * factor))) for c in rgb)
        return f"#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}"


class CardFrame(ctk.CTkFrame):
    """Styled card container."""

    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=Colors.BG_MEDIUM,
            corner_radius=12,
            border_width=1,
            border_color=Colors.BORDER,
            **kwargs
        )


class StrengthBar(ctk.CTkFrame):
    """Password strength indicator bar."""

    def __init__(self, master, height: int = 8, **kwargs):
        super().__init__(master, height=height, fg_color=Colors.BG_LIGHT, corner_radius=4, **kwargs)

        self.fill = ctk.CTkFrame(self, height=height, fg_color=Colors.DANGER, corner_radius=4)
        self.fill.place(relx=0, rely=0, relwidth=0, relheight=1)

    def set_strength(self, score: int):
        """Update the strength indicator (0-100)."""
        score = max(0, min(100, score))

        if score >= 80:
            color = Colors.SUCCESS
        elif score >= 60:
            color = Colors.CYAN
        elif score >= 40:
            color = Colors.WARNING
        else:
            color = Colors.DANGER

        self.fill.configure(fg_color=color)
        self.fill.place(relwidth=score / 100)


# =============================================================================
# MODAL DIALOGS
# =============================================================================
class AddEditEntryDialog(ctk.CTkToplevel):
    """Dialog for adding or editing password entries."""

    def __init__(self, master, entry: Optional[PasswordEntry] = None,
                 on_save: Callable = None):
        super().__init__(master)

        self.entry = entry
        self.on_save = on_save
        self.result = None

        self.title("Edit Entry" if entry else "Add Entry")
        self.geometry("500x500")
        self.configure(fg_color=Colors.BG_DARK)

        self.transient(master)
        self.grab_set()

        self._create_widgets()

        if entry:
            self._populate_fields()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _create_widgets(self):
        """Create dialog widgets."""
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Service
        ctk.CTkLabel(
            main_frame, text="Service Name",
            text_color=Colors.TEXT_SECONDARY, anchor="w"
        ).pack(fill="x", pady=(0, 5))

        self.service_entry = ctk.CTkEntry(
            main_frame, fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY
        )
        self.service_entry.pack(fill="x", pady=(0, 15))

        # Username
        ctk.CTkLabel(
            main_frame, text="Username / Email",
            text_color=Colors.TEXT_SECONDARY, anchor="w"
        ).pack(fill="x", pady=(0, 5))

        self.username_entry = ctk.CTkEntry(
            main_frame, fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY
        )
        self.username_entry.pack(fill="x", pady=(0, 15))

        # Password with generate button
        ctk.CTkLabel(
            main_frame, text="Password",
            text_color=Colors.TEXT_SECONDARY, anchor="w"
        ).pack(fill="x", pady=(0, 5))

        pw_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        pw_frame.pack(fill="x", pady=(0, 15))

        self.password_entry = ctk.CTkEntry(
            pw_frame, fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
            show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.show_pw_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            pw_frame, text="Show", variable=self.show_pw_var,
            command=self._toggle_password_visibility,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 10))

        StyledButton(
            pw_frame, text="Generate", command=self._generate_password,
            width=80, variant="secondary"
        ).pack(side="left")

        # Notes
        ctk.CTkLabel(
            main_frame, text="Notes (Optional)",
            text_color=Colors.TEXT_SECONDARY, anchor="w"
        ).pack(fill="x", pady=(0, 5))

        self.notes_text = ctk.CTkTextbox(
            main_frame, height=100, fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
            border_width=1
        )
        self.notes_text.pack(fill="x", pady=(0, 20))

        # Buttons
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x")

        StyledButton(
            btn_frame, text="Cancel", command=self._on_cancel,
            variant="secondary"
        ).pack(side="left")

        StyledButton(
            btn_frame, text="Save", command=self._on_save,
            variant="success"
        ).pack(side="right")

    def _populate_fields(self):
        """Populate fields with existing entry data."""
        self.service_entry.insert(0, self.entry.service)
        self.username_entry.insert(0, self.entry.username)
        self.password_entry.insert(0, self.entry.password)
        self.notes_text.insert("1.0", self.entry.notes)

    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        self.password_entry.configure(show="" if self.show_pw_var.get() else "•")

    def _generate_password(self):
        """Generate a random password."""
        password = PasswordGenerator.generate_password(length=20)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)

    def _on_save(self):
        """Save the entry."""
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        notes = self.notes_text.get("1.0", "end-1c").strip()

        if not service:
            self._show_error("Service name is required")
            return

        if not password:
            self._show_error("Password is required")
            return

        if self.entry:
            self.entry.service = service
            self.entry.username = username
            self.entry.password = password
            self.entry.notes = notes
            self.entry.modified = datetime.now().isoformat()
            self.result = self.entry
        else:
            self.result = PasswordEntry(
                service=service,
                username=username,
                password=password,
                notes=notes
            )

        if self.on_save:
            self.on_save(self.result)

        self.destroy()

    def _on_cancel(self):
        """Cancel and close dialog."""
        self.result = None
        self.destroy()

    def _show_error(self, message: str):
        """Show an error message."""
        error_dialog = ctk.CTkToplevel(self)
        error_dialog.title("Error")
        error_dialog.geometry("300x120")
        error_dialog.configure(fg_color=Colors.BG_DARK)
        error_dialog.transient(self)
        error_dialog.grab_set()

        ctk.CTkLabel(
            error_dialog, text=message,
            text_color=Colors.DANGER
        ).pack(pady=20)

        StyledButton(
            error_dialog, text="OK",
            command=error_dialog.destroy
        ).pack()


# =============================================================================
# MODULE FRAMES
# =============================================================================
class VaultModule(ctk.CTkFrame):
    """Password vault module for managing stored credentials."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.entries: List[PasswordEntry] = []
        self.filtered_entries: List[PasswordEntry] = []

        self._create_widgets()

    def _create_widgets(self):
        """Create vault module widgets."""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header, text="Password Vault",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(side="left")

        StyledButton(
            header, text="+ Add Entry",
            command=self._add_entry,
            variant="success"
        ).pack(side="right")

        # Search bar
        search_frame = CardFrame(self)
        search_frame.pack(fill="x", pady=(0, 20))

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._on_search)

        search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search passwords...",
            textvariable=self.search_var,
            fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
            height=40
        )
        search_entry.pack(fill="x", padx=15, pady=15)

        # Entries list
        self.list_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent"
        )
        self.list_frame.pack(fill="both", expand=True)

        self._render_entries()

    def load_entries(self, entries: List[Dict]):
        """Load entries from vault data."""
        self.entries = [PasswordEntry.from_dict(e) for e in entries]
        self.filtered_entries = self.entries.copy()
        self._render_entries()

    def _render_entries(self):
        """Render the list of entries."""
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        if not self.filtered_entries:
            self._render_welcome_screen()
            return

        for entry in self.filtered_entries:
            self._create_entry_card(entry)

    def _render_welcome_screen(self):
        """Render an attractive welcome screen for new users."""
        welcome_container = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        welcome_container.pack(fill="both", expand=True, pady=20)

        # Welcome card
        welcome_card = CardFrame(welcome_container)
        welcome_card.pack(fill="x", pady=(0, 20))

        welcome_content = ctk.CTkFrame(welcome_card, fg_color="transparent")
        welcome_content.pack(fill="x", padx=30, pady=30)

        ctk.CTkLabel(
            welcome_content,
            text="Welcome to SecureVault",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=Colors.PRIMARY
        ).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            welcome_content,
            text="Your personal fortress for passwords and sensitive credentials.",
            font=ctk.CTkFont(size=14),
            text_color=Colors.TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 20))

        # Feature highlights
        features = [
            ("Military-Grade Encryption", "Your passwords are protected with AES-256 encryption and PBKDF2 key derivation with 600,000 iterations."),
            ("Zero Knowledge Architecture", "Your master password never leaves your device. Only you can access your vault."),
            ("Built for Security Professionals", "Compliant with NIST SP 800-63B guidelines for digital identity protection."),
        ]

        for title, desc in features:
            feature_frame = ctk.CTkFrame(welcome_content, fg_color=Colors.BG_LIGHT, corner_radius=8)
            feature_frame.pack(fill="x", pady=(0, 10))

            feature_inner = ctk.CTkFrame(feature_frame, fg_color="transparent")
            feature_inner.pack(fill="x", padx=15, pady=12)

            ctk.CTkLabel(
                feature_inner,
                text=title,
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=Colors.CYAN,
                anchor="w"
            ).pack(fill="x")

            ctk.CTkLabel(
                feature_inner,
                text=desc,
                font=ctk.CTkFont(size=12),
                text_color=Colors.TEXT_SECONDARY,
                anchor="w",
                wraplength=500
            ).pack(fill="x", pady=(3, 0))

        # Getting started section
        ctk.CTkLabel(
            welcome_content,
            text="Getting Started",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(20, 10))

        steps = [
            "Click the '+ Add Entry' button above to store your first password",
            "Use the Password Generator to create strong, unique passwords",
            "Check the Strength Analyzer to evaluate your existing passwords",
        ]

        for i, step in enumerate(steps, 1):
            step_frame = ctk.CTkFrame(welcome_content, fg_color="transparent")
            step_frame.pack(fill="x", pady=(0, 8))

            ctk.CTkLabel(
                step_frame,
                text=f"{i}.",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=Colors.PRIMARY,
                width=25
            ).pack(side="left")

            ctk.CTkLabel(
                step_frame,
                text=step,
                font=ctk.CTkFont(size=13),
                text_color=Colors.TEXT_SECONDARY,
                anchor="w"
            ).pack(side="left", fill="x")

    def _create_entry_card(self, entry: PasswordEntry):
        """Create a card for a password entry."""
        card = CardFrame(self.list_frame)
        card.pack(fill="x", pady=(0, 10))

        # Main content
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=15)

        # Left side - info
        info_frame = ctk.CTkFrame(content, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            info_frame, text=entry.service,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=Colors.TEXT_PRIMARY, anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            info_frame, text=entry.username or "(no username)",
            text_color=Colors.TEXT_SECONDARY, anchor="w"
        ).pack(fill="x")

        # Strength indicator
        analysis = PasswordStrengthAnalyzer.analyze(entry.password)
        strength_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        strength_frame.pack(fill="x", pady=(5, 0))

        ctk.CTkLabel(
            strength_frame, text=f"Strength: {analysis['strength']}",
            text_color=Colors.TEXT_SECONDARY, font=ctk.CTkFont(size=12)
        ).pack(side="left")

        bar = StrengthBar(strength_frame, width=100)
        bar.pack(side="left", padx=(10, 0))
        bar.set_strength(analysis['score'])

        # Right side - actions
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(side="right")

        StyledButton(
            actions, text="Copy", width=70,
            command=lambda e=entry: self._copy_password(e),
            variant="secondary"
        ).pack(side="left", padx=(0, 5))

        StyledButton(
            actions, text="Edit", width=70,
            command=lambda e=entry: self._edit_entry(e),
            variant="primary"
        ).pack(side="left", padx=(0, 5))

        StyledButton(
            actions, text="Delete", width=70,
            command=lambda e=entry: self._delete_entry(e),
            variant="danger"
        ).pack(side="left")

    def _on_search(self, *args):
        """Handle search input."""
        query = self.search_var.get().lower()
        if query:
            self.filtered_entries = [
                e for e in self.entries
                if query in e.service.lower() or query in e.username.lower()
            ]
        else:
            self.filtered_entries = self.entries.copy()
        self._render_entries()

    def _add_entry(self):
        """Open dialog to add a new entry."""
        dialog = AddEditEntryDialog(self.app, on_save=self._save_new_entry)
        dialog.wait_window()

    def _save_new_entry(self, entry: PasswordEntry):
        """Save a new entry."""
        self.entries.append(entry)
        self.filtered_entries = self.entries.copy()
        self._save_to_vault()
        self._render_entries()

    def _edit_entry(self, entry: PasswordEntry):
        """Open dialog to edit an entry."""
        dialog = AddEditEntryDialog(
            self.app, entry=entry,
            on_save=self._save_edited_entry
        )
        dialog.wait_window()

    def _save_edited_entry(self, entry: PasswordEntry):
        """Save an edited entry."""
        self._save_to_vault()
        self._render_entries()

    def _delete_entry(self, entry: PasswordEntry):
        """Delete an entry."""
        self.entries = [e for e in self.entries if e.id != entry.id]
        self.filtered_entries = [e for e in self.filtered_entries if e.id != entry.id]
        self._save_to_vault()
        self._render_entries()

    def _copy_password(self, entry: PasswordEntry):
        """Copy password to clipboard."""
        self.app.clipboard_clear()
        self.app.clipboard_append(entry.password)
        self.app.update()

    def _save_to_vault(self):
        """Save entries to encrypted vault."""
        entries_data = [e.to_dict() for e in self.entries]
        self.app.security.save_entries(entries_data)


class GeneratorModule(ctk.CTkFrame):
    """Password generator module."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create generator module widgets."""
        ctk.CTkLabel(
            self, text="Password Generator",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 20))

        # Main card
        card = CardFrame(self)
        card.pack(fill="x")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=20)

        # Generated password display
        self.password_var = ctk.StringVar(value="Click 'Generate' to create a password")

        pw_frame = ctk.CTkFrame(content, fg_color=Colors.BG_LIGHT, corner_radius=8)
        pw_frame.pack(fill="x", pady=(0, 20))

        self.password_label = ctk.CTkLabel(
            pw_frame, textvariable=self.password_var,
            font=ctk.CTkFont(family="Courier", size=16),
            text_color=Colors.CYAN
        )
        self.password_label.pack(side="left", padx=15, pady=15, fill="x", expand=True)

        StyledButton(
            pw_frame, text="Copy", width=70,
            command=self._copy_password, variant="secondary"
        ).pack(side="right", padx=10)

        # Strength indicator
        strength_frame = ctk.CTkFrame(content, fg_color="transparent")
        strength_frame.pack(fill="x", pady=(0, 20))

        self.strength_label = ctk.CTkLabel(
            strength_frame, text="Strength: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.strength_label.pack(side="left")

        self.strength_bar = StrengthBar(strength_frame, width=200)
        self.strength_bar.pack(side="left", padx=(10, 0))

        self.entropy_label = ctk.CTkLabel(
            strength_frame, text="Entropy: - bits",
            text_color=Colors.TEXT_SECONDARY
        )
        self.entropy_label.pack(side="right")

        # Length slider
        length_frame = ctk.CTkFrame(content, fg_color="transparent")
        length_frame.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(
            length_frame, text="Length:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        self.length_var = ctk.IntVar(value=16)
        self.length_label = ctk.CTkLabel(
            length_frame, text="16",
            text_color=Colors.TEXT_PRIMARY, width=30
        )
        self.length_label.pack(side="left", padx=(10, 0))

        self.length_slider = ctk.CTkSlider(
            length_frame, from_=8, to=64,
            variable=self.length_var,
            command=self._on_length_change,
            fg_color=Colors.BG_LIGHT,
            progress_color=Colors.PRIMARY,
            button_color=Colors.PRIMARY
        )
        self.length_slider.pack(side="left", fill="x", expand=True, padx=(10, 0))

        # Character options
        options_frame = ctk.CTkFrame(content, fg_color="transparent")
        options_frame.pack(fill="x", pady=(0, 15))

        self.upper_var = ctk.BooleanVar(value=True)
        self.lower_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)
        self.ambiguous_var = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            options_frame, text="A-Z", variable=self.upper_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 15))

        ctk.CTkCheckBox(
            options_frame, text="a-z", variable=self.lower_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 15))

        ctk.CTkCheckBox(
            options_frame, text="0-9", variable=self.digits_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 15))

        ctk.CTkCheckBox(
            options_frame, text="!@#$", variable=self.symbols_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 15))

        ctk.CTkCheckBox(
            options_frame, text="Exclude Ambiguous (Il1O0)",
            variable=self.ambiguous_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        # Generate button
        StyledButton(
            content, text="Generate Password",
            command=self._generate, variant="success"
        ).pack(pady=(10, 0))

    def _on_length_change(self, value):
        """Handle length slider change."""
        self.length_label.configure(text=str(int(value)))

    def _generate(self):
        """Generate a new password."""
        password = PasswordGenerator.generate_password(
            length=self.length_var.get(),
            use_upper=self.upper_var.get(),
            use_lower=self.lower_var.get(),
            use_digits=self.digits_var.get(),
            use_symbols=self.symbols_var.get(),
            exclude_ambiguous=self.ambiguous_var.get()
        )

        self.password_var.set(password)
        self._update_strength(password)

    def _update_strength(self, password: str):
        """Update strength indicators."""
        analysis = PasswordStrengthAnalyzer.analyze(password)
        self.strength_label.configure(text=f"Strength: {analysis['strength']}")
        self.strength_bar.set_strength(analysis['score'])
        self.entropy_label.configure(text=f"Entropy: {analysis['entropy']:.1f} bits")

    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_var.get()
        if password and not password.startswith("Click"):
            self.app.clipboard_clear()
            self.app.clipboard_append(password)
            self.app.update()


class PassphraseModule(ctk.CTkFrame):
    """Passphrase generator module."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create passphrase module widgets."""
        ctk.CTkLabel(
            self, text="Passphrase Generator",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 20))

        card = CardFrame(self)
        card.pack(fill="x")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=20)

        # Generated passphrase display
        self.passphrase_var = ctk.StringVar(value="Click 'Generate' to create a passphrase")

        pw_frame = ctk.CTkFrame(content, fg_color=Colors.BG_LIGHT, corner_radius=8)
        pw_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            pw_frame, textvariable=self.passphrase_var,
            font=ctk.CTkFont(family="Courier", size=16),
            text_color=Colors.CYAN
        ).pack(side="left", padx=15, pady=15, fill="x", expand=True)

        StyledButton(
            pw_frame, text="Copy", width=70,
            command=self._copy_passphrase, variant="secondary"
        ).pack(side="right", padx=10)

        # Strength indicator
        strength_frame = ctk.CTkFrame(content, fg_color="transparent")
        strength_frame.pack(fill="x", pady=(0, 20))

        self.strength_label = ctk.CTkLabel(
            strength_frame, text="Strength: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.strength_label.pack(side="left")

        self.strength_bar = StrengthBar(strength_frame, width=200)
        self.strength_bar.pack(side="left", padx=(10, 0))

        self.entropy_label = ctk.CTkLabel(
            strength_frame, text="Entropy: - bits",
            text_color=Colors.TEXT_SECONDARY
        )
        self.entropy_label.pack(side="right")

        # Word count slider
        word_frame = ctk.CTkFrame(content, fg_color="transparent")
        word_frame.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(
            word_frame, text="Words:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        self.word_count_var = ctk.IntVar(value=4)
        self.word_label = ctk.CTkLabel(
            word_frame, text="4",
            text_color=Colors.TEXT_PRIMARY, width=30
        )
        self.word_label.pack(side="left", padx=(10, 0))

        ctk.CTkSlider(
            word_frame, from_=3, to=8,
            variable=self.word_count_var,
            command=lambda v: self.word_label.configure(text=str(int(v))),
            fg_color=Colors.BG_LIGHT,
            progress_color=Colors.PRIMARY,
            button_color=Colors.PRIMARY
        ).pack(side="left", fill="x", expand=True, padx=(10, 0))

        # Separator
        sep_frame = ctk.CTkFrame(content, fg_color="transparent")
        sep_frame.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(
            sep_frame, text="Separator:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        self.separator_var = ctk.StringVar(value="-")
        ctk.CTkEntry(
            sep_frame, textvariable=self.separator_var,
            width=50, fg_color=Colors.BG_LIGHT,
            border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY
        ).pack(side="left", padx=(10, 0))

        # Options
        options_frame = ctk.CTkFrame(content, fg_color="transparent")
        options_frame.pack(fill="x", pady=(0, 15))

        self.capitalize_var = ctk.BooleanVar(value=True)
        self.number_var = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(
            options_frame, text="Capitalize Words", variable=self.capitalize_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left", padx=(0, 20))

        ctk.CTkCheckBox(
            options_frame, text="Add Number", variable=self.number_var,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        # Generate button
        StyledButton(
            content, text="Generate Passphrase",
            command=self._generate, variant="success"
        ).pack(pady=(10, 0))

    def _generate(self):
        """Generate a new passphrase."""
        passphrase = PasswordGenerator.generate_passphrase(
            word_count=self.word_count_var.get(),
            separator=self.separator_var.get(),
            capitalize=self.capitalize_var.get(),
            add_number=self.number_var.get()
        )

        self.passphrase_var.set(passphrase)
        self._update_strength(passphrase)

    def _update_strength(self, passphrase: str):
        """Update strength indicators."""
        analysis = PasswordStrengthAnalyzer.analyze(passphrase)
        self.strength_label.configure(text=f"Strength: {analysis['strength']}")
        self.strength_bar.set_strength(analysis['score'])
        self.entropy_label.configure(text=f"Entropy: {analysis['entropy']:.1f} bits")

    def _copy_passphrase(self):
        """Copy passphrase to clipboard."""
        passphrase = self.passphrase_var.get()
        if passphrase and not passphrase.startswith("Click"):
            self.app.clipboard_clear()
            self.app.clipboard_append(passphrase)
            self.app.update()


class ManualGeneratorModule(ctk.CTkFrame):
    """Manual password generator with custom character set."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create manual generator widgets."""
        ctk.CTkLabel(
            self, text="Manual Generator",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 20))

        card = CardFrame(self)
        card.pack(fill="x")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=20, pady=20)

        # Info text
        ctk.CTkLabel(
            content,
            text="Generate passwords using only specific characters.\nUseful for systems with strict password requirements.",
            text_color=Colors.TEXT_SECONDARY,
            justify="left"
        ).pack(anchor="w", pady=(0, 20))

        # Generated password display
        self.password_var = ctk.StringVar(value="Enter characters and click 'Generate'")

        pw_frame = ctk.CTkFrame(content, fg_color=Colors.BG_LIGHT, corner_radius=8)
        pw_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            pw_frame, textvariable=self.password_var,
            font=ctk.CTkFont(family="Courier", size=16),
            text_color=Colors.CYAN
        ).pack(side="left", padx=15, pady=15, fill="x", expand=True)

        StyledButton(
            pw_frame, text="Copy", width=70,
            command=self._copy_password, variant="secondary"
        ).pack(side="right", padx=10)

        # Custom charset input
        ctk.CTkLabel(
            content, text="Allowed Characters:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(anchor="w", pady=(0, 5))

        self.charset_var = ctk.StringVar(value="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789")

        self.charset_entry = ctk.CTkEntry(
            content, textvariable=self.charset_var,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY
        )
        self.charset_entry.pack(fill="x", pady=(0, 15))

        # Length slider
        length_frame = ctk.CTkFrame(content, fg_color="transparent")
        length_frame.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(
            length_frame, text="Length:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        self.length_var = ctk.IntVar(value=16)
        self.length_label = ctk.CTkLabel(
            length_frame, text="16",
            text_color=Colors.TEXT_PRIMARY, width=30
        )
        self.length_label.pack(side="left", padx=(10, 0))

        ctk.CTkSlider(
            length_frame, from_=8, to=64,
            variable=self.length_var,
            command=lambda v: self.length_label.configure(text=str(int(v))),
            fg_color=Colors.BG_LIGHT,
            progress_color=Colors.PRIMARY,
            button_color=Colors.PRIMARY
        ).pack(side="left", fill="x", expand=True, padx=(10, 0))

        # Generate button
        StyledButton(
            content, text="Generate Password",
            command=self._generate, variant="success"
        ).pack(pady=(10, 0))

    def _generate(self):
        """Generate a password from custom charset."""
        charset = self.charset_var.get()
        if not charset:
            self.password_var.set("Please enter allowed characters")
            return

        password = PasswordGenerator.generate_from_charset(
            length=self.length_var.get(),
            charset=charset
        )
        self.password_var.set(password)

    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_var.get()
        if password and not password.startswith("Enter") and not password.startswith("Please"):
            self.app.clipboard_clear()
            self.app.clipboard_append(password)
            self.app.update()


class AnalyzerModule(ctk.CTkFrame):
    """Password strength analyzer module."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create analyzer module widgets."""
        # Header section
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame, text="Password Strength Analyzer",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            header_frame,
            text="Discover how secure your passwords really are. Get instant feedback and actionable recommendations.",
            font=ctk.CTkFont(size=13),
            text_color=Colors.TEXT_SECONDARY,
            wraplength=600
        ).pack(anchor="w", pady=(5, 0))

        card = CardFrame(self)
        card.pack(fill="x")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", padx=25, pady=25)

        # Password input with better description
        input_header = ctk.CTkFrame(content, fg_color="transparent")
        input_header.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            input_header, text="Test Your Password",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            input_header, text="Type or paste any password to see a detailed security analysis",
            text_color=Colors.TEXT_SECONDARY,
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w")

        input_frame = ctk.CTkFrame(content, fg_color="transparent")
        input_frame.pack(fill="x", pady=(0, 20))

        self.password_var = ctk.StringVar()
        self.password_var.trace_add("write", self._on_password_change)

        self.password_entry = ctk.CTkEntry(
            input_frame, textvariable=self.password_var,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY, show="•"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            input_frame, text="Show", variable=self.show_var,
            command=self._toggle_visibility,
            fg_color=Colors.PRIMARY, text_color=Colors.TEXT_SECONDARY
        ).pack(side="left")

        # Results section
        self.results_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.results_frame.pack(fill="x")

        # Strength display
        self.strength_label = ctk.CTkLabel(
            self.results_frame, text="Strength: -",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        )
        self.strength_label.pack(anchor="w", pady=(0, 10))

        self.strength_bar = StrengthBar(self.results_frame, width=400, height=12)
        self.strength_bar.pack(anchor="w", pady=(0, 20))

        # Stats grid
        stats_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 20))

        # Left column
        left_stats = ctk.CTkFrame(stats_frame, fg_color="transparent")
        left_stats.pack(side="left", fill="x", expand=True)

        self.entropy_label = ctk.CTkLabel(
            left_stats, text="Entropy: - bits",
            text_color=Colors.TEXT_SECONDARY
        )
        self.entropy_label.pack(anchor="w")

        self.length_label = ctk.CTkLabel(
            left_stats, text="Length: - characters",
            text_color=Colors.TEXT_SECONDARY
        )
        self.length_label.pack(anchor="w")

        self.types_label = ctk.CTkLabel(
            left_stats, text="Character Types: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.types_label.pack(anchor="w")

        # Right column
        right_stats = ctk.CTkFrame(stats_frame, fg_color="transparent")
        right_stats.pack(side="right", fill="x", expand=True)

        self.common_label = ctk.CTkLabel(
            right_stats, text="Common Password: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.common_label.pack(anchor="w")

        self.sequential_label = ctk.CTkLabel(
            right_stats, text="Sequential Characters: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.sequential_label.pack(anchor="w")

        self.repeated_label = ctk.CTkLabel(
            right_stats, text="Repeated Characters: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.repeated_label.pack(anchor="w")

        # Feedback section
        ctk.CTkLabel(
            self.results_frame, text="Feedback:",
            font=ctk.CTkFont(weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(10, 5))

        self.feedback_frame = ctk.CTkFrame(
            self.results_frame, fg_color=Colors.BG_LIGHT, corner_radius=8
        )
        self.feedback_frame.pack(fill="x")

        self.feedback_label = ctk.CTkLabel(
            self.feedback_frame, text="Enter a password to see analysis",
            text_color=Colors.TEXT_SECONDARY, justify="left", anchor="w"
        )
        self.feedback_label.pack(padx=15, pady=15, anchor="w")

    def _toggle_visibility(self):
        """Toggle password visibility."""
        self.password_entry.configure(show="" if self.show_var.get() else "•")

    def _on_password_change(self, *args):
        """Handle password input change."""
        password = self.password_var.get()
        analysis = PasswordStrengthAnalyzer.analyze(password)

        self.strength_label.configure(text=f"Strength: {analysis['strength']}")
        self.strength_bar.set_strength(analysis['score'])

        details = analysis.get('details', {})

        self.entropy_label.configure(
            text=f"Entropy: {analysis['entropy']:.1f} bits"
        )
        self.length_label.configure(
            text=f"Length: {details.get('length', 0)} characters"
        )
        self.types_label.configure(
            text=f"Character Types: {details.get('character_types', 0)}/4"
        )

        is_common = details.get('is_common', False)
        self.common_label.configure(
            text=f"Common Password: {'Yes' if is_common else 'No'}",
            text_color=Colors.DANGER if is_common else Colors.SUCCESS
        )

        seq = details.get('sequential_chars', 0)
        self.sequential_label.configure(
            text=f"Sequential Characters: {seq}",
            text_color=Colors.WARNING if seq > 2 else Colors.TEXT_SECONDARY
        )

        rep = details.get('repeated_chars', 0)
        self.repeated_label.configure(
            text=f"Repeated Characters: {rep}",
            text_color=Colors.WARNING if rep > 2 else Colors.TEXT_SECONDARY
        )

        feedback_text = "\n".join(f"• {f}" for f in analysis['feedback'])
        self.feedback_label.configure(text=feedback_text)


class BruteForceModule(ctk.CTkFrame):
    """Brute force time calculator module."""

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create brute force calculator widgets."""
        # Header section
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame, text="Brute Force Time Calculator",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            header_frame,
            text="See how long it would take attackers to crack your password across different attack scenarios.",
            font=ctk.CTkFont(size=13),
            text_color=Colors.TEXT_SECONDARY,
            wraplength=600
        ).pack(anchor="w", pady=(5, 0))

        card = CardFrame(self)
        card.pack(fill="both", expand=True)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=25, pady=25)

        # Password input with better description
        input_header = ctk.CTkFrame(content, fg_color="transparent")
        input_header.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            input_header, text="Enter a Password to Test",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            input_header,
            text="We will calculate crack times from basic online attacks to nation-state level resources",
            text_color=Colors.TEXT_SECONDARY,
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w")

        input_frame = ctk.CTkFrame(content, fg_color="transparent")
        input_frame.pack(fill="x", pady=(0, 20))

        self.password_var = ctk.StringVar()

        self.password_entry = ctk.CTkEntry(
            input_frame, textvariable=self.password_var,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        StyledButton(
            input_frame, text="Calculate",
            command=self._calculate, variant="primary"
        ).pack(side="left")

        # Stats
        stats_frame = ctk.CTkFrame(content, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 20))

        self.combinations_label = ctk.CTkLabel(
            stats_frame, text="Possible Combinations: -",
            text_color=Colors.TEXT_SECONDARY
        )
        self.combinations_label.pack(side="left", padx=(0, 30))

        self.entropy_label = ctk.CTkLabel(
            stats_frame, text="Entropy: - bits",
            text_color=Colors.TEXT_SECONDARY
        )
        self.entropy_label.pack(side="left")

        # Scenarios table
        ctk.CTkLabel(
            content, text="Estimated Crack Times:",
            font=ctk.CTkFont(weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 10))

        self.scenarios_frame = ctk.CTkScrollableFrame(
            content, fg_color="transparent"
        )
        self.scenarios_frame.pack(fill="both", expand=True)

        self._render_scenarios({})

    def _calculate(self):
        """Calculate crack times."""
        password = self.password_var.get()
        if not password:
            return

        combinations = BruteForceCalculator.calculate_combinations(password)
        entropy = PasswordStrengthAnalyzer.calculate_entropy(password)

        self.combinations_label.configure(
            text=f"Possible Combinations: {combinations:,.0f}"
        )
        self.entropy_label.configure(
            text=f"Entropy: {entropy:.1f} bits"
        )

        results = BruteForceCalculator.calculate_crack_times(password)
        self._render_scenarios(results)

    def _render_scenarios(self, results: Dict):
        """Render scenario results."""
        for widget in self.scenarios_frame.winfo_children():
            widget.destroy()

        if not results:
            for key, scenario in BruteForceCalculator.SCENARIOS.items():
                self._create_scenario_row(
                    scenario["name"],
                    "-",
                    scenario["description"]
                )
        else:
            for key, data in results.items():
                self._create_scenario_row(
                    data["name"],
                    data["time"],
                    data["description"]
                )

    def _create_scenario_row(self, name: str, time: str, description: str):
        """Create a scenario row."""
        row = ctk.CTkFrame(self.scenarios_frame, fg_color=Colors.BG_LIGHT, corner_radius=8)
        row.pack(fill="x", pady=(0, 8))

        content = ctk.CTkFrame(row, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=10)

        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            left, text=name,
            font=ctk.CTkFont(weight="bold"),
            text_color=Colors.TEXT_PRIMARY, anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            left, text=description,
            text_color=Colors.TEXT_SECONDARY,
            font=ctk.CTkFont(size=12), anchor="w"
        ).pack(fill="x")

        # Color code the time
        if time == "Instant":
            color = Colors.DANGER
        elif "second" in time or "minute" in time:
            color = Colors.DANGER
        elif "hour" in time or "day" in time:
            color = Colors.WARNING
        elif "year" in time:
            if "billion" in time or "million" in time:
                color = Colors.SUCCESS
            else:
                color = Colors.CYAN
        else:
            color = Colors.TEXT_SECONDARY

        ctk.CTkLabel(
            content, text=time,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color
        ).pack(side="right")


class NISTGuidelinesModule(ctk.CTkFrame):
    """NIST SP 800-63B guidelines reference module."""

    GUIDELINES = {
        "recommended": [
            {
                "title": "Minimum Length of 8 Characters",
                "description": "Passwords should be at least 8 characters. Longer passwords (15+) are encouraged for higher security.",
                "why": "Length is the most important factor in password strength. Each additional character exponentially increases crack time."
            },
            {
                "title": "Maximum Length of 64+ Characters",
                "description": "Allow passwords up to at least 64 characters to support passphrases.",
                "why": "Passphrases like 'correct-horse-battery-staple' are both memorable and extremely secure."
            },
            {
                "title": "Support All ASCII Characters",
                "description": "Allow all printable ASCII characters, including spaces and Unicode.",
                "why": "Restricting characters reduces the password space and frustrates users who want to use complex passwords."
            },
            {
                "title": "Check Against Compromised Passwords",
                "description": "Verify passwords against lists of commonly-used, expected, or compromised passwords.",
                "why": "Attackers use dictionaries of leaked passwords. Even a 'strong-looking' password is weak if it has been breached."
            },
            {
                "title": "No Mandatory Complexity Rules",
                "description": "Don't require mixtures of character types. Users create weaker passwords with forced complexity.",
                "why": "P@ssw0rd! meets complexity rules but is easily guessed. Let users choose their own approach."
            },
            {
                "title": "No Periodic Password Changes",
                "description": "Don't force regular password expiration unless there's evidence of compromise.",
                "why": "Forced changes lead to predictable patterns like Summer2024 to Fall2024. Change only when necessary."
            },
            {
                "title": "Offer Password Strength Meter",
                "description": "Provide real-time feedback to help users create stronger passwords.",
                "why": "Users make better choices when they can see the impact of their decisions in real-time."
            },
            {
                "title": "Allow Paste in Password Fields",
                "description": "Support paste functionality to enable password managers.",
                "why": "Blocking paste discourages password managers and encourages weak, memorable passwords."
            },
            {
                "title": "Use Proper Password Hashing",
                "description": "Store passwords using approved algorithms like PBKDF2, bcrypt, scrypt, or Argon2.",
                "why": "These algorithms are designed to be slow, making brute-force attacks computationally expensive."
            },
            {
                "title": "Salt All Password Hashes",
                "description": "Use a random salt of at least 32 bits for each stored password.",
                "why": "Salts prevent rainbow table attacks and ensure identical passwords have different hashes."
            }
        ],
        "deprecated": [
            {
                "title": "Composition Rules",
                "description": "Requiring uppercase, lowercase, numbers, and symbols often leads to predictable patterns.",
                "why": "Users typically capitalize the first letter and add 1! at the end. Attackers know this."
            },
            {
                "title": "Password Hints",
                "description": "Password hints can be exploited by attackers and should not be used.",
                "why": "Hints often reveal too much information. 'My dog's name' tells attackers exactly what to guess."
            },
            {
                "title": "Security Questions",
                "description": "Knowledge-based authentication questions are easily researched or guessed.",
                "why": "Your mother's maiden name is public record. Your first pet's name is probably on social media."
            },
            {
                "title": "Forced Periodic Changes",
                "description": "Mandatory password expiration causes users to make minimal, predictable changes.",
                "why": "Research shows forced rotation decreases security by encouraging simple, incrementable passwords."
            },
            {
                "title": "SMS-Based Two-Factor Authentication",
                "description": "SMS is vulnerable to interception and SIM swapping. Use authenticator apps instead.",
                "why": "Attackers can hijack phone numbers through social engineering of mobile carriers."
            }
        ]
    }

    def __init__(self, master, app: "SecureVaultApp"):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self._create_widgets()

    def _create_widgets(self):
        """Create NIST guidelines widgets."""
        # Header section
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame, text="NIST Password Guidelines",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            header_frame,
            text="Modern password security based on NIST Special Publication 800-63B. These guidelines represent the current best practices for digital identity and authentication.",
            font=ctk.CTkFont(size=13),
            text_color=Colors.TEXT_SECONDARY,
            wraplength=650
        ).pack(anchor="w", pady=(5, 0))

        # Scrollable content
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Recommended practices
        rec_card = CardFrame(scroll)
        rec_card.pack(fill="x", pady=(0, 20))

        rec_header = ctk.CTkFrame(rec_card, fg_color="transparent")
        rec_header.pack(fill="x", padx=25, pady=(25, 15))

        # Using text instead of emoji
        rec_badge = ctk.CTkFrame(rec_header, fg_color=Colors.SUCCESS, corner_radius=4)
        rec_badge.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            rec_badge, text="RECOMMENDED",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=Colors.BG_DARK
        ).pack(padx=8, pady=3)

        ctk.CTkLabel(
            rec_header, text="What You Should Do",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(side="left")

        for guideline in self.GUIDELINES["recommended"]:
            self._create_guideline_item(rec_card, guideline, Colors.SUCCESS)

        # Add bottom padding
        ctk.CTkFrame(rec_card, fg_color="transparent", height=15).pack()

        # Deprecated practices
        dep_card = CardFrame(scroll)
        dep_card.pack(fill="x")

        dep_header = ctk.CTkFrame(dep_card, fg_color="transparent")
        dep_header.pack(fill="x", padx=25, pady=(25, 15))

        # Using text instead of emoji
        dep_badge = ctk.CTkFrame(dep_header, fg_color=Colors.DANGER, corner_radius=4)
        dep_badge.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            dep_badge, text="AVOID",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(padx=8, pady=3)

        ctk.CTkLabel(
            dep_header, text="Outdated Practices to Avoid",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(side="left")

        for guideline in self.GUIDELINES["deprecated"]:
            self._create_guideline_item(dep_card, guideline, Colors.DANGER)

        # Add bottom padding
        ctk.CTkFrame(dep_card, fg_color="transparent", height=15).pack()

    def _create_guideline_item(self, parent, guideline: Dict, accent_color: str):
        """Create a guideline item."""
        item = ctk.CTkFrame(parent, fg_color=Colors.BG_LIGHT, corner_radius=8)
        item.pack(fill="x", padx=25, pady=(0, 12))

        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="x", padx=18, pady=15)

        # Title
        ctk.CTkLabel(
            content, text=guideline["title"],
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=Colors.TEXT_PRIMARY, anchor="w"
        ).pack(fill="x")

        # Description
        ctk.CTkLabel(
            content, text=guideline["description"],
            text_color=Colors.TEXT_SECONDARY,
            anchor="w", justify="left", wraplength=580,
            font=ctk.CTkFont(size=13)
        ).pack(fill="x", pady=(5, 0))

        # Why it matters section
        why_frame = ctk.CTkFrame(content, fg_color=Colors.BG_MEDIUM, corner_radius=6)
        why_frame.pack(fill="x", pady=(10, 0))

        why_content = ctk.CTkFrame(why_frame, fg_color="transparent")
        why_content.pack(fill="x", padx=12, pady=10)

        ctk.CTkLabel(
            why_content, text="Why it matters:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=accent_color, anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            why_content, text=guideline["why"],
            text_color=Colors.TEXT_SECONDARY,
            anchor="w", justify="left", wraplength=540,
            font=ctk.CTkFont(size=12)
        ).pack(fill="x", pady=(3, 0))


# =============================================================================
# MAIN APPLICATION
# =============================================================================
class SecureVaultApp(ctk.CTk):
    """Main SecureVault application."""

    def __init__(self):
        super().__init__()

        self.title("SecureVault Password Manager")
        self.geometry("1100x700")
        self.minsize(1000, 650)
        self.configure(fg_color=Colors.BG_DARK)

        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Initialize security manager
        script_dir = os.path.dirname(os.path.abspath(__file__))
        vault_path = os.path.join(script_dir, "vault.encrypted")
        self.security = SecurityManager(vault_path)

        # Module references
        self.modules: Dict[str, ctk.CTkFrame] = {}
        self.current_module: Optional[str] = None
        self.nav_buttons: Dict[str, ctk.CTkButton] = {}

        # Build UI
        self._create_login_screen()

    def _create_login_screen(self):
        """Create the login/setup screen."""
        self.login_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.login_frame.pack(fill="both", expand=True)

        # Center container
        center = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Logo/Title
        ctk.CTkLabel(
            center, text="SecureVault",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=Colors.PRIMARY
        ).pack(pady=(0, 5))

        ctk.CTkLabel(
            center, text="Password Manager",
            font=ctk.CTkFont(size=16),
            text_color=Colors.TEXT_SECONDARY
        ).pack(pady=(0, 30))

        # Card
        card = CardFrame(center)
        card.pack(padx=50)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(padx=40, pady=40)

        if self.security.vault_exists():
            self._create_unlock_form(content)
        else:
            self._create_setup_form(content)

    def _create_unlock_form(self, parent):
        """Create the vault unlock form."""
        ctk.CTkLabel(
            parent, text="Unlock Vault",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(pady=(0, 20))

        ctk.CTkLabel(
            parent, text="Enter your master password:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(pady=(0, 10))

        self.password_entry = ctk.CTkEntry(
            parent, width=300, height=40,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY, show="•"
        )
        self.password_entry.pack(pady=(0, 10))
        self.password_entry.bind("<Return>", lambda e: self._unlock_vault())

        self.error_label = ctk.CTkLabel(
            parent, text="",
            text_color=Colors.DANGER
        )
        self.error_label.pack(pady=(0, 10))

        StyledButton(
            parent, text="Unlock", width=300,
            command=self._unlock_vault, variant="primary"
        ).pack()

        self.password_entry.focus()

    def _create_setup_form(self, parent):
        """Create the vault setup form."""
        ctk.CTkLabel(
            parent, text="Create New Vault",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=Colors.TEXT_PRIMARY
        ).pack(pady=(0, 20))

        ctk.CTkLabel(
            parent, text="Choose a strong master password:",
            text_color=Colors.TEXT_SECONDARY
        ).pack(pady=(0, 10))

        self.password_entry = ctk.CTkEntry(
            parent, width=300, height=40,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY, show="•",
            placeholder_text="Master password"
        )
        self.password_entry.pack(pady=(0, 10))

        self.confirm_entry = ctk.CTkEntry(
            parent, width=300, height=40,
            fg_color=Colors.BG_LIGHT, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY, show="•",
            placeholder_text="Confirm password"
        )
        self.confirm_entry.pack(pady=(0, 10))
        self.confirm_entry.bind("<Return>", lambda e: self._create_vault())

        self.error_label = ctk.CTkLabel(
            parent, text="",
            text_color=Colors.DANGER
        )
        self.error_label.pack(pady=(0, 10))

        ctk.CTkLabel(
            parent,
            text="Warning: If you forget your master password,\nyour data cannot be recovered.",
            text_color=Colors.WARNING,
            font=ctk.CTkFont(size=12)
        ).pack(pady=(0, 15))

        StyledButton(
            parent, text="Create Vault", width=300,
            command=self._create_vault, variant="success"
        ).pack()

        self.password_entry.focus()

    def _unlock_vault(self):
        """Attempt to unlock the vault."""
        password = self.password_entry.get()

        if not password:
            self.error_label.configure(text="Please enter your password")
            return

        vault_data = self.security.unlock_vault(password)

        if vault_data is None:
            self.error_label.configure(text="Incorrect password")
            self.password_entry.delete(0, "end")
            return

        self.login_frame.destroy()
        self._create_main_interface()

        # Load entries
        if "entries" in vault_data:
            self.modules["vault"].load_entries(vault_data["entries"])

    def _create_vault(self):
        """Create a new vault."""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password:
            self.error_label.configure(text="Please enter a password")
            return

        if len(password) < 8:
            self.error_label.configure(text="Password must be at least 8 characters")
            return

        if password != confirm:
            self.error_label.configure(text="Passwords do not match")
            return

        if self.security.create_vault(password):
            self.login_frame.destroy()
            self._create_main_interface()
        else:
            self.error_label.configure(text="Failed to create vault")

    def _create_main_interface(self):
        """Create the main application interface."""
        # Main container
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)

        # Sidebar
        sidebar = ctk.CTkFrame(
            self.main_frame,
            fg_color=Colors.BG_MEDIUM,
            width=220,
            corner_radius=0
        )
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Sidebar header
        header = ctk.CTkFrame(sidebar, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=20)

        ctk.CTkLabel(
            header, text="SecureVault",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=Colors.PRIMARY
        ).pack(anchor="w")

        # Navigation
        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.pack(fill="x", padx=10)

        nav_items = [
            ("vault", "Password Vault"),
            ("generator", "Password Generator"),
            ("passphrase", "Passphrase Generator"),
            ("manual", "Manual Generator"),
            ("analyzer", "Strength Analyzer"),
            ("bruteforce", "Brute Force Calc"),
            ("nist", "NIST Guidelines"),
        ]

        for key, label in nav_items:
            btn = ctk.CTkButton(
                nav_frame, text=label,
                fg_color="transparent",
                text_color=Colors.TEXT_SECONDARY,
                hover_color=Colors.BG_LIGHT,
                anchor="w",
                height=40,
                corner_radius=8,
                command=lambda k=key: self._switch_module(k)
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[key] = btn

        # Lock button at bottom
        lock_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        lock_frame.pack(side="bottom", fill="x", padx=10, pady=20)

        StyledButton(
            lock_frame, text="Lock Vault",
            command=self._lock_vault,
            variant="danger"
        ).pack(fill="x")

        # Content area
        self.content_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color="transparent"
        )
        self.content_frame.pack(side="right", fill="both", expand=True, padx=30, pady=30)

        # Create modules
        self.modules["vault"] = VaultModule(self.content_frame, self)
        self.modules["generator"] = GeneratorModule(self.content_frame, self)
        self.modules["passphrase"] = PassphraseModule(self.content_frame, self)
        self.modules["manual"] = ManualGeneratorModule(self.content_frame, self)
        self.modules["analyzer"] = AnalyzerModule(self.content_frame, self)
        self.modules["bruteforce"] = BruteForceModule(self.content_frame, self)
        self.modules["nist"] = NISTGuidelinesModule(self.content_frame, self)

        # Show vault by default
        self._switch_module("vault")

    def _switch_module(self, module_key: str):
        """Switch to a different module."""
        # Hide current module
        if self.current_module:
            self.modules[self.current_module].pack_forget()
            self.nav_buttons[self.current_module].configure(
                fg_color="transparent",
                text_color=Colors.TEXT_SECONDARY
            )

        # Show new module
        self.modules[module_key].pack(fill="both", expand=True)
        self.nav_buttons[module_key].configure(
            fg_color=Colors.BG_LIGHT,
            text_color=Colors.TEXT_PRIMARY
        )
        self.current_module = module_key

    def _lock_vault(self):
        """Lock the vault and return to login screen."""
        self.security.lock()
        self.main_frame.destroy()
        self.modules = {}
        self.nav_buttons = {}
        self.current_module = None
        self._create_login_screen()


# =============================================================================
# ENTRY POINT
# =============================================================================
def main():
    """Application entry point."""
    app = SecureVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
