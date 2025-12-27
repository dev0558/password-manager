# SecureVault Password Manager

A production-ready desktop password manager built with Python and CustomTkinter, implementing NIST SP 800-63B Digital Identity Guidelines and industry-standard cryptographic practices.

## Features

### Password Vault
- Secure storage for service credentials (service name, username, password, notes)
- Full-text search across all stored entries
- Real-time password strength indicators
- Copy-to-clipboard functionality
- Create, read, update, and delete operations

### Password Generator
- Configurable length (8-64 characters)
- Toggle options for character types (uppercase, lowercase, digits, symbols)
- Option to exclude ambiguous characters (I, l, 1, O, 0)
- Real-time strength and entropy display

### Passphrase Generator
- Word count selection (3-8 words)
- Configurable separator characters
- Optional word capitalization
- Optional number suffix

### Manual Generator
- Custom character set input
- Generate passwords using only specified characters
- Useful for systems with specific password requirements

### Password Strength Analyzer
- Entropy calculation in bits
- Pattern detection (sequential, repeated, keyboard patterns)
- Common password checking
- Actionable feedback based on NIST guidelines

### Brute Force Calculator
- Crack time estimation across multiple attack scenarios:
  - Online (rate-limited)
  - Online (unlimited)
  - Offline CPU
  - Single GPU
  - GPU Cluster
  - Bcrypt protected
  - Nation-state level

### NIST Guidelines Reference
- Key recommendations from SP 800-63B
- Both recommended and deprecated practices
- Educational context for each guideline

## Security Implementation

### Master Password Protection
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations
- Cryptographically secure 16-byte random salt per vault
- Master password never stored in any form

### Data Encryption
- Fernet symmetric encryption (AES-128-CBC with HMAC)
- Entire vault contents encrypted before writing to disk
- Secure memory handling where possible

### Random Generation
- All random operations use Python's `secrets` module
- Cryptographically secure random number generation

## Installation

### Requirements
- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. Clone or download the repository

2. Navigate to the securevault directory:
   ```bash
   cd securevault
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

## Usage

### First Run
1. Launch the application
2. Create a master password (minimum 8 characters recommended)
3. Confirm your master password
4. Your vault is now ready to use

### Subsequent Runs
1. Launch the application
2. Enter your master password to unlock the vault

### Adding Passwords
1. Navigate to "Password Vault" in the sidebar
2. Click "+ Add Entry"
3. Fill in service name, username, password, and optional notes
4. Click "Generate" to create a random password, or enter your own
5. Click "Save"

### Managing Passwords
- **Copy**: Click "Copy" to copy the password to clipboard
- **Edit**: Click "Edit" to modify an entry
- **Delete**: Click "Delete" to remove an entry
- **Search**: Use the search bar to filter entries

### Locking the Vault
- Click "Lock Vault" in the sidebar to secure your data
- You'll need to enter your master password again to access entries

## File Structure

```
securevault/
    main.py              # Application entry point and all modules
    vault.encrypted      # Encrypted password storage (created at runtime)
    requirements.txt     # Python dependencies
    README.md           # This documentation
```

## Color Palette

The application uses a professional dark theme with the following colors:
- Background Dark: #0a0f1a
- Background Medium: #111827
- Background Light: #1e293b
- Primary Blue: #3b82f6
- Cyan Accent: #06b6d4
- Success: #10b981
- Warning: #f59e0b
- Danger: #ef4444

## Security Best Practices

1. **Choose a strong master password**: Use a passphrase of 4+ random words or a password of 15+ characters
2. **Never share your master password**: There is no recovery option if forgotten
3. **Keep your system secure**: Use full-disk encryption and keep your OS updated
4. **Regular backups**: Back up your `vault.encrypted` file to secure storage

## Technical Notes

- The application runs entirely offline with no network dependencies
- All cryptographic operations follow NIST recommendations
- The vault file is encrypted with AES and authenticated with HMAC
- Password strength calculations use entropy-based analysis

## Dependencies

- `customtkinter>=5.2.0` - Modern UI framework
- `cryptography>=41.0.0` - Cryptographic operations

## Platform Support

- Windows
- macOS
- Linux

## License

This software is provided for educational and personal use.
