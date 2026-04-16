# SecureVault - Encrypted File Storage System

A secure, end-to-end encrypted file storage and sharing platform built with Flask. Features RSA-2048 and AES encryption, JWT authentication, and comprehensive audit logging.

## 📋 Overview

SecureVault is a network security project developed for CS3403 at RV University. It provides:

- **Secure Authentication**: User registration and login with SHA-256 password hashing
- **Encrypted File Storage**: AES encryption for stored files with RSA-2048 key exchange
- **File Sharing**: Secure file sharing between users with revocable access
- **Audit Logging**: Complete audit trail of all user actions and security events
- **Web Interface**: Clean, user-friendly HTML5 client

## ✨ Features

### Security
- ✅ SHA-256 password hashing with secure storage
- ✅ JWT (HS256) token-based authentication (24-hour expiry)
- ✅ RSA-2048 asymmetric encryption
- ✅ AES symmetric encryption for file storage
- ✅ Tamper detection via file hash validation
- ✅ Comprehensive audit logging and security alerts

### File Management
- ✅ Upload and download encrypted files
- ✅ File size and type validation
- ✅ Secure file sharing with other users
- ✅ Revocable file access
- ✅ File deletion with proper cleanup

### Monitoring
- ✅ Audit trail for all operations
- ✅ Security alert generation
- ✅ User activity tracking
- ✅ Access denial logging

## 🛠️ Technology Stack

- **Backend**: Flask 3.0.0
- **Authentication**: PyJWT 2.8.0
- **Encryption**: cryptography 41.0.7
- **CORS**: flask-cors 4.0.0
- **Database**: SQLite with WAL mode for concurrent access
- **Frontend**: HTML5, CSS3, JavaScript

## 📁 Project Structure

```
sv2/
├── run.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── client/
│   └── index.html           # Web interface
├── server/
│   ├── auth.py              # Authentication & JWT handling
│   ├── encryption.py        # RSA & AES encryption
│   ├── file_handler.py      # File upload/download/sharing
│   ├── audit_log.py         # Audit logging
│   └── __init__.py
├── database/
│   ├── models.py            # Database schema & queries
│   └── __init__.py
├── encrypted_storage/       # Encrypted files storage
├── keys/                    # RSA key pairs
└── tests/
    └── test_all.py          # Test suite
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SecureVault.git
   cd SecureVault/sv2
   ```

2. **Create a virtual environment** (optional but recommended)
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the server**
   ```bash
   python run.py
   ```

5. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`
   - Register a new account or login

## 🔐 Security Protocols

### Authentication Flow
1. User registers with username and password
2. Password is hashed using SHA-256
3. Upon login, JWT token is generated (valid for 24 hours)
4. All subsequent requests require valid JWT token in Authorization header

### File Encryption Flow
1. User uploads file
2. File is encrypted using AES encryption
3. Encryption key is wrapped with user's RSA public key
4. File hash is computed for tamper detection
5. Encrypted file is stored securely

### File Sharing
1. File owner grants access to another user
2. File key is re-encrypted with recipient's RSA public key
3. Recipient can decrypt and download the file
4. Owner can revoke access at any time

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password_hash`: SHA-256 hashed password
- `created_at`: Account creation timestamp

### Files Table
- `id`: Primary key
- `user_id`: Owner user ID
- `filename`: Original filename
- `file_hash`: SHA-256 hash for tamper detection
- `encrypted_filename`: Encrypted storage filename
- `created_at`: Upload timestamp

### Audit Logs Table
- `id`: Primary key
- `user_id`: Acting user
- `action`: Operation performed
- `details`: Additional details
- `status`: Success/Failure
- `timestamp`: Action timestamp

## 📡 API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User login
- `GET /users` - Get all users (for sharing)

### Files
- `POST /upload` - Upload encrypted file
- `GET /download/<file_id>` - Download encrypted file
- `GET /files` - List user's files
- `POST /share` - Share file with another user
- `POST /revoke_share` - Revoke file access
- `DELETE /delete/<file_id>` - Delete file

### Audit & Security
- `GET /audit_logs` - View audit logs
- `GET /security_alerts` - View security alerts
- `GET /log_stats` - View log statistics

## 🧪 Testing

Run the test suite:
```bash
python -m pytest tests/test_all.py -v
```

Or execute directly:
```bash
python tests/test_all.py
```

## 🔑 Environment Variables

You can customize the following via environment variables:

```bash
JWT_SECRET=your_secret_key
```

Default JWT_SECRET: `CS3403_SecureVault_RVU_2025!`

## ⚠️ Important Notes

- **Development Only**: This is an educational project. Do not use in production without additional security hardening.
- **Key Management**: RSA keys are stored in the `keys/` directory. Protect these files carefully.
- **Database Persistence**: SQLite database uses WAL mode for concurrent access support.
- **File Storage**: Encrypted files are stored in `encrypted_storage/` directory.

## 👥 Contributors

- **Course**: CS3403 Network Security
- **Institution**: RV University
- **Year**: 2025

## 📝 License

This project is provided for educational purposes as part of the CS3403 Network Security course.

## 🤝 Support

For issues, questions, or suggestions, please contact your course instructor or create an issue in the repository.

---

**Built with ❤️ for Network Security Education**
