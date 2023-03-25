# Password Manager
A simple and secure password manager to store and manage your passwords locally.

##Features
- Securely encrypts and stores your passwords using a master password.
- Generate strong random passwords.
- Copy passwords to clipboard for easy use.
- User-friendly graphical interface.

## Installation
1. Make sure you have Python 3.6 or higher installed. You can download it from python.org.
2. Install the required packages:

```bash
pip install cryptography pyperclip
```

3. Clone this repository or download the source code:

```bash
git clone https://github.com/your-username/password-manager.git
```

## Usage
1. Navigate to the project directory:
```bash
cd password-manager
```
2. Run the application:
```bash
python app.py
```

3. The application will ask you to set a master password if it's your first time using it. This master password will be used to encrypt and decrypt your stored passwords.

4. You can now use the application to add, retrieve, or modify passwords for different websites or applications. All passwords are encrypted using your master password and stored in a local file.

## Security
This password manager uses the Fernet symmetric encryption provided by the cryptography library. The master password is hashed using the PBKDF2HMAC key derivation function with a random salt. The encrypted passwords and salt are stored locally in separate files.

Please note that the security of this password manager depends on the strength of your master password and the security of your local environment. Make sure to choose a strong master password and keep your computer secure.

## License
This project is open source and available under the MIT License.

## Disclaimer
This password manager is a personal project and should be used at your own risk. The author is not responsible for any loss of data, security breaches, or other issues that may arise from using this software.
