import pyotp
import qrcode

def generate_totp_secret():
    secret = pyotp.random_base32()
    return secret

def display_qr_code(secret):
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri("user@example.com", issuer_name="PasswordManagerApp")
    qr = qrcode.QRCode()
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.show()