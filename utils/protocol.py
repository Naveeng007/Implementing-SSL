from utils.convertors import *
import Crypto.PublicKey.RSA


class Error_Codes():
    UNEXPECTED_MESSAGE_TYPE = 1
    UNKNOWN_MESSAGE_TYPE = 2
    LENGTH_ERROR = 3
    BAD_SESSION_ID = 4
    UNSUPPORTED_FIELD = 5
    UNSUPPORTED_STRUCTURE = 6
    INCORRECT_SERVER_CERTIFICATE = 7
    INCORRECT_CLIENT_CERTIFICATE = 8
    INCORRECT_LOGIN = 9
    BAD_ENCRYPTION = 10
    UNKNOWN_ERROR = 11


# Read the Certificate from file
def load_certificate(certificate_file: str):
    cert = ''
    with open(certificate_file) as f:
        cert = text_to_bytes(f.read())
    return cert


# Read the private Key from File
def load_private_key(private_key_file: str):
    key = ''
    with open(private_key_file) as f:
        key = Crypto.PublicKey.RSA.importKey(f.read())

    print(key)
    return key
