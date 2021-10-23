from Crypto.Cipher import AES
import sha1
import base64


# TODO Pads and encrypts a message using a given master secret
def encrypt_message(array, master_secret):
    # create NEW AES object
    aes = AES.new(sha1.digestToString(master_secret)
                  [:16], AES.MODE_CBC, 16 * '\00')
    # Pad the array, encrypt it, and convert it to base64
    return base64.b64encode(aes.encrypt(bytes(array + (16 - len(array)) % 16 * '\x00')))


# Decrypts a message using a given master secret
def decrypt_message(byte_array, master_secret):
    # create NEW AES object
    aes = AES.new(sha1.digestToString(master_secret)
                  [:16], AES.MODE_CBC, 16 * '\00')
    # Decode from base64, decrypt and convert to bytearray
    return bytearray(aes.decrypt(base64.b64decode(byte_array)))
