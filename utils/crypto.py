import base64
from Crypto.Cipher import AES


def digestToString(a):
    aStr = hex(a)
    hexHash = aStr[2:len(aStr)-1].zfill(40)
    assert len(hexHash) == 40
    return hexHash


# Pads and encrypts a message using a given master secret
def encrypt_message(array, master_secret):

    # Create new AES object
    aes = AES.new(digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')

    # Pad the array, encrypt it, and convert it to base64
    return base64.b64encode(aes.encrypt(bytes(array + bytearray((16 - len(array)) % 16))))


# Decrypts the message using a given master secret
def decrypt_message(byte_array, master_secret):

    # Create new AES object
    aes = AES.new(digestToString(master_secret)[:16], AES.MODE_CBC, 16 * '\00')

    # Decode from base64, decrypt and convert to bytearray
    return bytearray(aes.decrypt(base64.b64decode(byte_array)))
