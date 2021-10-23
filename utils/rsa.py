from convertors import *

'''
RSA abbreviation is Rivest–Shamir–Adleman.
It is an asymmetric cryptographic algorithm which means that there are two different keys i.e., the public key and the private key. 
Since this is asymmetric, nobody else except the browser can decrypt the data even if a third-party user has a public key in the browser.
'''


# Encrypt the message m using key (e, n)
def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


# Encrypt the cipher c using key (d, n)
def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


# Converts Text to Decimal Representation
def text_to_decimal(m_text: str) -> int:

    # Converting to Hex
    m_hex = text_to_bytes(m_text).hex()

    # Converting to Integer
    m_dec = int(m_hex, 16)

    return m_dec


# Converts Text in Decimal Representation to String
def decimal_to_text(m_dec: int, length) -> str:

    # Converting to byte array
    m_bytes = int_to_binary(m_dec, length)

    # Converting to Text
    m_text = bytes_to_text(m_bytes)

    return m_text
