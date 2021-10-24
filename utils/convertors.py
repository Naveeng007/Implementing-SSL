import math


# Converts Integer to Binary, padded up to given length
def int_to_binary(n: int, length: int):
    n_bytes = bytearray(length)

    while length > 0:
        length -= 1
        n_bytes[length] = int(n & 255)
        n >>= 8

    return n_bytes


# Converts Binary to Integer
def binary_to_int(byte_array: bytearray):
    result = 0

    for x in byte_array:
        result <<= 8
        result += x

    return result


# Gets the Minimum bytes required to represent Integer (unsigned)
def req_bytes(n: int):
    if n < 1:
        return 1

    length = 0
    while n > 0:
        n >>= 1
        length += 1

    return int(math.ceil(length / 8))


# Converts Text to Bytes
def text_to_bytes(text: str):
    length = len(text)
    text_bytes = bytearray(length)

    for i in range(length):
        text_bytes[i] = ord(text[i])

    return text_bytes


# Converts Bytes to Text
def bytes_to_text(byte_array: bytearray):
    result = ''

    for x in byte_array:
        result += chr(x)

    return result
