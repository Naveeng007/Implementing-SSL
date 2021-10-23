import textwrap
from typing import List
from convertors import *

'''
SHA-1 or Secure Hash Algorithm 1 is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value.
This hash value is known as a message digest.
This message digest is usually then rendered as a hexadecimal number which is 40 digits long.
'''


# Convert Text to Binary String
def text_to_binary(text: str) -> str:

    result = ''
    text_byte = text_to_bytes(text)

    for byte in text_byte:
        result += bin(byte)[2:].zfill(8)

    return result


# After Padding: (String) 1 (Extra 0s) (Length of String using 64bits)
def pad(text_bin: bytearray) -> str:

    length = len(text_bin)
    length_bin = bin(length)[2:].zfill(64)

    padded_bin = text_bin + '1' + ('0' * (448 - length - 1)) + length_bin
    return padded_bin


# Left Shift the 32b words by given number of Shifts
def left_shift(n: int, no_shift: int) -> int:
    nLeft = n << no_shift
    nRight = n >> (32 - no_shift)
    shifted = (nLeft | nRight) % (2**32)
    return shifted


# Get K according to iteration value
def get_K(iter: int) -> int:
    if iter < 20:
        return int("5A827999", 16)
    elif iter < 40:
        return int("6ED9EBA1", 16)
    elif iter < 60:
        return int("8F1BBCDC", 16)
    else:
        return int("CA62C1D6", 16)


# Compute f according to interation value
def compute_f(iter: int, hex_list: List[int]) -> int:
    if iter < 20:
        return (hex_list[1] & hex_list[2]) | (~hex_list[1] & hex_list[3])
    elif iter < 40:
        return hex_list[1] ^ hex_list[2] ^ hex_list[3]
    elif iter < 60:
        return (hex_list[1] & hex_list[2]) | (hex_list[1] & hex_list[3]) | (hex_list[2] & hex_list[3])
    else:
        return hex_list[1] ^ hex_list[2] ^ hex_list[3]


# Main SHA1 Algorithm
def main(bin: str, hex_list: List[int]) -> int:

    # These hex will be updated once per chunk
    hex_ori = list(hex_list)

    # Dividing into 512b chunks
    chunks = textwrap.wrap(bin, 512)

    for chunk in chunks:
        h = list(hex_ori)

        # Dividing into 32b words
        words = textwrap.wrap(chunk, 32)

        # Converting to Integer for easy implementation
        for i in range(16):
            words[i] = int(words[i], 2)

        # Performing 16-80 iterations
        for i in range(16, 80):
            words.append(words[i-3] ^ words[i-8] ^
                         words[i-14] ^ words[i-16])
            words[i] = left_shift(words[i], 1)

        # Performing 80 iterations
        for j in range(80):

            # Applying changes to hex_list
            temp = (left_shift(h[0], 5) + compute_f(j, h) +
                    h[4] + words[j] + get_K(j)) % (2**32)

            h[4] = h[3]
            h[3] = h[2]
            h[2] = left_shift(h[1], 30)
            h[1] = h[0]
            h[0] = temp

        # Updating the Original hex_list
        for i in range(5):
            hex_ori[i] = (h[i] + hex_ori[i]) % (2**32)

    # Computing Final Result
    result = (hex_ori[0] << 128) | (hex_ori[1] << 96) | (
        hex_ori[2] << 64) | (hex_ori[3] << 32) | (hex_ori[4])

    return result


def sha1(text: str) -> int:

    hex_list = [int("67452301", 16), int("EFCDAB89", 16), int(
        "98BADCFE", 16), int("10325476", 16), int("C3D2E1F0", 16)]

    text_bin = text_to_binary(text)
    text_bin_padded = pad(text_bin)
    return main(text_bin_padded, hex_list)


print(hex(sha1('abcd')))
