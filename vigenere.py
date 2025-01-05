import base64
from itertools import product

def generate_keys(alphabet, max_length):
    for length in range(1, max_length + 1):
        for key in product(alphabet, repeat=length):
            yield ''.join(key)

def is_valid_text(text):
    return any(char.isalpha() for char in text)

def vigenere_encrypt(text, key):
    if not isinstance(key, str):
        raise ValueError("Key harus berupa string")
    encrypted = []
    key = key.lower()
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if char.islower():
                encrypted.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                encrypted.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    if not isinstance(key, str):
        raise ValueError("Key harus berupa string")
    plaintext = []
    key = key.lower()
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('a')
            if char.islower():
                plaintext.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            else:
                plaintext.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            plaintext.append(char)
    return ''.join(plaintext)

def bruteforce_vigenere(ciphertext, max_length, alphabet='abcdefghijklmnopqrstuvwxyz'):
    possible_keys = generate_keys(alphabet, max_length)
    results = []

    for key in possible_keys:
        decrypted_text = vigenere_decrypt(ciphertext, key)
        if is_valid_text(decrypted_text):
            results.append(f"Key: {key}, Decrypted: {decrypted_text}")
    
    return results