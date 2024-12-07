import os
import time
import csv
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ECC Key Agreement (ECDH) to derive shared key
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES key size
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


def generate_ecc_key(curve):
    return ec.generate_private_key(curve, default_backend())


def aes_encrypt_cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)


def aes_decrypt_cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


# AES Encryption using the derived ECC shared key
def ecc_encrypt(data, private_key, peer_public_key):
    shared_key = derive_shared_key(private_key, peer_public_key)
    iv = os.urandom(16)  # Generate a random IV for AES
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)  # Pad data
    encrypted_data = aes_encrypt_cbc(padded_data, shared_key, iv)
    return encrypted_data, iv


# AES Decryption using the derived ECC shared key
def ecc_decrypt(encrypted_data, private_key, peer_public_key, iv):
    shared_key = derive_shared_key(private_key, peer_public_key)
    decrypted_data = aes_decrypt_cbc(encrypted_data, shared_key, iv)
    padding_length = decrypted_data[-1]
    unpadded_data = decrypted_data[:-padding_length]  # Remove padding
    return unpadded_data


# Measure encryption and decryption time
def measure_speed_ecc(data):

    # Measure encryption time
    start = time.time()

    # Generate ECC key pair for testing
    private_key = generate_ecc_key(ec.SECP256R1())
    peer_private_key = generate_ecc_key(ec.SECP256R1())
    peer_public_key = peer_private_key.public_key()

    encrypted_data, iv = ecc_encrypt(data, private_key, peer_public_key)
    encryption_time = time.time() - start

    # Measure decryption time
    start = time.time()
    ecc_decrypt(encrypted_data, private_key, peer_public_key, iv)
    decryption_time = time.time() - start

    return encryption_time, decryption_time


def save_to_csv(file_name, data):
    """Save the results to a CSV file."""
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)


def test_file_sizes():
    # Test different file sizes
    file_sizes = [1, 10, 100, 1000]  # File sizes in MB
    ecc_encrypt_times = {16: [], 24: [], 32: []}
    ecc_decrypt_times = {16: [], 24: [], 32: []}

    for file_size in file_sizes:
        for key_size in ecc_encrypt_times.keys():
            filename = f'../test_files/test_{file_size}MB.txt'

            # Measure encryption and decryption times
            with open(filename, 'rb') as f:
                data = f.read()

            ecc_encryption_time, ecc_decryption_time = measure_speed_ecc(data)

            # Accumulate total times
            ecc_encrypt_times[key_size].append(ecc_encryption_time)
            ecc_decrypt_times[key_size].append(ecc_decryption_time)

    # Prepare data for CSV
    encrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
    decrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

    for key_size in ecc_encrypt_times.keys():
        encrypt_time_data.append([f"CBC-{key_size * 8} with ECC"] + ecc_encrypt_times[key_size])
        decrypt_time_data.append([f"CBC-{key_size * 8} with ECC"] + ecc_decrypt_times[key_size])

    # Save throughput results to CSV
    save_to_csv('../dataframes/encryption/ecc_encryption_times.csv', encrypt_time_data)
    save_to_csv('../dataframes/decryption/ecc_decryption_times.csv', decrypt_time_data)


test_file_sizes()
