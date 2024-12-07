import os
import time
import csv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16  # AES block size in bytes


# AES Encryption in ECB and CBC modes
def aes_encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, BLOCK_SIZE))


def aes_decrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), BLOCK_SIZE)


def aes_encrypt_cbc(data, key):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, BLOCK_SIZE))  # Prepend IV to encrypted data


def aes_decrypt_cbc(data, key):
    iv, encrypted_data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)


def measure_speed_ecb(data, key_size):

    # Encryption
    start_time = time.perf_counter()
    key = get_random_bytes(key_size)
    encrypted_data = aes_encrypt_ecb(data, key)
    encryption_time = time.perf_counter() - start_time

    # Decryption
    start_time = time.perf_counter()
    decrypted_data = aes_decrypt_ecb(encrypted_data, key)
    decryption_time = time.perf_counter() - start_time

    assert decrypted_data == data, "Decrypted data does not match original!"
    return encryption_time, decryption_time


def measure_speed_cbc(data, key_size):

    # Encryption
    start_time = time.perf_counter()
    key = get_random_bytes(key_size)
    encrypted_data = aes_encrypt_cbc(data, key)
    encryption_time = time.perf_counter() - start_time

    # Decryption
    start_time = time.perf_counter()
    decrypted_data = aes_decrypt_cbc(encrypted_data, key)
    decryption_time = time.perf_counter() - start_time

    assert decrypted_data == data, "Decrypted data does not match original!"
    return encryption_time, decryption_time


def save_to_csv(file_name, data):
    """Save the results to a CSV file."""
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)


def test_file_sizes():
    # Test different file sizes
    file_sizes = [1, 10, 100, 1000]  # File sizes in MB
    cbc_encrypt_times = {16: [], 24: [], 32: []}
    cbc_decrypt_times = {16: [], 24: [], 32: []}
    ecb_encrypt_times = {16: [], 24: [], 32: []}
    ecb_decrypt_times = {16: [], 24: [], 32: []}

    for file_size in file_sizes:
        for key_size in cbc_encrypt_times.keys():
            filename = f'../test_files/test_{file_size}MB.txt'

            # Measure encryption and decryption times
            with open(filename, 'rb') as f:
                data = f.read()

            cbc_encryption_time, cbc_decryption_time = measure_speed_cbc(data, key_size)
            ecb_encryption_time, ecb_decryption_time = measure_speed_ecb(data, key_size)

            # Accumulate total times
            cbc_encrypt_times[key_size].append(cbc_encryption_time)
            cbc_decrypt_times[key_size].append(cbc_decryption_time)
            ecb_encrypt_times[key_size].append(ecb_encryption_time)
            ecb_decrypt_times[key_size].append(ecb_decryption_time)

    # Prepare data for CSV
    encrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
    decrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

    for key_size in cbc_encrypt_times.keys():
        encrypt_time_data.append([f"AES-{key_size * 8} CBC"] + cbc_encrypt_times[key_size])
        decrypt_time_data.append([f"AES-{key_size * 8} CBC"] + cbc_decrypt_times[key_size])
        encrypt_time_data.append([f"AES-{key_size * 8} ECB"] + ecb_encrypt_times[key_size])
        decrypt_time_data.append([f"AES-{key_size * 8} ECB"] + ecb_decrypt_times[key_size])


    # Save throughput results to CSV
    save_to_csv('../dataframes/encryption/aes_encryption_times.csv', encrypt_time_data)
    save_to_csv('../dataframes/decryption/aes_decryption_times.csv', decrypt_time_data)


test_file_sizes()
