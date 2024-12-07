import time
import csv
from Crypto.Cipher import ARC4
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import os


def rc4_encrypt(data, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def rc4_decrypt(data, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def chacha20_encrypt(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)


def chacha20_decrypt(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)


def measure_file_speed_rc4(data, key_size):

    # Measure encryption time
    start = time.perf_counter()

    # Generate a key for RC4
    key = get_random_bytes(key_size)

    encrypted_data = rc4_encrypt(data, key)
    encryption_time = time.perf_counter() - start

    # Measure decryption time
    start = time.perf_counter()
    rc4_decrypt(encrypted_data, key)
    decryption_time = time.perf_counter() - start

    return encryption_time, decryption_time


def measure_file_speed_chacha20(data, key_size):

    # Measure encryption time
    start = time.perf_counter()

    # Generate a key and nonce for ChaCha20
    key = get_random_bytes(key_size)
    nonce = get_random_bytes(8)  # ChaCha20 requires an 8-byte nonce

    encrypted_data = chacha20_encrypt(data, key, nonce)
    encryption_time = time.perf_counter() - start

    # Measure decryption time
    start = time.perf_counter()
    chacha20_decrypt(encrypted_data, key, nonce)
    decryption_time = time.perf_counter() - start

    return encryption_time, decryption_time


def save_to_csv(file_name, data):
    """Save the results to a CSV file."""
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)


def test_file_sizes():
    # Test different file sizes
    file_sizes = [1, 10, 100, 1000]  # File sizes in MB
    rc4_encrypt_times = {16: [], 24: [], 32: []}
    rc4_decrypt_times = {16: [], 24: [], 32: []}
    chacha20_encrypt_times = {32: []}
    chacha20_decrypt_times = {32: []}

    for file_size in file_sizes:
        for key_size in rc4_encrypt_times.keys():
            filename = f'../test_files/test_{file_size}MB.txt'

            # Measure encryption and decryption times
            with open(filename, 'rb') as f:
                data = f.read()

            # Measure RC4 times
            rc4_encryption_time, rc4_decryption_time = measure_file_speed_rc4(data, key_size)

            # Accumulate total times for each algorithm
            rc4_encrypt_times[key_size].append(rc4_encryption_time)
            rc4_decrypt_times[key_size].append(rc4_decryption_time)

            # Measure ChaCha20 times
            if key_size == 32:
                chacha20_encryption_time, chacha20_decryption_time = measure_file_speed_chacha20(data, key_size)
                chacha20_encrypt_times[key_size].append(chacha20_encryption_time)
                chacha20_decrypt_times[key_size].append(chacha20_decryption_time)

    # Prepare data for CSV
    encrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
    decrypt_time_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

    for key_size in rc4_encrypt_times.keys():
        encrypt_time_data.append([f"RC4-{key_size * 8}"] + rc4_encrypt_times[key_size])
        decrypt_time_data.append([f"RC4-{key_size * 8}"] + rc4_decrypt_times[key_size])

    for key_size in chacha20_encrypt_times.keys():
        encrypt_time_data.append([f"ChaCha20-{key_size * 8}"] + chacha20_encrypt_times[key_size])
        decrypt_time_data.append([f"ChaCha20-{key_size * 8}"] + chacha20_decrypt_times[key_size])

    # Save throughput results to CSV
    save_to_csv('../dataframes/encryption/stream_cipher_encryption_times.csv', encrypt_time_data)
    save_to_csv('../dataframes/decryption/stream_cipher_decryption_times.csv', decrypt_time_data)


test_file_sizes()
