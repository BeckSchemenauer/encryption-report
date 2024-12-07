import os
import tracemalloc
import psutil
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time
import csv


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


# Track memory usage
def log_memory_usage():
    process = psutil.Process()
    mem_info = process.memory_info()
    return mem_info.rss / (1024 * 1024)  # Memory in MB


# Save results to CSV
def save_to_csv(file_name, data):
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)


# Test different file sizes
file_sizes = [1, 10, 100, 1000]  # File sizes in MB
encrypt_throughputs = []
decrypt_throughputs = []

for file_size in file_sizes:
    filename = f'../test_files/test_{file_size}MB.txt'

    # Track throughput and memory usage
    encryption_throughput = []
    decryption_throughput = []
    memory_usage = []
    total_encryption_time = 0
    total_decryption_time = 0

    for iteration in range(100):  # Run 100 times
        print(iteration)

        # Read file data
        with open(filename, 'rb') as f:
            data = f.read()

        # Start memory tracking
        tracemalloc.start()
        initial_memory = log_memory_usage()

        # Measure encryption and decryption times
        encryption_time, decryption_time = measure_speed_ecc(
            data
        )

        # Accumulate total times
        total_encryption_time += encryption_time
        total_decryption_time += decryption_time

        # Calculate throughput (MB/s)
        encryption_throughput.append(file_size / encryption_time)
        decryption_throughput.append(file_size / decryption_time)

        # Track memory usage
        current_memory = log_memory_usage()
        memory_usage.append(current_memory)

        # Stop memory tracking
        tracemalloc.stop()

    # Log average results for 100 iterations
    avg_encryption_throughput = sum(encryption_throughput) / len(encryption_throughput)
    avg_decryption_throughput = sum(decryption_throughput) / len(decryption_throughput)
    avg_memory_usage = sum(memory_usage) / len(memory_usage)

    encrypt_throughputs.append(avg_encryption_throughput)
    decrypt_throughputs.append(avg_decryption_throughput)

    # Print results
    print(f"File: {filename}, ECC Encryption: Avg Encryption Throughput: "
          f"{avg_encryption_throughput:.2f} MB/s, "
          f"Avg Decryption Throughput: {avg_decryption_throughput:.2f} MB/s, "
          f"Avg Memory Usage: {avg_memory_usage:.2f} MB")
    print(f"Total Encryption Time: {total_encryption_time:.2f} seconds, "
          f"Total Decryption Time: {total_decryption_time:.2f} seconds")

# Prepare data for CSV
encrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
decrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

# Add results for each key size
encrypt_throughput_data.append(["ECC Encryption"] + encrypt_throughputs)
decrypt_throughput_data.append(["ECC Decryption"] + decrypt_throughputs)

# Save throughput results to CSV
save_to_csv('../dataframes/throughput/ecc_encryption_throughputs.csv', encrypt_throughput_data)
save_to_csv('../dataframes/throughput/ecc_decryption_throughputs.csv', decrypt_throughput_data)
