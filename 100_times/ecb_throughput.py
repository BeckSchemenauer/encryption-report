import os
import time
import tracemalloc
import psutil
import csv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16  # AES block size in bytes

# AES Encryption in ECB mode
def aes_encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, BLOCK_SIZE))


def aes_decrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), BLOCK_SIZE)


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
encrypt_throughputs = {16: [], 24: [], 32: []}
decrypt_throughputs = {16: [], 24: [], 32: []}

for file_size in file_sizes:
    for key_size in encrypt_throughputs.keys():
        filename = f'../test_files/test_{file_size}MB.txt'

        # Track throughput and memory usage
        encryption_throughput = []
        decryption_throughput = []
        memory_usage = []
        total_encryption_time = 0
        total_decryption_time = 0

        for iteration in range(100):  # Run 100 times
            print(iteration)
            # Start memory tracking
            tracemalloc.start()
            initial_memory = log_memory_usage()

            # Measure encryption and decryption times
            with open(filename, 'rb') as f:
                data = f.read()

            encryption_time, decryption_time = measure_speed_ecb(data, key_size)

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

        # Log average results for 5 iterations
        avg_encryption_throughput = sum(encryption_throughput) / len(encryption_throughput)
        avg_decryption_throughput = sum(decryption_throughput) / len(decryption_throughput)

        encrypt_throughputs[key_size].append(avg_encryption_throughput)
        decrypt_throughputs[key_size].append(avg_decryption_throughput)

        # Print results
        print(f"File: {filename}, AES-{key_size * 8} ECB: Avg Encryption Throughput: "
              f"{avg_encryption_throughput:.2f} MB/s, "
              f"Avg Decryption Throughput: {avg_decryption_throughput:.2f} MB/s")
        print(f"Total Encryption Time: {total_encryption_time:.2f} seconds, "
              f"Total Decryption Time: {total_decryption_time:.2f} seconds")

# Prepare data for CSV
encrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
decrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

for key_size in encrypt_throughputs.keys():
    encrypt_throughput_data.append([f"AES-{key_size * 8} ECB"] + encrypt_throughputs[key_size])
    decrypt_throughput_data.append([f"AES-{key_size * 8} ECB"] + decrypt_throughputs[key_size])

# Save throughput results to CSV
save_to_csv('../dataframes/encryption_throughputs_ecb.csv', encrypt_throughput_data)
save_to_csv('../dataframes/decryption_throughputs_ecb.csv', decrypt_throughput_data)
