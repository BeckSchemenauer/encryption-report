import time
import tracemalloc
import psutil
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import csv


# ChaCha20 encryption function
def chacha20_encrypt(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)


# ChaCha20 decryption function
def chacha20_decrypt(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)


# Measure file speed for ChaCha20
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
encrypt_throughputs = {32: []}
decrypt_throughputs = {32: []}

for file_size in file_sizes:
    for key_size in encrypt_throughputs.keys():
        filename = f'../test_files/test_{file_size}MB.txt'

        # Track throughput and memory usage
        encryption_throughput = []
        decryption_throughput = []
        memory_usage = []
        total_encryption_time = 0
        total_decryption_time = 0

        for iteration in range(10):  # Run 100 times
            print(iteration)

            # Start memory tracking
            tracemalloc.start()
            initial_memory = log_memory_usage()

            # Read file data
            with open(filename, 'rb') as f:
                data = f.read()

            # Measure encryption and decryption times
            encryption_time, decryption_time = measure_file_speed_chacha20(
                data, key_size,
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

        # Log average results for each file size/key size combination
        encrypt_throughputs[key_size].append(sum(encryption_throughput) / len(encryption_throughput))
        decrypt_throughputs[key_size].append(sum(decryption_throughput) / len(decryption_throughput))

        # Print results
        print(f"File: {filename}, ChaCha20-{key_size * 8}-bit: Avg Encryption Throughput: "
              f"{sum(encryption_throughput) / len(encryption_throughput):.2f} MB/s, "
              f"Avg Decryption Throughput: {sum(decryption_throughput) / len(decryption_throughput):.2f} MB/s, "
              f"Avg Memory Usage: {sum(memory_usage) / len(memory_usage):.2f} MB")
        print(f"Total Encryption Time: {total_encryption_time:.2f} seconds, "
              f"Total Decryption Time: {total_decryption_time:.2f} seconds")


# Prepare data for CSV
encrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]
decrypt_throughput_data = [["Method"] + [f"{size}MB" for size in file_sizes]]

# Add results for ChaCha20-256-bit
for key_size in encrypt_throughputs.keys():
    encrypt_throughput_data.append([f"ChaCha20-{key_size * 8}-bit"] + encrypt_throughputs[key_size])
    decrypt_throughput_data.append([f"ChaCha20-{key_size * 8}-bit"] + decrypt_throughputs[key_size])

# Save throughput results to CSV
save_to_csv('../dataframes/throughput/chacha20_encryption_throughputs.csv', encrypt_throughput_data)
save_to_csv('../dataframes/throughput/chacha20_decryption_throughputs.csv', decrypt_throughput_data)
