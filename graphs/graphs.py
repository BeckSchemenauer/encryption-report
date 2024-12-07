import os

import pandas as pd
import matplotlib.pyplot as plt


def plot_times(df, figure_name):

    if "encrypt" in figure_name:
        mode = "Encryption"
    else:
        mode = "Decryption"

    x = [1, 10, 100, 1000]  # File sizes in MB
    plt.figure(figsize=(10, 6))

    for index, row in df.iterrows():
        plt.plot(x, row[1:], label=row[0], marker='o')  # Plot each row, skipping the first column

    # Customize the plot
    plt.title(f"{mode} Time vs File Size", fontsize=14)
    plt.xlabel("File Size (MB)", fontsize=12)
    plt.ylabel("Encryption Time (seconds)", fontsize=12)
    plt.xscale('log')  # Optional: Use a log scale for file sizes if appropriate
    plt.legend(title="Encryption Techniques", fontsize=10)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    plt.savefig(figure_name)

    # Show the plot
    plt.tight_layout()
    plt.show()


def plot_throughput(df, figure_name):
    x = [1, 10, 100, 1000]  # File sizes in MB
    plt.figure(figsize=(10, 6))

    for index, row in df.iterrows():
        plt.plot(x, row[1:], label=row[0], marker='o')  # Plot each row, skipping the first column

    # Customize the plot
    plt.title("Throughput vs File Size", fontsize=14)
    plt.xlabel("File Size (MB)", fontsize=12)
    plt.ylabel("Throughput (MB/s)", fontsize=12)
    plt.xscale('log')  # Optional: Use a log scale for file sizes if appropriate
    plt.legend(title="Encryption Techniques", fontsize=10)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    plt.savefig(figure_name)

    # Show the plot
    plt.tight_layout()
    plt.show()


# Encrypt / Decrypt Data
aes_encrypt_df = pd.read_csv("../dataframes/encryption/aes_encryption_times.csv")
aes_decrypt_df = pd.read_csv("../dataframes/decryption/aes_decryption_times.csv")
stream_ciphers_encrypt_df = pd.read_csv("../dataframes/encryption/stream_cipher_encryption_times.csv")
stream_ciphers_decrypt_df = pd.read_csv("../dataframes/decryption/stream_cipher_decryption_times.csv")
ecc_encrypt_df = pd.read_csv("../dataframes/encryption/ecc_encryption_times.csv")
ecc_decrypt_df = pd.read_csv("../dataframes/decryption/ecc_decryption_times.csv")

# Throughput Data
aes_encrypt_throughput_df = pd.read_csv("../dataframes/throughput/aes_encryption_throughputs.csv")
aes_decrypt_throughput_df = pd.read_csv("../dataframes/throughput/aes_encryption_throughputs.csv")
stream_cipher_encrypt_throughput_df = pd.read_csv("../dataframes/throughput/stream_cipher_encryption_throughputs.csv")
stream_cipher_decrypt_throughput_df = pd.read_csv("../dataframes/throughput/stream_cipher_decryption_throughputs.csv")
ecc_encrypt_throughput_df = pd.read_csv("../dataframes/throughput/ecc_encryption_throughputs.csv")
ecc_decrypt_throughput_df = pd.read_csv("../dataframes/throughput/ecc_decryption_throughputs.csv")


# Plot AES and ECC
combined_encrypt_df = pd.concat([aes_encrypt_df, ecc_encrypt_df], axis=0)
combined_decrypt_df = pd.concat([aes_decrypt_df, ecc_decrypt_df], axis=0)
combined_throughput_df = pd.concat([aes_encrypt_throughput_df, ecc_encrypt_throughput_df], axis=0)
plot_times(combined_encrypt_df, "encrypt_times_aes")
plot_times(combined_decrypt_df, "decrypt_times_aes")
plot_throughput(combined_throughput_df, "throughput_aes_ecc")

# Plot Stream Ciphers
plot_times(stream_ciphers_encrypt_df, "encrypt_times_stream_ciphers")
plot_times(stream_ciphers_decrypt_df, "decrypt_times_stream_ciphers")
plot_throughput(stream_cipher_encrypt_throughput_df, "throughput_stream_ciphers")

# Plot Fastest AES, ECC, and Stream Cipher
top_encrypt_df = pd.concat([combined_encrypt_df.iloc[[0, 4, 8]], stream_ciphers_encrypt_df.iloc[[1, 3]]], axis=0)
top_throughput_df = pd.concat([combined_throughput_df.iloc[[1, 5, 6]], stream_cipher_encrypt_throughput_df.iloc[[3]]], axis=0)
plot_times(top_encrypt_df, "top_encrypt_times_each_mode")
plot_throughput(top_throughput_df, "top_throughputs_each_mode")
