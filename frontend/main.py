import requests
import time
# from build_payload2 import build_payload2
# from get_public_key import get_public_key
import numpy as np
from scipy import stats
import json
import pandas as pd
import os

from src.rsa_encryption import prepare_rsa_key
from src.ecc_encryption import prepare_ecc_key
from src.build_payload import EdgeGateway
from src.server_public_key import server_rsa_public_key, server_ecc_public_key

url = "http://localhost:3000/telemetry"

csv_path = os.path.join("..", "statistics")

sensor1 = EdgeGateway(1)
modes = ["rsa", "ecc"]
sizes = [1, 10, 100]

with open(os.path.join("..", "statistics_summary.txt"), "w") as output_file:
    for mode in modes:
        for size in sizes:
            durations_encryption = []
            packet_size = []
            generate_durations = []
            decryption_durations = []

            for _ in range(30):
                sensor1.generate_sensor_data()

            start_tp = time.perf_counter()
            for _ in range(30):
                start_encrypt = time.perf_counter()
                session_key, key, generate_dur = prepare_rsa_key(server_rsa_public_key) if mode == "rsa" else prepare_ecc_key(server_ecc_public_key)
                payload = sensor1.build_payload(mode, session_key, key)
                end_encrypt = time.perf_counter()

                decryption_duration=sensor1.post(url, json=payload).json()["decryption_duration"]

                durations_encryption.append(end_encrypt - start_encrypt)
                decryption_durations.append(decryption_duration)
                packet_size.append(len(json.dumps(payload).encode()))
                generate_durations.append(generate_dur)
            end_tp = time.perf_counter()

            df = pd.DataFrame({"Encryption (second)": durations_encryption,
                            "decryption (second)": decryption_durations,
                            "size (byte)": packet_size,
                            "session key generation (second)": generate_durations})
            df.to_csv(os.path.join(csv_path, f"{mode} {size}kb.csv"),index=False)

            df_tp = pd.DataFrame({"time (second)": [start_tp], "time after 30 messages sent (second)": [end_tp]})
            df_tp.to_csv(os.path.join(csv_path, f"{mode} {size}kb throughput.csv"),index=False)

            output_file.write(f"{mode} {size}kb\n")

            d1 = np.array(durations_encryption) * 1000
            output_file.write(f"Encrypt- mean: {np.mean(d1):.3f} ms, median: {np.median(d1):.3f} ms, std: {np.std(d1):.3f} ms\n")

            d2 = np.array(decryption_durations) * 1000
            output_file.write(f"Decrypt- mean: {np.mean(d2):.3f} ms, median: {np.median(d2):.3f} ms, std: {np.std(d2):.3f} ms\n")

            output_file.write(f"Throughput: {30/(end_tp-start_tp)} message/second\n")

            d3 = np.array(packet_size)
            output_file.write(f"JSON size - mean: {np.mean(d3):.3f} bytes, median: {np.median(d3):.3f} bytes, std: {np.std(d3):.3f} bytes\n")

            d4 = np.array(generate_durations) * 1000
            output_file.write(f"Generate key- mean: {np.mean(d4):.3f} ms, median: {np.median(d4):.3f} ms, std: {np.std(d4):.3f} ms\n")

            output_file.write("="*80+"\n\n")
