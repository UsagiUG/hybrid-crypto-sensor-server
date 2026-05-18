import base64
import json
import os

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from nicegui import ui

def get_server_public_key() -> str:
    url='http://localhost:3000/public-key' 
    response = requests.get(url)
    response.raise_for_status()
    return response.json()['pub']
    # return '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8naqge5WFHlloyPDMwN\n3JZoV26EPzfhdC7MkYD6MLwvOesXn2lM9PBNt8kjEyb8lBnAyWYmWA/HJ0GiP07l\n++NoIYSCJIJttQhzD+LDzUjWhf5poOWDwE7GZlAQ2Aqj+ffBdOI7D2RBN+4YlT2t\ne0UmNJ7Y8AvukGHDMW8TCN8Arp6Rx/wqI1y61AH6IfQ+igvdMjTmKGlXuMNnu+bO\nLg8ig7jy4FtLNHRxnL/LTMnDH7+rXV72cT1Rw8yAWwhOQS6D8IYsWhpJ8YnC7ghw\nHdNuUjm6SfpZKHuJyz/yg6siM3TS7xlAXVT2yktBw5YnN0Da7duOMqkODZupMjGw\nrwIDAQAB\n-----END PUBLIC KEY-----\n'

# sensor data is made manually
def get_sensor_data():
    return {
        'timestamp': '2026-05-17T01:08:00Z',
        'sensor_id': '01',
        'readings': {
            'temperature': 26,
            'humidity': 93
        }
    }

def generate_aes_key():
    return os.urandom(32)

def get_aes_key():
    return b'D\x85\xb4\x9f\xab\x89E\x96C\x02\xe5\x9cbK\x10\x05\xba#1K\xf7\xf5\x96\xd8\x1c4Q\xb6\x15\x0e\x0bB'

def generate_iv():
    return os.urandom(16)

def aes_encrypt(aes_key, iv, data: dict) -> bytes:
    # dict ke bytes
    plaintext = json.dumps(data).encode("utf-8")

    # padding supaya panjang plaintext kelipatan 16
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # enkripsi
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return ciphertext

def build_payload(encrypted_aes_key: bytes, iv: bytes, ciphertext: bytes) -> dict[str, str]:
    return {
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def rsa_encrypt(aes_key: bytes, public_key_pem) -> bytes:
    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    
    ciphertext = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def send_sensor_data():
    try:
        server_public_key = get_server_public_key()
    except Exception as e:
        ui.notify('Error: Tidak bisa terhubung ke /public-key', type='negative')
        return
    
    try:
        aes_key = get_aes_key()
    except Exception as e:
        generate_aes_key()
        aes_key = get_aes_key()

    iv = generate_iv()

    try:
        sensor_data = get_sensor_data()
    except Exception as e:
        ui.notify('Error: Tidak ada data sensor', type='negative')
        return

    ciphertext = aes_encrypt(aes_key, iv, sensor_data)

    encrypted_aes_key = rsa_encrypt(aes_key, server_public_key)

    data_to_send = build_payload(encrypted_aes_key, iv, ciphertext)

    return data_to_send
    # try:
    #     url='http://localhost:3000/api/telemetry' 
    #     response=requests.post(url, json=data_to_send)
    #     if response.status_code==200:
    #         data=response.json()
    #         return()
    # except Exception as e:

result = send_sensor_data()
print(result)
# Tampilan Aplikasi (NiceGUI)
# ui.label('Generator Kunci (NiceGUI + Node.js)').classes('text-h5 m-4')
# ui.button('Generate New Keys', on_click=kirim_data).classes('bg-blue-500 text-white m-4')

# # Tempat untuk menampilkan teks hasil generate key nanti
# hasil_box = ui.label('').classes('m-4 text-grey-8 font-mono break-all')

# ui.run()