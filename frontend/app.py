#########################################################################
#                   STREAMLIT CONTACT FORM TEMPLATE                     #
# Version: 0.2.0                                                        #
# License: MIT License (https://opensource.org/license/mit/)            #
# Author: João L. Neto (https://github.com/jlnetosci/)                  #
# Release date: 2023-11-07                                              #
# Documentation: https://github.com/jlnetosci/streamlit-contact-form    #
# Credit is not mandatory, but it is kindly appreciated.                #
# For a subtle link to github you may just uncomment the last line.     #
#########################################################################

import streamlit as st
import os
import time
import datetime
import requests
import time
import os
import base64
import json
import base64
import requests

from build_payload import build_payload
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from random import randbytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rsa_encryption import rsa_encrypt
from sensor_simulation import sensor_simulation
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone, timedelta

## Page configuration options
# st.set_page_config(layout="wide") # column widths set below are dependent on the layout being set to wide

## Load secrets.toml variables
options = os.getenv("OPTIONS")
server = os.getenv("SERVER")
port = os.getenv("PORT")
u = os.getenv("U")
secret = os.getenv("SECRET")
recipient = os.getenv("RECIPIENT")


## Form
st.header("Edge Gateway")

def sensor_simulation(temperature, air_humidity, soil_moisture, soil_ph) -> dict[str,float]:
  tz_wib = timezone(timedelta(hours=7))
  return {
      'reading_timestamp': datetime.now(tz_wib).isoformat(),
      'temperature': temperature,
      'air_humidity': air_humidity,
      'soil_moisture': soil_moisture,
      'soil_ph': soil_ph
  }

def rsa_encrypt(message: bytes, public_key_pem: str) -> bytes:
    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))

    ciphertext = public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext



def get_public_key() -> str:
    url='http://localhost:3000/public-key'
    response = requests.get(url)
    response.raise_for_status()
    return response.json()['public_key']

def generate_session_id(num_bytes = 32):
    return randbytes(num_bytes)

def build_payload(temperature, air_humidity, soil_moisture, soil_ph, 
                  public_key_pem: str, send_no_session_key: bool = False, return_aad_bytes: bool = False) -> dict:
	tz_wib = timezone(timedelta(hours=7))
	session_key = generate_session_id()
	encrypted_session_key = rsa_encrypt(session_key, public_key_pem) # -> raw_bytes

	aesgcm = AESGCM(session_key)
	iv = os.urandom(12)
	plaintext_bytes = json.dumps(sensor_simulation(
        temperature, air_humidity, soil_moisture, soil_ph
    )).encode('utf-8') # -> dict[str,float]
	aad = {
		'sensor_id': 1,
		'transmission_timestamp': datetime.now(tz_wib).isoformat(),
		'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8') if not send_no_session_key else None,
	}
	aad_bytes = json.dumps(aad, separators=(',', ':'), sort_keys=True).encode('utf-8')

	encrypted_raw = aesgcm.encrypt(iv, plaintext_bytes, aad_bytes)
	ciphertext = encrypted_raw[:-16]
	tag = encrypted_raw[-16:]

	return {
		'aad': aad if not return_aad_bytes else aad_bytes.decode('utf-8'),
		'nonce': base64.b64encode(iv).decode('utf-8'),
		'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
		'tag': base64.b64encode(tag).decode('utf-8')
	}




## Contact form
temperature = st.number_input("temperature", value=st.session_state.get('temperature', 0), key='temperature') # input widget for contact email
air_humidity = st.number_input("air_humidity", value=st.session_state.get('air_humidity', 0), key='air_humidity') # input widget for message
soil_moisture = st.number_input("soil_moisture", value=st.session_state.get('soil_moisture', 0), key='soil_moisture') # input widget for message
soil_ph = st.number_input("soil_ph", value=st.session_state.get('soil_ph', 0), key='soil_ph') # input widget for message

if st.button("Send", type="primary"):
    server_public_key = get_public_key()

    url = 'http://localhost:3000/telemetry'

    # # CPU warm up
    # for _ in range(10):
    #     build_payload(server_public_key)
        
    durations1 = []

    for _ in range(1):
        start = time.perf_counter()
        payload = build_payload(temperature, air_humidity, soil_moisture, soil_ph, server_public_key)
        
        response=requests.post(url, json=payload)
        
        end = time.perf_counter()
        durations1.append(end - start)

    st.text(response.json())
