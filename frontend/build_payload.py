from datetime import datetime, timezone, timedelta
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
from rsa_encryption import rsa_encrypt
from sensor_simulation import sensor_simulation

# def get_session_key() -> bytes | None:
#   if session_key_use_count > session_key_lifetime:
#	 return AESGCM.generate_key(bit_length=256)
#   else:
#	 return None



def build_payload(public_key_pem: str) -> dict:
	tz_wib = timezone(timedelta(hours=7))

	# this one gonna cascade depending on the result. None is not a valid session_key. You need to use the current session_key
	# session_key = get_session_key() # -> raw_bytes
	# session_key for testing because get_session_key isn't finished yet
	session_key = b'\xf8\xb1\xab)4\xac\xdf\xfa\x8b)\xbf\xd9\xd9^c\xc5\x17\x11\x8f\xfe{\xeb\x00u\xaa9\xac:\x8aVp\xcd'
	encrypted_session_key = rsa_encrypt(session_key, public_key_pem) # -> raw_bytes

	aesgcm = AESGCM(session_key)
	iv = os.urandom(12)
	plaintext_bytes = json.dumps(sensor_simulation()).encode('utf-8') # -> dict[str,float]
	aad = {
		'sensor_id': 1,
		'transmission_timestamp': datetime.now(tz_wib).isoformat(),
		'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
	}
	aad_bytes = json.dumps(aad, separators=(',', ':'), sort_keys=True).encode('utf-8')

	encrypted_raw = aesgcm.encrypt(iv, plaintext_bytes, aad_bytes)
	ciphertext = encrypted_raw[:-16]
	tag = encrypted_raw[-16:]

	print('aad_bytes ', aad_bytes)
	print('repr(aad_bytes) ', repr(aad_bytes))
	# return {
	# 	**aad,
	# 	'nonce': base64.b64encode(iv).decode('utf-8'),
	# 	'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
	# 	'tag': base64.b64encode(tag).decode('utf-8')
	# }

	return {
		'aad': aad,
		'nonce': base64.b64encode(iv).decode('utf-8'),
		'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
		'tag': base64.b64encode(tag).decode('utf-8')
	}
