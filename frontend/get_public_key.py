import requests
from build_payload import build_payload
# import json

def get_public_key() -> str:
    url='http://localhost:3000/public-key'
    response = requests.get(url)
    response.raise_for_status()
    return response.json()['public_key']
    # return response

# server_public_key = get_server_public_key()
# print(server_public_key)
