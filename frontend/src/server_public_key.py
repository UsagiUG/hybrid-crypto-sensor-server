import os

certs_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'certs'))

with open(os.path.join(certs_dir, 'rsa_public_key.pem'), 'r', encoding='utf-8') as f:
    server_rsa_public_key = f.read()

with open(os.path.join(certs_dir, 'ecc_public_key.pem'), 'r', encoding='utf-8') as f:
    server_ecc_public_key = f.read()

if __name__ == "__main__":
    print(certs_dir)
    print(server_rsa_public_key)

# BASE_DIR 
# print({"BASE_DIR": BASE_DIR})

# BASE_DIR2 = os.path.abspath(__file__)
# print({"BASE_DIR2": BASE_DIR2})
