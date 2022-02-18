import urllib3
from requests import post
from random import randint
from time import time
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes

urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

nodes = ['127.0.0.1:8000', '127.0.0.1:8001', '127.0.0.1:8002']

payload = {"ciphertext": None, "plaintext_hash": None,
           "authentication_tag": None, "pkcs1_oaep_session_key": None, "metadata": {}, "owner_cert": None}

s0 = time()

owner_cert = open('oaep_private-key.pem','rb').read()
public_key = RSA.importKey(owner_cert)
PKCS1 = PKCS1_OAEP.new(public_key)

for i in range(100):
    aes_key = get_random_bytes(32)
    cleartext = get_random_bytes(randint(4096, 8192))
    h = SHA3_256.new(cleartext)
    cleartext_hash = h.digest()
    cipher = AES.new(aes_key, AES.MODE_SIV)
    cipher.update(cleartext_hash)
    ciphertext, tag = cipher.encrypt_and_digest(cleartext)
    payload['ciphertext'] = b64encode(ciphertext).decode('utf8')
    payload['plaintext_hash'] = b64encode(cleartext_hash).decode('utf8')
    payload['authentication_tag'] = b64encode(tag).decode('utf8')
    payload['pkcs1_oaep_session_key'] = b64encode(
        PKCS1.encrypt(aes_key)).decode('utf8')
    payload['metadata'] = {'cleartext_size': len(cleartext), 'gen_counter': i}
    payload['owner_cert'] = b64encode(owner_cert).decode('utf8')

    # print(payload)
    #s1 = time()
    r = post(
        'https://{}/add'.format(nodes[randint(0, len(nodes)-1)]), json=payload, verify='root.cert')
    print(r.status_code, r.json())

print(time() - s0)
