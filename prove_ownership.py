import struct
import psycopg2 as pg2
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from contextlib import closing
from random import randint

connect_string = 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=c:/Devel/Bergstrom2/bergstrom.key sslcert=c:/Devel/Bergstrom2/bergstrom.cert sslrootcert=c:/Devel/Bergstrom2/root.cert'

with closing(pg2.connect(connect_string)) as conn:
    # This'll handle the transaction and closing the cursor
    with conn, conn.cursor() as cur:
        cur.execute(
            'SELECT owner_identity_x509, plaintext_hash, content, authentication_tag, pkcs1_oaep_session_key FROM ledger.ledger WHERE ordering_clock = -9223372036854775707')
        row = cur.fetchone()

        # Alice (Challenger)

        # 1.) Alice checks Bobs certificate (optional, could be self signed, cert could be expired)

        # if (cert check failed):
        #    print("Cert is dubious")

        # 2.) Challenge / Response

        owner_public_key = RSA.importKey(row[0].tobytes())

        PKCS1 = PKCS1_OAEP.new(owner_public_key)

        a = randint(1, 1000)
        b = randint(1, 1000)

        alice_secret = struct.pack('!HH', a, b)

        challenge = (PKCS1.encrypt(alice_secret), row[1].tobytes().hex())

        # Bob (Owner)

        owner_private_key = RSA.importKey(
            open('c:/Devel/Bergstrom2/oaep_private-key.pem').read())

        PKCS1 = PKCS1_OAEP.new(owner_private_key)

        aes_session_key = PKCS1.decrypt(row[4].tobytes())

        cipher = AES.new(aes_session_key, AES.MODE_SIV)
        cipher.update(row[1].tobytes())
        plaintext = cipher.decrypt_and_verify(
            row[2].tobytes(), row[3].tobytes())

        challenge_secret = PKCS1.decrypt(challenge[0])

        a, b = struct.unpack('!HH', challenge_secret)

        challenge_answer = (PKCS1.encrypt(
            struct.pack('!I', a*b)), challenge[1])

        # Alice (Challenger)

        PKCS1 = PKCS1_OAEP.new(owner_public_key)

        answer = struct.unpack('!I', PKCS1.decrypt(challenge_answer[0]))[0]

        if (a*b == answer):
            print(a, b, answer)
            print("Bob can prove ownership of {}".format(challenge_answer[1]))
        else:
            print("Bob cannot prove ownership of {}".format(
                challenge_answer[1]))
