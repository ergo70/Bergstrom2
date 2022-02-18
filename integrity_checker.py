import struct
import psycopg2 as pg2
import psycopg2.extensions as pg2_ex
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from contextlib import closing

connect_string = 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert'

public_key = ECC.import_key(open('public-key.pem').read())
verifier = DSS.new(public_key, 'fips-186-3')

private_key = RSA.importKey(
    open('oaep_private-key.pem').read())
PKCS1 = PKCS1_OAEP.new(private_key)


# class SHA3_256_Helper(object):
# ASN.1 Object ID
#    oid = "2.16.840.1.101.3.4.2.8"

#    def __init__(self, raw_bytes):
#        self._raw_bytes = raw_bytes

#    def digest(self):
#        return self._raw_bytes

#    def new(*args, **kwargs):
#        raw_bytes = args[0]

#        return SHA3_256_Helper(raw_bytes)


with closing(pg2.connect(connect_string)) as conn:
    conn.set_isolation_level(pg2_ex.ISOLATION_LEVEL_SERIALIZABLE)
    # This'll handle the transaction and closing the cursor
    with conn, conn.cursor() as cur:
        cur.execute(
            '''with t as (select ordering_clock,created,ciphertext,plaintext_hash,authentication_tag,pkcs1_oaep_session_key,metadata,chain_hash,witness_signature,lag(chain_hash, 1) over (order by ordering_clock asc) as prev_hash,witness_identity_x509, owner_identity_x509 from ledger.ledger l order by ordering_clock asc) select ordering_clock,created,ciphertext,plaintext_hash,authentication_tag,pkcs1_oaep_session_key,metadata,chain_hash,witness_signature,prev_hash,witness_identity_x509, owner_identity_x509 from t where ciphertext != decode('47454E455349535F424C4F434B', 'hex')''')
        for row in cur:
            ordering_clock = row[0]
            print("Testing link {} ... ".format(ordering_clock), end='')
            previous_hash = row[9]
            created = row[1]
            ciphertext = row[2]
            plaintext_hash = row[3]
            authentication_tag = row[4]
            pkcs1_oaep_session_key = row[5]
            metadata = row[6]
            chain_hash = row[7]
            witness_signature = row[8]
            witness_cert = row[10]
            owner_cert = row[11]
            aes_key = PKCS1.decrypt(pkcs1_oaep_session_key.tobytes())
            h = SHA3_256.new(previous_hash.tobytes())
            h.update(struct.pack('!q', ordering_clock))
            h.update(struct.pack('!d', created))
            h.update(ciphertext.tobytes())
            h.update(plaintext_hash.tobytes())
            h.update(authentication_tag.tobytes())
            h.update(pkcs1_oaep_session_key.tobytes())
            h.update(witness_cert.tobytes())
            h.update(owner_cert.tobytes())
            for key in sorted(metadata):
                h.update(key.encode('utf8'))
                h.update(str(metadata.get(key)).encode('utf8'))

            if chain_hash.tobytes() == h.digest():
                try:
                    cipher = AES.new(aes_key, AES.MODE_SIV)
                    cipher.update(plaintext_hash)
                    plaintext = cipher.decrypt_and_verify(
                        ciphertext, authentication_tag)
                    # print(plaintext.decode('utf-8'))
                    verifier.verify(h, witness_signature)
                    h = SHA3_256.new(plaintext)
                    if plaintext_hash.tobytes() != h.digest():
                        print("Cleartext hash comparison failed")
                    print("pass")
                except (ValueError, KeyError):
                    print("AEAD decrypt and/or verify failed")
            else:
                print("Chain hash comparison failed")
