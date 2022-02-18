import struct
import json
import psycopg2 as pg2
#import threading
import logging
from pysyncobj import SyncObj, SyncObjConf
from pysyncobj.batteries import ReplCounter, ReplLockManager, SyncObjConsumer, replicated
from time import time, sleep
from contextlib import closing
from fastapi import FastAPI, status
from pydantic import BaseModel
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from random import random
from psycopg2 import extensions
from typing import Optional
from base64 import b64decode
#from queue import Queue

class ReplState(SyncObjConsumer):
    def __init__(self):
        """
        Simple distributed hash. You can set and get value.
        """
        super(ReplState, self).__init__()
        self.__counter = int()
        self.__hash = bytes()

    # @replicated
    # def set(self, newHashValue):
    #    self.__hash = newHashValue

    @replicated
    def set_all(self, newCounterValue, newHashValue):
        self.__counter = newCounterValue
        self.__hash = newHashValue

    @replicated
    def inc_and_set(self, newHashValue):
        self.__counter += 1
        self.__hash = newHashValue

        return self.__counter, self.__hash

    def get_all(self):

        return self.__counter, self.__hash

logging.basicConfig(level=logging.INFO)

connect_string = 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert'

node = FastAPI()

ordering_clock = ReplCounter()
# Lock will be released if connection dropped for more than 60 seconds
lock_manager = ReplLockManager(autoUnlockTime=60)
#item_queue = Queue()
repl_state = ReplState()


private_key = ECC.import_key(open('private-key.pem').read())
witness_cert = open('public-key.pem','rb').read()
signer = DSS.new(private_key, 'fips-186-3')

syncObjConf = SyncObjConf()
syncObjConf.appendEntriesUseBatch = False
#syncObjConf.journalFile='2.log'
syncObjConf.password='S3kr1t' 
syncObj = SyncObj('127.0.0.1:4324', ['127.0.0.1:4322', '127.0.0.1:4323'], consumers=[
                  repl_state, lock_manager], conf=syncObjConf)

global_conn = pg2.connect(connect_string)
global_conn.autocommit = True                            



class LedgerEntry(BaseModel):
    ciphertext: str
    plaintext_hash: str
    authentication_tag: str
    pkcs1_oaep_session_key: str
    metadata: dict
    owner_cert: str


def init_ordering_clock():
    logging.info("Init ordering clock")
    #ordering_clock.set(0, sync=True)
    if lock_manager.tryAcquire('startupLock', sync=True):
        with closing(pg2.connect(connect_string)) as conn:
            # conn.set_isolation_level(extensions.ISOLATION_LEVEL_SERIALIZABLE)
            # This'll handle the transaction and closing the cursor
            with conn, conn.cursor() as cur:
                cur.execute(
                    'WITH t AS (SELECT count(*) AS cnt, max(ordering_clock) as moc FROM ledger.ledger) SELECT cnt, moc, (SELECT chain_hash FROM ledger.ledger l WHERE l.ordering_clock=moc) FROM t')
                chain_size, last_position, last_hash = cur.fetchone()
                if chain_size == 0:
                    genesis_value = b'GENESIS_BLOCK'
                    h = SHA3_256.new(genesis_value)
                    signature = signer.sign(h)
                    digest = h.digest()
                    repl_state.set_all(-9223372036854775807, digest, sync=True)
                    cur.execute(
                        '''INSERT INTO ledger.ledger (ordering_clock, created, content, chain_hash, witness_signature, plaintext_hash, witness_identity_x509) VALUES (-9223372036854775808, %s, %s::bytea, %s::bytea, %s::bytea, %s, %s) ON CONFLICT DO NOTHING''', (time(), genesis_value, digest, signature, digest, witness_cert))
                else:
                    #logging.info(last_position)
                    #logging.info(repl_state.get_all())
                    if last_position is not None:
                        repl_state.set_all(
                            last_position+1, last_hash.tobytes(), sync=True)
                        #logging.info(repl_state.get_all())
        lock_manager.release('startupLock')


def do_insert(payload):
    created = time()
    ciphertext = b64decode(payload.ciphertext)
    plaintext_hash = b64decode(payload.plaintext_hash)
    authentication_tag = b64decode(payload.authentication_tag)
    pkcs1_oaep_session_key = b64decode(payload.pkcs1_oaep_session_key)
    owner_cert = b64decode(payload.owner_cert)

    while not lock_manager.tryAcquire('insertLock', sync=True):
        sleep(0.001)

    order_clock, previous_hash = repl_state.get_all()

    h = SHA3_256.new(previous_hash)
    h.update(struct.pack('!q', order_clock))
    h.update(struct.pack('!d', created))
    h.update(ciphertext)
    h.update(plaintext_hash)
    h.update(authentication_tag)
    h.update(pkcs1_oaep_session_key)
    h.update(witness_cert)
    h.update(owner_cert)
    for key in sorted(payload.metadata):
        h.update(key.encode('utf8'))
        h.update(str(payload.metadata.get(key)).encode('utf8'))

    signature = signer.sign(h)
    digest = h.digest()
    repl_state.inc_and_set(digest, sync=True)
    lock_manager.release('insertLock')

    with global_conn.cursor() as cur:
        cur.execute('INSERT INTO ledger.ledger (ordering_clock, created, content, plaintext_hash, authentication_tag,pkcs1_oaep_session_key, metadata, chain_hash, witness_signature, witness_identity_x509, owner_identity_x509) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)',
                    (order_clock, created, ciphertext, plaintext_hash, authentication_tag, pkcs1_oaep_session_key, json.dumps(payload.metadata), digest, signature, witness_cert, owner_cert))

    return digest.hex()                



# def attestation_worker():
#    while True:
#        with closing(pg2.connect(connect_string)) as conn:
#            # This'll handle the transaction and closing the cursor
#            with conn, conn.cursor() as cur:
#                cur.execute('SELECT l1.ordering_clock, l1.payload FROM ledger.ledger l1 WHERE l1.insert_node != 0 AND l1.hash IS NULL AND l1.signature IS NULL AND EXISTS (SELECT 1 FROM ledger.ledger l2 WHERE l2.ordering_clock = l1.ordering_clock - 1 AND l2.hash IS NOT NULL AND l2.signature IS NOT NULL) FOR UPDATE')
#                if cur.rowcount > 0:
#                    insert_position, payload = cur.fetchone()
#                    logging.info("Attestation task running for ordering_clock {}".format(
#                        insert_position))
#                    cur.execute(
#                        'SELECT hash FROM ledger.ledger WHERE ordering_clock = %s - 1', (insert_position,))
#                    previous_hash, *_ = cur.fetchone()
#                    # logging.info(previous_hash)
#                    h = SHA3_256.new(previous_hash)
#                    h.update(hex(payload['ordering_clock']).encode('utf8'))
#                    h.update(float.hex(payload['created']).encode('utf8'))
#                    h.update(payload['data'].encode('utf8'))
#                    signature = signer.sign(h)
#                    digest = h.digest()
#                    payload['hash'] = digest.hex()
#                    payload['signature'] = signature.hex()
#                    cur.execute('UPDATE ledger.ledger SET payload=%s::json, hash=%s, signature=%s, signed=to_timestamp(%s), signer_node=0 WHERE ordering_clock = %s',
#                                (json.dumps(payload), digest, signature, time(), insert_position))
#                #conn.commit()
#        sleep(random())

# def insert_worker():
#    while True:
#        do_insert(item_queue.get())


@node.post("/add", status_code=status.HTTP_201_CREATED)
async def add(item: LedgerEntry):
    chain_hash = do_insert(item)
    #item_queue.put(make_payload(ordering_clock.inc(sync=True), entry.data))

    return {'chain_hash': chain_hash}

@node.get("/entry/{ordering_clock}")
async def entry(ordering_clock):
    entry = '{}'
    with closing(pg2.connect(connect_string)) as conn:  
        with conn, conn.cursor() as cur:
            cur.execute("SELECT row_to_json(l) FROM ledger.ledger l WHERE ordering_clock = %s",(ordering_clock,))
            if cur.rowcount == 1:
                entry = cur.fetchone()[0]

    return json.loads(entry)

@node.get("/status")
async def status():
    return {"status": syncObj.getStatus()}

init_ordering_clock()

#p = threading.Thread(target=insert_worker, daemon=True)
# p.start()
