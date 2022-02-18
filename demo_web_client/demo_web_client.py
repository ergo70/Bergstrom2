from flask import Flask, render_template, request, flash, redirect
from werkzeug.utils import secure_filename
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from requests import post
from random import randint

nodes = ['127.0.0.1:8000', '127.0.0.1:8001', '127.0.0.1:8002']

payload = {"ciphertext": None, "plaintext_hash": None,
           "authentication_tag": None, "pkcs1_oaep_session_key": None, "metadata": {}, "owner_cert": None}

owner_cert = open('oaep_private-key.pem', 'rb').read()
public_key = RSA.importKey(owner_cert)
PKCS1 = PKCS1_OAEP.new(public_key)

app = Flask(__name__)
app.secret_key = get_random_bytes(32)


@app.route("/", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        document_title = request.form.get('title')
        if not document_title:
            flash('No document title')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            aes_key = get_random_bytes(32)
            cleartext = file.read()
            h = SHA3_256.new(cleartext)
            cleartext_hash = h.digest()
            cipher = AES.new(aes_key, AES.MODE_SIV)
            cipher.update(cleartext_hash)
            ciphertext, tag = cipher.encrypt_and_digest(cleartext)
            payload['ciphertext'] = b64encode(ciphertext).decode('utf8')
            payload['plaintext_hash'] = b64encode(
                cleartext_hash).decode('utf8')
            payload['authentication_tag'] = b64encode(tag).decode('utf8')
            payload['pkcs1_oaep_session_key'] = b64encode(
                PKCS1.encrypt(aes_key)).decode('utf8')
            payload['metadata'] = {'cleartext_size': len(
                cleartext), 'file_name': filename, 'document_title': document_title}
            payload['owner_cert'] = b64encode(owner_cert).decode('utf8')
            r = post('https://{}/add'.format(nodes[randint(0, len(nodes)-1)]),
                     json=payload, verify='root.cert')
            if r.status_code == 201:
                flash('Entry created @ {}'.format(r.json().get('chain_hash')))
            else:
                flash("Entry not created")
        return render_template('index.html')
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
