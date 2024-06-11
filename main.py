from flask import Flask, render_template, request, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

app = Flask(__name__)

# RSA Key Generation
rsa_key = RSA.generate(2048)
rsa_private_key = rsa_key.export_key()
rsa_public_key = rsa_key.publickey().export_key()

# ECC Key Generation
ecc_private_key = ec.generate_private_key(ec.SECP384R1())
ecc_public_key = ecc_private_key.public_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    algorithm = request.form['algorithm']
    message = request.form['message'].encode()

    if algorithm == 'rsa':
        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
        encrypted_message = rsa_cipher.encrypt(message)
    elif algorithm == 'ecc':
        shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        encrypted_message = derived_key + message  # Simplified encryption

    return render_template('index.html', encrypted_message=encrypted_message.hex(), algorithm=algorithm)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    algorithm = request.form['algorithm']
    encrypted_message = bytes.fromhex(request.form['encrypted_message'])

    if algorithm == 'rsa':
        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
        decrypted_message = rsa_cipher.decrypt(encrypted_message)
    elif algorithm == 'ecc':
        shared_key = ecc_private_key.exchange(ec.ECDH(), ecc_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        decrypted_message = encrypted_message[len(derived_key):]  # Simplified decryption

    return render_template('index.html', decrypted_message=decrypted_message.decode(), algorithm=algorithm)

if __name__ == '__main__':
    app.run(debug=True)
