import socket

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization.base import PublicFormat

import utils
from utils import *


def receive(conf, receive_port, filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Listening on 0.0.0.0:{}'.format(receive_port))
    sock.bind(("0.0.0.0", int(receive_port)))
    sock.listen()
    print('waiting connections')
    conn, client_address = sock.accept()
    print("connection accepted, sending public key...")
    pk = get_public_key(conf)
    conn.sendall(pk.public_bytes(Encoding.PEM, PublicFormat.PKCS1))
    print("Public key sent. Receiving encrypted_shared_key...")
    # First 32 bits are the shared key:
    encrypted_shared_key = conn.recv(
        256)  # chacha20 key, but encrypted with a 2048bit RSA key, so the size is 256 bytes
    if len(encrypted_shared_key) == 0:
        print("empty shared key received. Exiting...")
        exit(1)
    key = utils.decrypt_shared_key(conf, encrypted_shared_key)
    chacha20 = ChaCha20Poly1305(key)
    print("Receiving encrypted chunks and decrypting them on {}...".format(filename))
    with open(filename, 'wb') as f:
        i = 0
        while True:
            data = b''
            data += conn.recv(CHUNK_SIZE + 16)  # Encrypted size is CHUNK_SIZE + 16
            print("decrypting package of size {}...".format(len(data)))
            decrypted = chacha20.decrypt(i.to_bytes(12, byteorder="big"), data, None)
            f.write(decrypted)
            i += 1
            if len(data) < CHUNK_SIZE + 16:
                break
    print("done!")
    conn.close()
