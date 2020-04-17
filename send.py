import socket
from functools import partial

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from utils import *


def send(conf, receive_name, filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_host, server_port = get_address(conf, receive_name)
    print('connecting to {}:{}'.format(server_host, server_port))
    sock.connect((server_host, server_port))
    # Recibir llave pública
    pk = b''
    print("receiving public key...")
    while True:
        resp = sock.recv(4096)
        pk += resp
        if len(resp) < 4096:
            break
    pk = pk.decode()
    print("public key received is {}".format(pk))
    if receive_name not in conf["publicKeys"]:
        print("This peer has not a Public Key registered. Want to register this PK? (Y/n)")
        if input() == "n":
            print("Could not verify PK, ending connection...")
            sock.close()
            exit(1)
        else:
            print("Accepting PK received as {}'s Public Key".format(receive_name))
            add_public_key(conf, receive_name, pk)
    else:
        if conf["publicKeys"][receive_name] != pk:
            print("public key mismatch. MITM!")
            exit(1)
        else:
            print("PK received matches with registered PK for {}".format(receive_name))
            # Key is ok, send symmetric encryption key and then the file
    print("Generating shared key for ChaCha20Poly1305 authenticated encryption...")
    key = ChaCha20Poly1305.generate_key() # 32 bytes
    encrypted_shared_key = get_encrypted_shared_key(key, pk)
    chacha20 = ChaCha20Poly1305(key)
    print("Generating encrypted shared key to receiver...")
    sock.sendall(encrypted_shared_key)
    i = 0
    print("Sending encrypted file to receiver")
    with open(filename, 'rb') as f:
        for chunk in iter(partial(f.read, CHUNK_SIZE), b''):
            encrypted = chacha20.encrypt(i.to_bytes(12, byteorder="big"), chunk, None)
            print("sending package of size {}...".format(len(encrypted)))
            i += 1
            sock.sendall(encrypted)
    sock.close()
    print("done!")

