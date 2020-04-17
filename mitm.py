import socket

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization.base import Encoding, PublicFormat

from utils import *

def mitm(conf, recv_port, dest_addr, dest_port, recv_filename):
    """
    Acts like a receiver and a sender at the same time, intercepting a message.
    :param conf:
    :param dest_addr:
    :param dest_port:
    :param recv_filename:
    :return:
    """
    # Listen incoming connection
    sock_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Listening on 0.0.0.0:{}'.format(recv_port))
    sock_in.bind(("0.0.0.0", int(recv_port)))
    sock_in.listen()
    # Send our PK to incoming connection
    conn, client_address = sock_in.accept()
    print("connection accepted, sending public key...")
    our_pk = get_public_key(conf)
    conn.sendall(our_pk.public_bytes(Encoding.PEM, PublicFormat.PKCS1))

    # Connect to external server
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('connecting to {}:{}'.format(dest_addr, dest_port))
    sock_out.connect((dest_addr, int(dest_port)))
    # Receive PK from outgoing server
    their_pk = b''
    print("receiving public key...")
    while True:
        resp = sock_out.recv(4096)
        their_pk += resp
        if len(resp) < 4096:
            break
    their_pk = their_pk.decode()
    print("public key received is {}".format(their_pk))

    # Receive encrypted share key
    print("Public key sent. Receiving encrypted_shared_key...")
    # First 32 bits are the shared key:
    encrypted_shared_key = conn.recv(
        256)  # chacha20 key, but encrypted with a 2048bit RSA key, so the size is 256 bytes
    if len(encrypted_shared_key) == 0:
        print("empty shared key received. Exiting...")
        exit(1)
    key = decrypt_shared_key(conf, encrypted_shared_key)

    # Re encrypt shared key and send to out server
    encrypted_shared_key = get_encrypted_shared_key(key, their_pk)
    chacha20 = ChaCha20Poly1305(key)
    sock_out.sendall(encrypted_shared_key)

    # Receive encrypted file chunks and resend them to other server
    chacha20 = ChaCha20Poly1305(key)

    print("receiving file size...")
    filesize = int.from_bytes(conn.recv(8), byteorder='big')
    print("file size is {} byts".format(filesize))
    with open(recv_filename, 'wb') as f:
        i = 0
        data = b''
        while filesize > 0:
            print("{} bytes remaining".format(filesize))
            while len(data) < BLOCK_SIZE:
                newdata = conn.recv(BLOCK_SIZE)  # Encrypted size is CHUNK_SIZE + 16
                data += newdata
                if len(newdata) == 0:
                    break
            if len(data) > 0:
                print("sending package of size {}...".format(len(data)))
                sock_out.sendall(data)
                print("decrypting package of size {}...".format(len(data[:BLOCK_SIZE])))
                decrypted = chacha20.decrypt(i.to_bytes(12, byteorder="big"), data[:BLOCK_SIZE], None)
                f.write(decrypted)
                filesize -= len(decrypted)
                i += 1
                data = data[BLOCK_SIZE:]
