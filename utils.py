import json

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, NoEncryption, load_pem_public_key

CONFIG = "config.json"
CHUNK_SIZE = 1024
TIMEOUT = 5


def load_config():
    """
    Loads the config from the config.json file
    :return: a map with the configuration
    """
    with open(CONFIG) as f:
        return json.load(f)


def save_config(conf):
    """
    Saves the config on config.json file
    :param conf: config.json location
    :return: nothing
    """
    with open(CONFIG, 'w') as f:
        json.dump(conf, f)


def get_private_key(conf):
    """
    Creates a new own private key if it does not exist, and then saves it
    :param conf: Configuration map
    :return pk: a private key
    """
    if "sk" not in conf:
        sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        conf["sk"] = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode('utf-8')  # Example only
        save_config(conf)
    else:
        sk = serialization.load_pem_private_key(conf["sk"].encode(), password=None, backend=default_backend())
    return sk


def get_public_key(conf):
    """
    Returns own public key
    :param conf: Configuration map
    :return: a Cryptography public key
    """
    return get_private_key(conf).public_key()


def get_address(conf, receive_name):
    '''
    Gets an IP address and port from the resolver (defined in config.json)
    :param conf: Configuration map.
    :param receive_name: receiver name.
    :return: Receiver address, as string, in "<ip>:<port>" format.
    '''
    addresses = requests.get(conf["resolver"]).json()
    if receive_name not in addresses:
        return None
    splittedAddr = addresses[receive_name].split(":")
    return splittedAddr[0], int(splittedAddr[1])


def get_encrypted_shared_key(key, pkbytes):
    """
    :param conf:
    :param pkbytes:
    :return:
    """
    pk = load_pem_public_key(pkbytes.encode(), backend=default_backend())
    return pk.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_shared_key(conf, key):
    """
    Decrypts the received shared key
    :param conf: configuration map
    :param key: encrypted shared key
    :return: decrypted shared key
    """
    sk = get_private_key(conf)
    if sk is None:
        print("private key is none")
        exit(1)
    return sk.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def add_public_key(conf, name, pk):
    """
    Add a public key to config file
    :param conf: config file
    :param name: pk name
    :param pk: public key
    :return: nothing
    """
    conf["publicKeys"][name] = pk
    save_config(conf)
