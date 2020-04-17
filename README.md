# Transfer 

(MITM-example)

Transfer is an example of a `man-in-the-middle` attack, using public key cryptography (RSA in this example).

This example requires Python 3 to work.

## Quick start

* Install Python Requirements: `pip install -r requirements.txt`
* Rename `config.json.example` to `config.json`
* To send `file.txt` to `alice`, execute `python main.py send alice file.txt`
* To receive `file.txt` listening on port `9876`, execute `python main.py receive 9876 file.txt` 
* To make a MITM attack and receive `file.txt` without being detected, edit the `addressbook.json` such the name `alice` points to the attackers IP, then execute `python main.py mitm 9876 <real_alice_ip> <real_alice_port> intercepted_file.txt`. This attack will succeed only if the sender does not check the public key received and compares with the previously known Alice's key, or if they has never connected with Alice before.

## The `config.json` file

This file defines some properties and values the program needs to remember, such as:

* `resolver`: URL representing a JSON file hosted in a server. The JSON file contains a map with names as keys and tuples (ip:port) as values.
* `sk`: stores the PKCS#8 representation of a secret key generated when receiving a file.
* `publicKeys`: a map with peer names as keys and a public key in PKCS#1 format as values. It is used to remember the public key for a peer. This allows us to avoid MITM attacks given the first connection was made with the real server.

To create this file, rename `config.json.sample` to `config.json`.

## Send Mode

```bash
python main.py send <recipent_name> <file_to_send> 
```

Sends `<file_to_send>` to `<recipient_name>`, The IP and port of `<recipient_name>` is obtained from the JSON file hosted in the address set as `resolver` property in `config.json`. When sending, the receiver sends its Public Key to the sender. The sender checks if it remembers that public key associated to the name of the receiver. If not, it asks if you want to save it as trusted. If it recognizes it, it compares it with the saved one. If they are different, the program halts and alerts of a possible MITM attack.

## Receive Mode

```bash
python main.py receive <listening_port> <path_to_receive> 
```

Receives a file listening on `<listening_port>` and copying the file to `<path_to_receive>`.

## Man-In-The-Middle Mode


```bash
python main.py mitm <listening_port> <real_recipent_ip> <real_recipient_port> <path_to_receive> 
```

Intercepts a file listening on `<listening_port>` and resending the intercepted messages to `<ral_recipient_ip>:<real_recipient_port>`. The intercepted file is saved on `<path_to_receive>`.

## Troubleshoot

* **I am having an error about config file not found**

**R:** Rename `config.json.sample` to `config.json`

* **I am trying to send something but I cannot connect to the receiver**

**R:** Execute the receiver first, then execute the sender.
