#!/bin/python3

from sys import argv
from os import listdir
from os.path import isfile, join
import json

from web3 import Web3
from eth_keys import keys


if len(argv) < 2:
    print("please specify keystore path.")
    exit(-1)

# get w3 instance
w3 = Web3()

# find all files
keystore_path = argv[1]
files = [join(keystore_path, f) for f in listdir(keystore_path)
         if isfile(join(keystore_path, f))]
files.sort()

# convert to pubkey
passphrases = [c*4 for c in "123456789a"]
allkeys = []
for i, f in enumerate(files):
    with open(f) as fh:
        print("unloking {}".format(f))
        encrypted_key = fh.read()
        private_key_bytes = w3.eth.account.decrypt(
            encrypted_key, passphrases[i])
        private_key = keys.PrivateKey(private_key_bytes)
        public_key = private_key.public_key
        allkeys.append({
            "address": public_key.to_address(),
            "passphrase": passphrases[i],
            "public_key": public_key.to_hex(),
            "private_key": private_key.to_hex()
        })

# write out result
with open("allkeys.json", "w") as fh:
    json.dump(allkeys, fh, indent=2, ensure_ascii=False)
