#!/usr/bin/env python3
from Crypto.Cipher import AES
import requests
from Crypto.Random import get_random_bytes
import hashlib
import argparse
import sys
import base64
import json

VERBOSE = False


def b64e(mb: bytes) -> str:
    bb = base64.b64encode(mb)
    return bb.decode("ascii")


def b64d(msg: str) -> bytes:
    mb = msg.encode("ascii")
    return base64.b64decode(mb)


def sha256(msg: bytes) -> str:
    return hashlib.sha256(msg).hexdigest()


def encrypt(skey: bytes, msg: bytes) -> dict:
    if len(skey) > 32:
        raise Exception("key > 32 bytes!")
    cipher = AES.new(skey, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(msg)
    nonce = cipher.nonce
    return {"ct": ct, "tag": b64e(tag), "nonce": b64e(nonce)}


def decrypt(skey: bytes, msg: dict) -> bytes:
    if len(skey) > 32:
        raise Exception("key > 32 bytes!")
    cipher = AES.new(skey, AES.MODE_EAX, msg["nonce"])
    return cipher.decrypt_and_verify(msg["ct"], msg["tag"])


def printv(message: object):
    if VERBOSE:
        print(message, file=sys.stderr)


def encrypt_and_store(key: bytes, msg: bytes, server: str, remove_after: int = 0) -> bytes:
    printv("Generating superkey..")
    superkey = get_random_bytes(32)
    printv("Encrypting message..")
    emsg = encrypt(superkey, msg)
    hmsg = sha256(emsg['ct']).encode()
    st = sha256(hmsg+key)
    su = sha256(hmsg)
    kh = (key+hmsg)[0:32]
    printv("Encrypting superkey..")
    websecret = encrypt(kh, superkey)
    del(superkey)
    websecret["ct"] = b64e(websecret["ct"])
    printv("Uploading crypted superkey..")
    r = requests.put(f"{server}/api/add/{su}",
                      json={"ST": st, "WS": websecret, "RA": remove_after})
    jdata = r.json()
    if "error" in jdata:
        raise Exception(jdata["error"])
    emsg['ct'] = b64e(emsg["ct"])
    return emsg


def retrieve_and_decrypt(key: bytes, jmsg: dict, server: str, remove: bool = False) -> (bytes | bool):
    printv("Retrieving cyphertext..")
    for k in jmsg:
        jmsg[k] = b64d(jmsg[k])
    hmsg = sha256(jmsg['ct']).encode()
    st = sha256(hmsg+key)
    su = sha256(hmsg)

    if remove:
        printv(f"Asking for superkey removal..")
        r = requests.delete(f"{server}/api/rem/{su}", json={"ST": st})
        jdata = r.json()
        if "error" in jdata:
            raise Exception(jdata["error"])
        return True

    printv(f"Retrieving encrypted superkey..")
    r = requests.post(f"{server}/api/get/{su}", json={"ST": st})
    jdata = r.json()
    if "error" in jdata:
        raise Exception(jdata["error"])

    ws = jdata["WS"]
    dmsg = {}
    for k in ws:
        dmsg[k] = b64d(ws[k])
    kh = (key+hmsg)[0:32]
    printv(f"Decrypting superkey..")
    superkey = decrypt(kh, dmsg)
    printv(f"Decrypting message..")
    return decrypt(superkey, jmsg)


def get_info(jmsg: dict, server: str) -> (bytes | bool):
    printv("Retrieving cyphertext..")
    for k in jmsg:
        jmsg[k] = b64d(jmsg[k])
    hmsg = sha256(jmsg['ct']).encode()
    su = sha256(hmsg)

    printv(f"Retrieving info..")
    r = requests.get(f"{server}/api/info/{su}")
    return r.json()


def main():
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument("--infile", "-i", type=argparse.FileType("rb"),
                        help="Default: STDIN", default=sys.stdin.buffer)
    parser.add_argument("--outfile", "-o", type=argparse.FileType("wb"),
                        help="Default: STDOUT", default=sys.stdout.buffer)
    parser.add_argument("--server", "-s", default="http://127.0.0.1:5000")
    parser.add_argument("--verbose", "-v",
                        action="store_true", help="Prints more")
    parser.add_argument("--key", "-k", type=str)
    parser.add_argument("--remove-after", "-a",
                       help="Removes the superkey after X fails. Requires as input: X", default=None, type=int)

    ed = parser.add_mutually_exclusive_group(required=True)
    ed.add_argument("--encrypt", "-e", action="store_true",
                          help="Encrypts the content of INPUT into OUTPUT. Requires as input: plaintext data")
    ed.add_argument("--decrypt", "-d", action="store_true",
                          help="Decrypts the content of INPUT into OUTPUT. Requires as input: encrypted data")
    ed.add_argument("--remove", "-r", action="store_true",
                          help="Removes the superkey for the specified encrypted data from the remote server. Requires as input: encrypted data")
    ed.add_argument("--info", "-I", action="store_true",
                  help="Retrieves infos for the specified encrypted data from the remote server. Requires as input: encrypted data")
    args = parser.parse_args()

    VERBOSE = args.verbose

    if not args.key and not args.info:
        raise parser.error(
            "--key/-k required!")

    if args.key and len(args.key) > 32:
        raise parser.error(
            f"--key/-k max length is 32 chars. (Is: {len(args.key)} chars)")

    if args.remove_after and args.remove_after <= 0:
        raise parser.error(
            "--remove-after/-r should be a positive integer.")
        
    with args.infile:
        printv("Reading data..")
        data = args.infile.read()

    if args.encrypt:
        key = args.key.encode()
        emsg = encrypt_and_store(
            key, data, args.server, remove_after=args.remove_after)
        with args.outfile:
            printv("Writing data..")
            args.outfile.write(json.dumps(emsg).encode())
    
    elif args.decrypt or args.remove:
        jmsg = json.loads(data.decode())
        key = args.key.encode()
        remove = args.remove
        msg = retrieve_and_decrypt(
            key, jmsg, args.server, remove)
        if not remove:
            with args.outfile:
                printv("Writing data..")
                args.outfile.write(msg)
    
    elif args.info:
        jmsg = json.loads(data.decode())
        jdata = get_info(jmsg, args.server)
        with args.outfile:
            printv("Writing data..")
            args.outfile.write(json.dumps(jdata, indent=2).encode())

    printv("\nAll done.")


if __name__ == "__main__":
    main()
