#!/usr/bin/env python3
from flask import Flask, request
import base64
import argparse


app = Flask(__name__)

KEYSTORE = {}

VALIDLENGTHS = {
    "SU": 64,
    "ST": 64,
    "tag": 16,
    "nonce": 16,
    "ct": 32
}


def b64e(msg: str) -> str:
    mb = msg.encode("ascii")
    bb = base64.b64encode(mb)
    return bb.decode("ascii")


def b64d(msg: str) -> bytes:
    mb = msg.encode("ascii")
    return base64.b64decode(mb)


def getb64len(msg: str) -> int:
    try:
        return len(b64d(msg))
    except Exception as e:
        print(e)
        return 0


@app.route("/api/add/<string:su>", methods=["PUT"])
def add(su):
    if len(su) != VALIDLENGTHS["SU"]:
        return {"error": "The length of SU is invalid."}, 400
    if su in KEYSTORE:
        return {"error": "SU conflict"}, 400
    jdata = request.get_json()

    for k in ["WS", "ST"]:
        if not k in jdata:
            return {"error": f"{k} missing."}, 400

    if len(jdata["ST"]) != VALIDLENGTHS["ST"]:
        return {"error": "The length of ST is invalid."}, 400

    for k in ["ct", "tag", "nonce"]:
        if not k in jdata["WS"]:
            return {"error": f"Key WS/{k} is missing."}, 400
        else:
            if getb64len(jdata["WS"][k]) != VALIDLENGTHS[k]:
                return {"error": f"Key WS/{k} is invalid!"}, 400
    remove_after = None
    if "RA" in jdata and jdata["RA"]:
        if type(jdata["RA"]) == int and jdata["RA"] > 0:
            remove_after = jdata["RA"]
        else:
            return {"error": f"Key RA is invalid!"}, 400

    KEYSTORE[su] = {
        "WS": {
            "ct": jdata["WS"]['ct'],
            "tag": jdata["WS"]['tag'],
            "nonce": jdata["WS"]['nonce'],
        },
        "RA": remove_after,
        "ST": jdata["ST"],
        "fail": 0
    }
    return {"msg": "ok"}


@app.route("/api/rem/<string:su>", methods=["DELETE"])
def rem(su):
    if len(su) != VALIDLENGTHS["SU"]:
        return {"error": "The length of SU is invalid."}, 400
    if not su in KEYSTORE:
        return {"error": "SU not found in keyserver"}, 404
    jdata = request.get_json()

    if not "ST" in jdata:
        return {"error": "ST missing."}, 400

    if len(jdata["ST"]) != VALIDLENGTHS["ST"]:
        return {"error": "The length of ST is invalid."}, 400

    k = KEYSTORE[su]
    if k["ST"] == jdata["ST"]:
        KEYSTORE.pop(su)
        return {"msg": "ok"}

    k["fail"] += 1
    if k["RA"] and k["fail"] >= k["RA"]:
        KEYSTORE.pop(su)
        return {"error": "auth error, key removed!"}, 401
    return {"error": "auth error"}, 401


@app.route("/api/get/<string:su>", methods=["POST"])
def get(su):
    if len(su) != VALIDLENGTHS["SU"]:
        return {"error": "The length of SU is invalid."}, 400
    if not su in KEYSTORE:
        return {"error": "SU not found in keyserver"}, 404
    jdata = request.get_json()

    if not "ST" in jdata:
        return {"error": "ST missing."}, 400

    if len(jdata["ST"]) != VALIDLENGTHS["ST"]:
        return {"error": "The length of ST is invalid."}, 400

    k = KEYSTORE[su]
    if k["ST"] == jdata["ST"]:
        return {"msg": "ok", "WS": k["WS"]}

    k["fail"] += 1
    if k["RA"] and k["fail"] >= k["RA"]:
        KEYSTORE.pop(su)
        return {"error": "auth error, key removed!"}, 401
    return {"error": "auth error"}, 401


@app.route("/api/info/<string:su>")
def info(su):
    if len(su) != VALIDLENGTHS["SU"]:
        return {"error": "The length of SU is invalid."}, 400
    if su in KEYSTORE:
        return {"exists": True, "fail": KEYSTORE[su]["fail"], "remove_after": KEYSTORE[su]["RA"]}
    return {"exists": False, "error": "SU not found in keyserver"}, 404


# @app.route("/api/debug")
# def debug():
#     return {"keys": KEYSTORE}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host","-H",help="Listening host, default: 127.0.0.1", default="127.0.0.1", type=str)
    parser.add_argument("--port","-p",help="Listening port, default: 5000", default=5000, type=int)
    args = parser.parse_args()
    app.run(args.host, args.port)
