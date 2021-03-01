import binascii
import hmac
import hashlib
import os
import time
import requests
import secrets
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://api2.nicehash.com"
ENCODING = "ISO-8859-1"

def get_config_from_env():
    config = {
        "api_key": os.environ["API_KEY"],
        "api_secret_key": os.environ["API_SECRET_KEY"],
        "btc_address": os.environ["BTC_ADDRESS"],
        "org_id": os.environ["ORG_ID"],
    }
    return config

def hmac_sig(api_key, epoch_ms, nonce, org_id, method, path, query, body):
    byte_key = api_key.encode(ENCODING)
    input_list = [
        api_key.encode(ENCODING),
        epoch_ms.encode(ENCODING),
        nonce.encode(ENCODING),
        ''.encode(ENCODING),
        org_id.encode(ENCODING),
        ''.encode(ENCODING),
        method.encode(ENCODING),
        path.encode(ENCODING),
        query.encode(ENCODING),
        body.encode(ENCODING)
    ]
    hash_input = b''
    result = hmac.new(byte_key, hash_input, hashlib.sha256).hexdigest()
    return result

def gen_headers(key, secret):
    pass

def main():
    config = get_config_from_env()
    epoch_ms = time.time() * 1000  # ms since epoch
    nonce = secrets.token_hex(18)
    method = "GET"
    path = "/main/api/v2/mining/rigs/payouts"
    query = ""
    body = ""
    hmac_result = hmac_sig(config["api_key"], epoch_ms, nonce, config["org_id"], method, path, query, body)
    print(hmac_result)


if __name__ == "__main__":
    main()
