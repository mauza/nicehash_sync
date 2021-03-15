import hmac
import hashlib
import logging
import os
import time
import requests
import secrets
import sys
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
LOGGER = logging.getLogger(__name__)

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


def hmac_sig(api_key, api_secret, epoch_ms, nonce, org_id, method, path, query, body=None):
    byte_key = bytes(api_secret, ENCODING)
    input_list = [
        bytes(api_key, ENCODING),
        bytes(epoch_ms, ENCODING),
        bytes(nonce, ENCODING),
        b'',
        bytes(org_id, ENCODING),
        b'',
        bytes(method, ENCODING),
        bytes(path, ENCODING),
        bytes(query, ENCODING)
    ]
    if body:
        input_list.append(body.encode(ENCODING))
    hash_input = b'\0'.join(input_list)
    result = hmac.new(byte_key, hash_input, digestmod=hashlib.sha256).hexdigest()
    return result


def create_headers(timestamp_ms, nonce, org_id, request_id, api_key, hmac_signiture):
    result = {
        "X-Time": timestamp_ms,
        "X-Nonce": nonce,
        "X-Organization-Id": org_id,
        "X-Request-id": request_id,
        "X-Auth": f"{api_key}:{hmac_signiture}"
    }
    return result


def make_request(path, query, method, api_key, api_secret, org_id, body=None, **kwargs):
    epoch_ms = str(int(time.time()*1000))  # ms since epoch
    nonce = secrets.token_hex(18)
    hmac_result = hmac_sig(api_key, api_secret, epoch_ms, nonce, org_id, method.upper(), path, query, body)
    request_id = secrets.token_hex(11)
    LOGGER.info(f"Sending {path}?{query} '{method}' request with id: {request_id}")
    headers = create_headers(epoch_ms, nonce, org_id, request_id, api_key, hmac_result)
    method = getattr(requests, method.lower())
    url = f"{BASE_URL}{path}?{query}"
    response = method(url, headers=headers, **kwargs)
    return response.json()

def rigs_stats_unpaid(
        key, secret, org_id, btc_address,
        after_timestamp=int(time.time()*1000)-86400000,
        before_timestamp=int(time.time()*1000)
):
    path = f"/main/api/v2/mining/external/{btc_address}/rigs/stats/unpaid"
    query = f"btcAddress={btc_address}&afterTimestamp={after_timestamp}&beforeTimestamp={before_timestamp}"
    result = make_request(path, query, "GET", key, secret, org_id)
    return result

def main():
    config = get_config_from_env()
    result = rigs_stats_unpaid(config["api_key"], config["api_secret_key"], config["org_id"], config["btc_address"])
    print(result)


if __name__ == "__main__":
    main()
