from nsync.nsync import hmac_sig


def test_get_hmac_sig():
    url = "https://api2.nicehash.com/main/api/v2/hashpower/orderBook?algorithm=X16R&page=0&size=100"
    query = "algorithm=X16R&page=0&size=100"
    path = "/main/api/v2/hashpower/orderBook"
    method = "GET"
    api_key = "4ebd366d-76f4-4400-a3b6-e51515d054d6"
    api_secret = "fd8a1652-728b-42fe-82b8-f623e56da8850750f5bf-ce66-4ca7-8b84-93651abc723b"
    epoch_ms = "1543597115712"
    org_id = "da41b3bc-3d0b-4226-b7ea-aee73f94a518"
    nonce = "9675d0f8-1325-484b-9594-c9d6d3268890"
    hs = hmac_sig(api_key, api_secret, epoch_ms, nonce, org_id, method, path, query)
    expected_result = "21e6a16f6eb34ac476d59f969f548b47fffe3fea318d9c99e77fc710d2fed798"
    assert hs == expected_result
