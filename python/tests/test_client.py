import os
import time
import unittest
from random import randrange

import requests

from vault_client import VaultClient

vault_addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
vault_token = os.environ.get("VAULT_TOKEN", "root")
vault_headers = {"X-Vault-Token": vault_token}

session = requests.Session()
session.headers.update(vault_headers)


class VaultClientTests(unittest.TestCase):
    def test_kv_v2_read(self):

        # Write a random value to kv-v2
        test_value = str(randrange(15))
        kv_path = "/v1/secret/data/kv_v2_read"
        kv_data = {"data":{"foo": test_value}}
        resp = session.post(
            url=vault_addr + kv_path, json=kv_data
        )

        vc = VaultClient()
        result = vc.read_kv("kv_v2_read", "foo")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(test_value, result)

    def test_kv_v2_read_ttl(self):

        # Write a random value to kv-v2 with 5 second TTL
        test_value = str(randrange(15))
        secret_name = "kv_v2_read_ttl"
        kv_path = f"/v1/secret/data/{secret_name}"
        kv_data = {"data": {"foo": test_value, "ttl": "5"}}
        resp = session.post(
            url=vault_addr + kv_path, json=kv_data
        )

        vc = VaultClient()
        result = vc.read_kv(secret_name, "foo")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(test_value, result)

        # Write a new random value to kv-v2 with 5 second TTL
        new_test_value = str(randrange(15))
        kv_path = f"/v1/secret/data/{secret_name}"
        kv_data = {"data": {"foo": new_test_value, "ttl": "5"}}
        resp = session.post(
            url=vault_addr + kv_path, json=kv_data
        )

        # Initially, the result should be the old value read from cache
        result = vc.read_kv(secret_name, "foo")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(test_value, result)

        time.sleep(5)
        # After 5 seconds, the result should be the new value as the TTL expired
        result = vc.read_kv(secret_name, "foo")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(new_test_value, result)

if __name__ == "__main__":
    unittest.main()
