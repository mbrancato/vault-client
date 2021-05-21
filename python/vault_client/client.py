import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import List, Any, Union, Optional, Dict
from urllib.parse import urlencode

import requests


def http_get(
    url: str, headers: Optional[dict] = None, data: Optional[dict] = None,
):
    return http_request("get", url=url, headers=headers, data=data)


def http_post(
    url: str, headers: Optional[dict] = None, data: Optional[dict] = None,
):
    return http_request("post", url=url, headers=headers, data=data)


def http_request(
    method: str, url: str, headers: Optional[dict] = None, data: Optional[dict] = None,
):
    try:
        if method.lower() == "get":
            response = requests.get(
                url, headers=headers, data=data, allow_redirects=False, timeout=3
            )
        elif method.lower() == "post":
            response = requests.post(
                url, headers=headers, data=data, allow_redirects=False, timeout=3
            )
        else:
            return None

        if response.status_code == 404:
            logging.debug("Secret or path not found in Vault.")
            return None
        elif response.status_code == 403:
            raise PermissionError(
                "Access to Vault secret denied. Check the token, authentication method, or policies."
            )
        elif response.status_code == 307:
            logging.error(
                "Vault request was not successful. Request may have been sent to a Vault standby server."
            )
            return None
        elif response.status_code == 502:
            logging.debug("Vault request was throttled.")
            return None
        elif 300 <= response.status_code < 500:
            logging.warning(
                "Unexpected response. The Vault client is not configured to handle redirects: "
                + f"{response.status_code} : {response.headers} : {response.text}"
            )
            return None
        elif response.status_code >= 500:
            logging.error(f"Error occurred while accessing Vault: {response.text}")
            return None

        return response.json()
    except Exception as e:
        logging.error(e)
        return None


def dotted_get(path: Union[str, List[str]], obj: dict):
    if isinstance(path, str):
        path = path.split(".")
    item = obj.get(path[0], None)
    if item and len(path) > 1:
        return dotted_get(path[1:], item)
    return item


class VaultClient:
    __vault_addr: str
    __vault_token: str
    __vault_namespace: str
    __vault_accessor: str
    __auth_method: str
    __auth_path: str
    __auth_role: str
    __vault_policies: List[str] = []
    __vault_token_lease_time: datetime
    __vault_token_lease_duration: int = 0
    __authenticated: bool = False
    __secrets: Dict[str, "VaultClient.VaultSecret"] = {}
    __default_kvv2_ttl: int = 300

    def get_auth_method(self) -> str:
        return self.__auth_method

    def get_auth_role(self) -> str:
        return self.__auth_role

    def get_vault_accessor(self) -> str:
        return self.__vault_accessor

    def get_vault_addr(self) -> str:
        return self.__vault_addr

    def get_vault_namespace(self) -> str:
        return self.__vault_namespace

    def get_vault_policies(self) -> List[str]:
        return self.__vault_policies

    def is_authenticated(self) -> bool:
        return self.__authenticated

    def set_auth_method(self, auth_method) -> None:
        self.__auth_method = auth_method

    def set_auth_path(self, auth_path) -> None:
        self.__auth_path = auth_path

    def set_auth_role(self, auth_role) -> None:
        self.__auth_role = auth_role

    def set_vault_accessor(self, vault_accessor) -> None:
        self.__vault_accessor = vault_accessor

    def set_vault_addr(self, vault_addr) -> None:
        self.__vault_addr = vault_addr

    def set_vault_namespace(self, vault_namespace) -> None:
        self.__vault_namespace = vault_namespace

    def set_vault_token(self, vault_token) -> None:
        self.__vault_token = vault_token

    def __init__(
        self,
        vault_addr: str = "",
        vault_namespace: str = "",
        auth_method: str = "",
        auth_path: str = "",
        auth_role: str = "",
        default_kv_v2_ttl: int = __default_kvv2_ttl,
    ):
        self.__vault_addr = vault_addr
        self.__vault_namespace = vault_namespace
        self.__auth_method = auth_method
        self.__auth_path = auth_path
        self.__auth_role = auth_role
        self.__default_kvv2_ttl = default_kv_v2_ttl
        self.__vault_token = os.getenv("VAULT_TOKEN", default="")
        if not self.__vault_addr:
            self.__vault_addr = os.getenv("VAULT_ADDR", default="")
        if not self.__vault_namespace:
            self.__vault_namespace = os.getenv("VAULT_NAMESPACE", default="")

        if self.__vault_token and self.__vault_addr:
            logging.debug("Using existing Token for authentication.")
            self.__vault_token_lease_duration = 0
            self.__authenticated = True

    def read_kv(
        self,
        name: str,
        key: str,
        version: int = 0,
        mount_path: str = "/secret",
        kv_version: int = 2,
    ) -> Any:
        if kv_version == 1:
            path = f"{mount_path}/{name}"
            kv_key = f"data.{key}"
            return self.read(path, kv_key)
        elif kv_version == 2:
            path = f"{mount_path}/data/{name}?version={version}"
            kv_key = f"data.data.{key}"
            return self.read(path, kv_key)
        else:
            logging.error("Unknown Key-Value secret engine version")
        return None

    def read(self, path: str, key: str) -> Any:
        value = self.__read_element(path, key)
        if value:
            if type(value) in [int, str, float]:
                return value
            else:
                return json.dumps(value, default=str)
        return None

    def login(self) -> bool:
        logging.debug("Performing Auth")
        result: bool = False

        if not self.__auth_path:
            logging.debug("Auth path null")
            self.__auth_path = self.__auth_method

        if self.__auth_method == "gcp":
            result = self.login_gcp()
        # JWT login method should really be called directly
        # TODO: Find a clean way to reauthenticate when token using JWT auth expires

        if not result:
            raise RuntimeError("Unable to authenticate to Vault.")
        else:
            return True

    def login_gcp(self) -> bool:
        logging.debug("Performing GCP Login")
        google_headers: dict = {"Metadata-Flavor": "Google"}
        google_url_params: str
        google_metadata_url: str
        jwt: str

        if self.__auth_role:
            google_url_params = urlencode(
                [("audience", f"vault/{self.__auth_role}"), ("format", "full")]
            )
        else:
            google_url_params = urlencode([("audience", "vault"), ("format", "full")])

        google_metadata_url = (
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?"
            + google_url_params
        )
        jwt = requests.get(google_metadata_url, headers=google_headers).text

        return self.login_jwt(jwt)

    def login_jwt(self, jwt: str) -> bool:
        logging.debug("Performing JWT Login")
        login_result_json: str
        login_path = f"/v1/auth/{self.__auth_path}/login"
        vault_login_jwt_data = {"role": self.__auth_role, "jwt": jwt}
        login_result = http_post(
            self.__vault_addr + login_path, data=vault_login_jwt_data,
        )

        if login_result and dotted_get("auth.client_token", login_result):
            self.__vault_token_lease_time = datetime.now()
            self.__vault_token = dotted_get("auth.client_token", login_result)
            self.__vault_accessor = dotted_get("auth.accessor", login_result)
            self.__vault_token_lease_duration = dotted_get(
                "auth.lease_duration", login_result
            )
            self.__vault_policies = dotted_get("auth.policies", login_result)
            self.__authenticated = True
            return True

        return False

    def __read_element(self, path: str, key: str) -> Optional[Dict[str, Any]]:
        current_time = datetime.now()

        if not path or not key:
            return None

        if path[0] != "/":
            path = "/" + path

        if not self.__authenticated:
            self.login()

        if self.__vault_token_lease_duration > 0:
            seconds_since_token_lease = (
                datetime.now() - self.__vault_token_lease_time
            ).seconds

            if float(seconds_since_token_lease) > (
                float(self.__vault_token_lease_duration) * (2.0 / 3.0)
            ):
                self.login()

        if path not in self.__secrets.keys():
            logging.debug("Secret is new")
            self.__secrets[path] = VaultClient.VaultSecret(path=path)

        secret: VaultClient.VaultSecret = self.__secrets[path]

        if not secret.leased:
            # No lease yet
            self.__secrets[path] = self.__get_secret(secret)
        else:
            if not self.__secrets[path].lease_time:
                raise ValueError("Missing existing secret value when checking lease.")
            assert isinstance(self.__secrets[path].lease_time, datetime)
            assert isinstance(current_time, datetime)
            seconds_since_secret_lease = (
                current_time - self.__secrets[path].lease_time  # type: ignore
            ).seconds
            if seconds_since_secret_lease >= self.__secrets[path].lease_duration:  # type: ignore
                # Lease expired
                self.__secrets[path] = self.__get_secret(secret)
            elif float(seconds_since_secret_lease) > (
                float(secret.lease_duration) * (2.0 / 3.0)
            ):
                if secret.renewable:
                    if not self.__secrets[path].update_lock:
                        self.__secrets[path].update_lock = True
                        self.__renew_secret(secret)
                else:
                    # Lease is not renewable
                    if not self.__secrets[path].update_lock:
                        self.__secrets[path].update_lock = True
                        self.__update_secret(secret)
            else:
                # Not expired and not ready for renewal yet
                pass

        if not self.__secrets[path].value:
            raise ValueError("Missing secret value after being read.")

        if self.__secrets[path].leased:
            return dotted_get(key, self.__secrets[path].value)  # type: ignore
        else:
            return None

    def __get_secret(self, secret: "VaultSecret"):
        vault_headers = {"X-Vault-Token": self.__vault_token}
        secret_response = http_get(
            self.__vault_addr + "/v1" + secret.path, headers=vault_headers
        )

        if secret_response:
            secret.lease_time = datetime.now()
            secret.value = secret_response
            secret.leased = True
            if dotted_get("renewable", secret_response):
                secret.renewable = dotted_get("renewable", secret_response)
            if dotted_get("lease_duration", secret_response):
                secret.lease_duration = dotted_get("lease_duration", secret_response)
            else:
                secret.lease_duration = self.__default_kvv2_ttl
            # Implement TTL support for KV V2
            if dotted_get("data.data.ttl", secret_response):
                secret.lease_duration = int(
                    dotted_get("data.data.ttl", secret_response)
                )
            if dotted_get("lease_id", secret_response):
                secret.lease_id = dotted_get("lease_id", secret_response)

        return secret

    def __renew_secret(self, secret: "VaultSecret"):
        renewer = VaultClient.VaultSecretRenewThread(parent=self, secret=secret)
        renewer.start()

    def __update_secret(self, secret: "VaultSecret"):
        updater = VaultClient.VaultSecretUpdateThread(parent=self, secret=secret)
        updater.start()

    @dataclass
    class VaultSecret:
        path: str
        value: Optional[Dict[Any, Any]] = None
        lease_id: Optional[str] = None
        lease_time: Optional[datetime] = None
        lease_duration: int = 0
        leased: Optional[bool] = False
        renewable: Optional[bool] = False
        update_lock: Optional[bool] = False

    class VaultSecretUpdateThread(threading.Thread):
        def __init__(self, parent, secret: "VaultClient.VaultSecret"):
            self.parent = parent
            self.secret = secret
            thread = threading.Thread(target=self.run, args=())
            thread.daemon = True
            super().__init__()

        def run(self):

            self.parent._VaultClient__secrets[
                self.secret.path
            ] = self.parent._VaultClient__get_secret(self.secret)
            self.parent._VaultClient__secrets[self.secret.path].update_lock = False

    class VaultSecretRenewThread(threading.Thread):
        def __init__(self, parent, secret: "VaultClient.VaultSecret"):
            self.parent = parent
            self.secret = secret
            thread = threading.Thread(target=self.run, args=())
            thread.daemon = True
            super().__init__()

        def run(self):
            vault_headers = {"X-Vault-Token": self.parent._VaultClient__vault_token}
            renewal_data = {
                "lease_id": self.secret.lease_id,
                "increment": self.secret.lease_duration,
            }

            secret_response = http_post(
                self.parent._VaultClient__vault_addr + "/v1/sys/leases/renew",
                headers=vault_headers,
                data=renewal_data,
            )

            if secret_response and dotted_get("lease_id", secret_response):
                self.secret.lease_time = datetime.now()
                self.secret.lease_id = dotted_get("lease_id", secret_response)
                self.secret.renewable = dotted_get("renewable", secret_response)
                self.secret.lease_duration = dotted_get(
                    "lease_duration", secret_response
                )

            self.secret.update_lock = False
            self.parent._VaultClient__secrets[self.secret.path] = self.secret
