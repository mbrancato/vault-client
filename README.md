# Vault Client

![Java](https://github.com/mbrancato/vault-client/workflows/Java%20CI%20with%20Gradle/badge.svg)
![Python](https://github.com/mbrancato/vault-client/workflows/Python%20package/badge.svg)

Vault Client is designed to be a dead simple client library for Vault consumer 
applications. The purpose is to implement a robust Vault client that makes it 
easy for developers to instrument HashiCorp Vault into applications.

All implementations of Vault Client will use a common API. After configuring 
Vault authentication, the developer simply needs to replace the location of a 
needed secret in their code with the appropriate `read` method. The Vault 
Client object will handle authentication renewal and secret / lease renewal.

## Quick Start Example

**Java**

```java
String dbUser;
String dbPass;
VaultClient vault = new VaultClient();
vault.setAuthMethod("gcp");
vault.setAuthRole("app_name");
vault.setVaultAddr("https://myvault.company.org");

dbUser = vault.read("database/creds/my-role", "username");
dbPass = vault.read("database/creds/my-role", "password");
```

**Python**

```python
vault = VaultClient(
    vault_addr="https://myvault.company.org",
    auth_method="gcp",
    auth_role="app_name",
)

db_user = vault.read("database/creds/my-role", "username")
db_pass = vault.read("database/creds/my-role", "password")
```

## Feature Matrix

|                       | Java | Python | C#/.NET |
|----------------------:|:----:|:------:|:-------:|
| Language Support      | ⚠️   | ⚠️     | ❌       |
| Auth Renewal (Async)  | 🚧   | 🚧     | ❌       |
| Generic Read          | ✅   | ✅     | ❌       |
| KV Read               | ✅   | ✅     | ❌       |
| Lease Renewal (Async) | ✅   | ✅     | ❌       |
| JWT Auth              | ✅   | ✅     | ❌       |
| GCP Auth (GCE)        | ✅   | ✅     | ❌       |
| Azure Auth            | 🚧   | ❌     | ❌       |
| AppRole Auth          | ❌   | ❌     | ❌       |
| TLS Auth              | ❌   | ❌     | ❌       |

✅ - Implemented  
❌ - Not implemented  
⚠️ - Partially implemented  
🚧 - Under construction  

