# Vault Client

Vault Client is designed to be a dead simple client library for Vault consumer 
applications. The purpose is to implement a robust Vault client that makes it 
easy for developers to instrument HashiCorp Vault into applications.

All implementations of Vault Client will use a common API. After configuring 
Vault authentication, the developer simply needs to replace the location of a 
needed secret in their code with the appropriate `read` method. The Vault 
Client object will handle authentication renewal and secret / lease renewal.

## Feature Matrix

|                       | Java | Python | C#/.NET |
|----------------------:|:----:|:------:|:-------:|
| Language Support      | ⚠️   | 🚧     | ❌       |
| Auth Renewal (Async)  | 🚧   | ❌     | ❌       |
| Generic Read          | ✅   | ❌     | ❌       |
| KV Read               | ✅   | ❌     | ❌       |
| Lease Renewal (Async) | ✅   | ❌     | ❌       |
| JWT Auth              | ✅   | ❌     | ❌       |
| GCP Auth (GCE)        | ✅   | ❌     | ❌       |
| Azure Auth            | 🚧   | ❌     | ❌       |
| AppRole Auth          | ❌   | ❌     | ❌       |
| TLS Auth              | ❌   | ❌     | ❌       |

✅ - Implemented  
❌ - Not implemented  
⚠️ - Partially implemented  
🚧 - Under construction  

