# Odoo Authenticate with Keycloak

## Introduction
This is Odoo addon to authenticate with keycloak SSO. Developed with Odoo 17 CE and Keycloak 26.
Odoo has auth_oauth addon to provide SSO, but on auth_oauth using authorization type token or implicit flow on keycloak client
So this addon is using authorization type code, this is some setup on your keycloak
- set Confidential or Client Authentication on
- set Authorization on
- set Standard Flow on
- setup client credential to get client_secret
Then you have realm, client_id and client secret to set on apps configuration 



## Configuration
Because it has secret code, we dont recommend to store it on Odoo system variable. So there are 3 methods to store this configuration data

### 1. .env File (Use dotenv) (default)
This addon using this method, so you need to create .env file and access it from __init__.py, example

```bash
from dotenv import load_dotenv
load_dotenv()
```
Then on your .env 
```bash
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=myclientid
KEYCLOAK_CLIENT_SECRET=thisissecrettoken
KEYCLOAK_BASE_URL=http://localhost:8080
```
dont forget to install dotenv plugin on python

### 2. Environment Variables (ENV)
You can store it to OS Environment Variables
Example on linux:
- export KEYCLOAK_REALM=master
- export KEYCLOAK_CLIENT_ID=myclientid
- export KEYCLOAK_CLIENT_SECRET=thisissecrettoken
- export KEYCLOAK_BASE_URL=http://localhost:8080

then you need to change some code to get Environment Variables

```bash
import os
secret = os.getenv("KEYCLOAK_CLIENT_ID")
```
### 3. Secrets Manager (Safest for production)
You can use:
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- GCP Secret Manager

Example on HashiCorp Vault, you need to install hvac
```bash
pip install hvac
```
then you can use it
```bash
import hvac

client = hvac.Client(url='http://127.0.0.1:8200', token='root')

read_response = client.secrets.kv.v2.read_secret_version(path='odoo')
secret_data = read_response['data']['data']

print(secret_data['secret_key'])  # Output: supersecret123
```

but you need to inherit or change on this addon to use other method other than default



