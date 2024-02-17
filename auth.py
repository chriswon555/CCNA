import requests
from requests.auth import HTTPBasicAuth

DNA_CENTER = {
    "host": "sandboxdnac.cisco.com",
    "port" : "443",
    "username": "devnetuser",
    "password": "Cisco123!"
}

def get_auth_token():
    endpoint = '/dna/system/api/v1/auth/token'
    url = 'https://' + DNA_CENTER['host'] + endpoint
    resp = requests.post(url, auth=HTTPBasicAuth(DNA_CENTER['username'], DNA_CENTER['password']), verify=False)
    token = resp.json()['Token']
    print(token)
    return token