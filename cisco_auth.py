import requests
from requests.auth import HTTPBasicAuth
from icecream import ic

requests.packages.urllib3.disable_warnings()

DNA_CENTER = {
    "host": "sandboxdnac.cisco.com",
    "port" : "443",
    "username": "devnetuser",
    "password": "Cisco123!"
}

def get_auth_token():
    # Endpoint URL
    endpoint = '/dna/system/api/v1/auth/token'
    url = 'https://' + DNA_CENTER['host'] + endpoint
    # Make the POST Request
    resp = requests.post(url, auth=HTTPBasicAuth(DNA_CENTER['username'], DNA_CENTER['password']), verify=False)
    # Retrieve the Token from the returned JSON
    token = resp.json()['Token']
    # Print out the Token
    print("Token Retrieved: {}".format(token))
    # Create a return statement to send the token back for later use
    return token

def get_device_list():
    """
    Building out function to retrieve list of devices. Using requests.get to make a call to the network device Endpoint
    """
    token = get_auth_token() # Get Token
    url = "https://sandboxdnac.cisco.com/api/v1/network-device"
    hdr = {'x-auth-token': token, 'content-type' : 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    device_list = resp.json()
    ic(device_list)
    print_device_list(device_list)

def print_device_list(device_json):
    print("{0:42}{1:17}{2:12}{3:18}{4:12}{5:16}{6:15}".
          format("hostname", "mgmt IP", "serial","platformId", "SW Version", "role", "Uptime"))
    for device in device_json['response']:
        uptime = "N/A" if device['upTime'] is None else device['upTime']
        if device['serialNumber'] is not None and "," in device['serialNumber']:
            serial_platform_list = zip(device['serialNumber'].split(","), device['platformId'].split(","))
        else:
            serial_platform_list = [(device['serialNumber'], device['platformId'])]
        for (serial_number, platform_id) in serial_platform_list:
            print("{0:42}{1:17}{2:12}{3:18}{4:12}{5:16}{6:15}".
                  format(device['hostname'],
                         device['managementIpAddress'],
                         serial_number,
                         platform_id,
                         device['softwareVersion'],
                         device['role'], uptime))


if __name__ == "__main__":
    get_device_list()

