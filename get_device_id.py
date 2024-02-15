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
    return token

def get_device_list():
    """
    Building out function to retrieve list of devices. Using requests.get to make a call to the network device Endpoint
    """
    global token
    token = get_auth_token() # Get Token
    url = "https://sandboxdnac.cisco.com/api/v1/network-device"
    hdr = {'x-auth-token': token, 'content-type' : 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    device_list = resp.json()
    get_device_id(device_list)


def get_device_id(device_json):
    for device in device_json['response']: # Loop through Device List and Retrieve DeviceId
        print("Fetching Interfaces for Device Id ----> {}".format(device['id']))
        print('\n')
        get_device_int(device['id'])
        print('\n')


def get_device_int(device_id):
    """
    Building out function to retrieve device interface. Using requests.get to make a call to the network device Endpoint
    """
    url = "https://sandboxdnac.cisco.com/api/v1/interface"
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    querystring = {"macAddress": device_id} # Dynamically build the query params to get device specific Interface information
    resp = requests.get(url, headers=hdr, params=querystring, verify=False) # Make the Get Request
    interface_info_json = resp.json()
    print_interface_info(interface_info_json)


def print_interface_info(interface_info):
    print("{0:42}{1:17}{2:12}{3:18}{4:17}{5:10}{6:15}".
          format("portName", "vlanId", "portMode", "portType", "duplex", "status", "lastUpdated"))
    for int in interface_info['response']:
        print("{0:42}{1:10}{2:12}{3:18}{4:17}{5:10}{6:15}".
              format(str(int['portName']),
                     str(int['vlanId']),
                     str(int['portMode']),
                     str(int['portType']),
                     str(int['duplex']),
                     str(int['status']),
                     str(int['lastUpdated'])))


if __name__ == "__main__":
    get_device_list()