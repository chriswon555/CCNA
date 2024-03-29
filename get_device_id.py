import requests
from requests.auth import HTTPBasicAuth
from auth import get_auth_token
from icecream import ic
import json

requests.packages.urllib3.disable_warnings()

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
    last_digit = 100
    for device in device_json['response']: # Loop through Device List and Retrieve DeviceId
        print("Fetching Interfaces for Device Id ----> {}".format(device['id']))
        print('\n')
        get_device_int(device['id'])
        
        get_device_summary(device['id'])
        ip = f'10.0.0.{last_digit}'
        set_management_ip(device['id'],ip)
        print('\n')
        last_digit += 1


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

def get_device_summary(device_id):
    url = f"https://sandboxdnac.cisco.com/api/v1/network-device/{device_id}/brief"
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False) # Make the Get Request
    device_summary = resp.json()
    ic(device_summary)

def set_management_ip(device_id,ip):
    url = f"https://sandboxdnac.cisco.com/api/v1/network-device/{device_id}/management-address"
    body = json.dumps({"newIP": ip})
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.request('PUT', url, headers=hdr, data=body, verify=False) # Make the Get Request
    device_summary = resp.json()
    ic(device_summary)

def get_ospf_interfaces():
    url = "https://sandboxdnac.cisco.com/api/v1/interface/ospf"
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.request('GET', url, headers=hdr, verify=False) # Make the Get Request
    interfaces = resp.json()
    ic(interfaces)

if __name__ == "__main__":
    get_device_list()
    get_ospf_interfaces()
