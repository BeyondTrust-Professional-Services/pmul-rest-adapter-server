#!/usr/bin/python3

import time
import hashlib
import hmac
import requests
import constants
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# generate a signed message
def gen_hmac(appkey: str, message: str) -> str:
    hmac_signature = hmac.new(
        bytes(appkey,'ascii'),
        bytes(message,'ascii'),
        hashlib.sha512
    ).hexdigest()
    return hmac_signature

def gen_message(appId: str) -> str:
    message = "appid={0}&timestamp={1}".format(appId, int(time.time()))
    return message


#message: str  = f'appid={constants.appId}&timestamp={int(time.time())}'

# Setup the parameters for the REST API call

def getassets(appKey=constants.appKey, appId=constants.appId, verbose=0, hostname=None):
    """Get client license information.
    
    Args:
        appKey (str): Application key for HMAC authentication
        appId (str): Application ID
        verbose (int): 0 for basic info, 1 for detailed stats
        hostname (str, optional): Filter results by hostname wildcard
    
    Returns:
        list: List of assets in Entitle format
    """
    if not appKey or not appId:
        raise ValueError("Invalid input values.")
    message = gen_message(appId)
    url = f'https://{constants.server}:{constants.port}/REST/v2.0/license/clients'
    params = {
        'appid': appId,
        'timestamp': int(time.time()),
        'hmac': gen_hmac(appKey, message),
        'verbose': verbose
    }
    if hostname:
        params['hostname'] = hostname
        
    disable_warnings(InsecureRequestWarning)
    response: requests.models.Response = requests.get(
        url=url,
        params=params,
        verify=False
    )
    response.raise_for_status()
    pmul_data = response.json()
    
    # Transform PMUL client data into Entitle asset format
    assets = []
    for client in pmul_data.get('clients', []):
        asset = {
            'identifier': client['uuid'],  # Use UUID as unique identifier
            'name': client['fqdn'],        # Use FQDN as display name
            'type': 'license',             # Custom type for PMUL licenses
            'role_options': [              # Define available roles for license assets
                {
                    'code': 'viewer',
                    'display_name': 'Viewer'
                },
                {
                    'code': 'admin',
                    'display_name': 'Administrator'
                }
            ]
        }
        assets.append(asset)
    
    return assets

def retireasset(assetname="", appKey="", appId=""):
    if not assetname or not appKey or not appId:
        raise ValueError("Invalid input values.")
    message=gen_message(appId)
    api_url: str = f'https://{constants.server}:{constants.port}/REST/v2.0/license/retire?{message}&hmac={gen_hmac(appKey, message)}'
    api_body = {
            "whoami": "root",
            "retire": {
                "fqdn":constants.client,
                }
            }
    response: requests.models.Response = requests.put(url=api_url, verify=False, data=api_body)
    return response.content.decode(encoding="utf-8")

def get_policy_list(appKey=constants.appKey, appId=constants.appId, path="/opt/pbul/policies"):
    """Get list of policy files from PMUL server.
    
    Args:
        appKey (str): Application key for HMAC authentication
        appId (str): Application ID
        path (str): Policy directory path
        
    Returns:
        dict: Policy directory listing
    """
    if not appKey or not appId:
        raise ValueError("Invalid input values.")
    message = gen_message(appId)
    url = f'https://{constants.server}:{constants.port}/REST/v2.0/policies'
    params = {
        'appid': appId,
        'timestamp': int(time.time()),
        'hmac': gen_hmac(appKey, message),
        'path': path
    }
    
    disable_warnings(InsecureRequestWarning)
    response: requests.models.Response = requests.get(
        url=url,
        params=params,
        verify=False
    )
    response.raise_for_status()
    return response.json()

def get_policy_content(appKey=constants.appKey, appId=constants.appId, file_path=None, format="script"):
    """Get content of a specific policy file.
    
    Args:
        appKey (str): Application key for HMAC authentication
        appId (str): Application ID
        file_path (str): Full path to policy file
        format (str): Format of response ('script' for line by line)
        
    Returns:
        dict: Policy file content
    """
    if not appKey or not appId or not file_path:
        raise ValueError("Invalid input values.")
    message = gen_message(appId)
    url = f'https://{constants.server}:{constants.port}/REST/v2.0/policies'
    params = {
        'appid': appId,
        'timestamp': int(time.time()),
        'hmac': gen_hmac(appKey, message),
        'file': file_path,
        'format': format
    }
    
    disable_warnings(InsecureRequestWarning)
    response: requests.models.Response = requests.get(
        url=url,
        params=params,
        verify=False
    )
    response.raise_for_status()
    return response.json()

def get_all_permissions(appKey=constants.appKey, appId=constants.appId):
    """Get all permissions from PMUL policies and transform to Entitle format.
    
    Args:
        appKey (str): Application key for HMAC authentication
        appId (str): Application ID
        
    Returns:
        dict: Permissions in Entitle format
    """
    # First get list of policy files
    policy_list = get_policy_list(appKey, appId)
    
    # Initialize permission structures
    actors_permissions = {}
    assets_permissions = {}
    
    # Process each policy file
    for policy_file in policy_list.get('dir', []):
        policy_id = policy_file['path']  # Use path as unique identifier
        
        # Get policy content
        content = get_policy_content(appKey, appId, policy_file['path'])
        
        # Transform policy into permissions
        # Assuming policies define access patterns that we can interpret as permissions
        # This is a simplified example - adjust based on actual policy content structure
        actors_permissions[policy_id] = [
            {
                'actor_id': 'system',  # Default system actor
                'role_code': 'viewer'  # Default read access
            }
        ]
        
        # If policy references other policies, create asset permissions
        if any('include' in line for line in content.get('lines', [])):
            assets_permissions[policy_id] = [
                {
                    'asset_id': ref_policy,
                    'role_code': 'reader'
                }
                for ref_policy in extract_policy_references(content)
            ]
    
    return {
        'actors_permissions': actors_permissions,
        'assets_permissions': assets_permissions
    }

def extract_policy_references(policy_content):
    """Extract referenced policies from policy content.
    
    Args:
        policy_content (dict): Policy content from get_policy_content
        
    Returns:
        list: List of referenced policy paths
    """
    references = []
    for line in policy_content.get('lines', []):
        if 'include' in line:
            # This is a simplified parser - adjust based on actual policy format
            # Example: include "/opt/pbul/policies/common.conf"
            path = line.split('"')[1] if '"' in line else line.split("'")[1]
            references.append(path)
    return references

def getactors():
    api_url: str=f'https://{constants.server}:{constants.port}/REST/v2.0/'
    raise ValueError("Incomplete implementation")
