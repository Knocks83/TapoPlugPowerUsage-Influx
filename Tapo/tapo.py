import Tapo.encryption as encryption

import requests
import json
from base64 import b64encode

import logging


class Tapo:
    def __init__(self, IP: str, username: str, password: str, terminalUUID = '00-00-00-00-00-00'):
        # Create a logger to use in the module
        self.logger = logging.getLogger('Tapo/API')

        self.IP = IP
        self.user = username
        self.password = password
        self.keyPair = encryption.generateKeyPair()
        self.terminalUUID = terminalUUID

        # Get the keys and log in.
        # If there was an error during either of the steps, the returned object will just be "None"
        if not self.__get_keys__():
            return None
        
        if not self.__login__():
            return None
    
    # Get the keys used to encrypt/decrypt the requests directed to the plug.
    # @return bool Whether the operation was succesful or not
    def __get_keys__(self) -> bool:
        data = {
            "method": "handshake",
            "params": {
                "key": self.keyPair['public'],
            },
            "requestTimeMils":0
        }

        response = requests.post("http://{}/app".format(self.IP), data=json.dumps(data), verify=False)

        if response.status_code != 200:
            self.logger.fatal('Error during key handshake!\n' + response.content.decode('utf-8'))
            return False

        self.key = json.loads(response.content.decode('utf-8'))['result']['key']

        # Store the cookie in the object, because it will be used during every request.
        cookie = response.headers["Set-Cookie"].split(';')[0].split('=')
        self.cookies = {
            cookie[0]: cookie[1]
        }

        self.decodedKey = encryption.decodeTapoKey(self.key, self.keyPair)

        return True


    # Login to the plug and get the Authorization Token used to authenticate requests.
    # @return bool Whether the login was succesful or not
    def __login__(self) -> bool:
        emailHash = encryption.shaDigestEmail(self.user)

        data = {
            "method": "login_device",
            "params": {
                "username": b64encode(emailHash.encode()).decode("utf-8"),
                "password": b64encode(self.password.encode()).decode("utf-8"),
            },
            "requestTimeMils":0
        }

        encyptedJsonData = encryption.encryptJsonData(self.decodedKey, json.dumps(data))

        secureData = {
            "method":"securePassthrough",
            "params":{
                "request": encyptedJsonData
            }
        }


        response = requests.post("http://{}/app".format(self.IP), cookies=self.cookies, data=json.dumps(secureData), verify=False)

        if response.status_code != 200:
            self.logger.fatal('Error during login request!\n' + response.content.decode('utf-8'))
            return False

        encryptedJsonResponse = json.loads(response.content.decode("utf-8"))['result']['response']
        
        decryptedJsonData = encryption.decryptJsonData(self.decodedKey, encryptedJsonResponse)
        self.authToken = json.loads(decryptedJsonData)['result']['token']

        return True


    def __request__(self, data: dict) -> str:
        encyptedJsonData = encryption.encryptJsonData(self.decodedKey, json.dumps(data))
        secureData = {
            "method":"securePassthrough",
            "params":{
            "request": encyptedJsonData
            }
        }

        response = requests.post("http://{}/app?token={}".format(self.IP,self.authToken), cookies=self.cookies, data=json.dumps(secureData), verify=False)
        
        if response.status_code != 200:
            self.logger.fatal('Error during request!\nRequest: ' + json.dumps(data) + '\nResponse:' + response.content.decode('utf-8'))

        encryptedJsonResponse = json.loads(response.content.decode("utf-8"))['result']['response']
        
        decryptedJsonData = encryption.decryptJsonData(self.decodedKey, encryptedJsonResponse)
        return "".join(n for n in decryptedJsonData if ord(n) >= 32 and ord(n) <= 126)


    def getDeviceInfo(self) -> dict:
        data = {
            "method": "get_device_info",
            "requestTimeMils":0,
            "terminalUUID": self.terminalUUID
        }

        response = self.__request__(data)
        return json.loads(response)


    def getCurrentPower(self) -> dict:
        data = {
            "method": "get_current_power",
            "requestTimeMils":0,
            "terminalUUID": self.terminalUUID
        }

        response = self.__request__(data)
        return json.loads(response)

