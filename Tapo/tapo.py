import Tapo.encryption as encryption

import requests
import json
import logging


class Tapo:
    def __init__(self, IP: str, username: str, password: str, terminalUUID = '00-00-00-00-00-00'):
        # Create a logger to use in the module
        self.logger = logging.getLogger('Tapo/API')
        self.session = requests.Session()

        self.IP = IP
        self.user = username
        self.password = password
        self.terminalUUID = terminalUUID
        self.seq = None

        if not self.__init_old__():
            self.logger.debug('Old login failed!')
            if not self.__init_new__():
                self.logger.fatal('Login failed!')
                return None

        self.logger.info('Login succesful!')


    def __init_old__(self):
        self.keyPair = encryption.generateKeyPair()

        # Get the keys and log in.
        # If there was an error during either of the steps, the returned object will just be "False"
        if not self.__get_keys__():
            return False
        if not self.__login__():
            return False
        return True        


    # There is now a new protocol used to "secure" queries to the plugs
    def __init_new__(self):
        # Generate random bytes and start the authentication to the plug
        localSeed = encryption.getRandomBytes(16)
        response = self.session.post("http://{}/app".format(self.IP) + '/handshake1', data=localSeed, verify=False).content

        # Get the server hashes, generate the auth hash and compare it to the one on the server
        remoteSeed, serverHash = response[0:16], response[16:]

        authHash = encryption.calcAuthHash(self.user.encode('utf-8'), self.password.encode('utf-8'))
        localSeedAuthHash = encryption.calcSHA256(localSeed + remoteSeed + authHash)

        if serverHash != localSeedAuthHash:
            logging.error('Wrong login!\nServer Hash: ' + serverHash + '\nLocal Auth: ' + localSeedAuthHash)
            return False

        # Continue the handshake by sending a new hash generated from the hashes above
        response = self.session.post("http://{}/app".format(self.IP) + '/handshake2', data=encryption.calcSHA256(remoteSeed + localSeed + authHash), verify=False)

        # Generate the AES key/IV by using the hashes
        ivSeq = encryption.calcSHA256(b"iv" + localSeed + remoteSeed + authHash)
        self.decodedKey = {
            "secretKeySpec": encryption.calcSHA256(b"lsk" + localSeed + remoteSeed + authHash)[:16],
            "ivParameterSpec": ivSeq[:12],
        }

        # Get the sequence number and generate the signature that will be used for every request
        self.seq = int.from_bytes(ivSeq[-4:], "big", signed=True)
        self.signature = encryption.calcSHA256(b"ldk" + localSeed + remoteSeed + authHash)[:28]

        return True


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

        response = self.session.post("http://{}/app".format(self.IP), data=json.dumps(data), verify=False)

        if response.status_code != 200:
            return False

        try:
            self.key = json.loads(response.content.decode('utf-8'))['result']['key']
        except KeyError:
            return False

        self.decodedKey = encryption.decodeTapoKey(self.key, self.keyPair)

        return True


    # Login to the plug and get the Authorization Token used to authenticate requests.
    # @return bool Whether the login was succesful or not
    def __login__(self) -> bool:
        emailHash = encryption.shaDigestEmail(self.user)

        data = {
            "method": "login_device",
            "params": {
                "username": encryption.b64Encode(emailHash),
                "password": encryption.b64Encode(self.password),
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


        response = self.session.post("http://{}/app".format(self.IP), data=json.dumps(secureData), verify=False)

        if response.status_code != 200:
            self.logger.fatal('Error during login request!\n' + response.content.decode('utf-8'))
            return False

        encryptedJsonResponse = json.loads(response.content.decode("utf-8"))['result']['response']
        
        decryptedJsonData = encryption.decryptJsonData(self.decodedKey, encryptedJsonResponse)
        self.authToken = json.loads(decryptedJsonData)['result']['token']

        return True


    def __request__(self, data: dict) -> str:
        # Pick the encryption method depending on whether the seq var exists
        if self.seq:
            # Increase seq number before than sending the request
            self.seq += 1
            encryptedJsonData = encryption.encryptJsonDataNew(self.decodedKey, json.dumps(data), self.seq)

            sig = encryption.calcSHA256(self.signature + self.seq.to_bytes(4, "big", signed=True) + encryptedJsonData)

            encryptedJsonData = sig + encryptedJsonData

            url = "http://{}/app/request".format(self.IP)
            response = self.session.post(url, data=encryptedJsonData, params={"seq": self.seq})

            if response.status_code != 200:
                self.logger.fatal('Error during request!\nRequest: ' + json.dumps(data) + '\nResponse:' + response.content.decode('utf-8'))
                return None

            decryptedJsonData = encryption.decryptJsonDataNew(self.decodedKey, response.content[32:], self.seq)

            return decryptedJsonData
        else:
            encryptedJsonData = encryption.encryptJsonData(self.decodedKey, json.dumps(data))

            secureData = {
                "method":"securePassthrough",
                "params": {
                    "request": encryptedJsonData
                }
            }

            url = "http://{}/app?token={}".format(self.IP,self.authToken)

            response = self.session.post(url, data=json.dumps(secureData), verify=False)

            if response.status_code != 200:
                self.logger.fatal('Error during request!\nRequest: ' + json.dumps(data) + '\nResponse:' + response.content.decode('utf-8'))
                return None

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
