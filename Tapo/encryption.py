from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
import base64


def generateKeyPair() -> dict[str, str]:
  key = RSA.generate(1024)
  privateKey = key.export_key(pkcs=8)
  publicKey = key.publickey().export_key(pkcs=8)

  tapoKeyPair = {
    "public": publicKey.decode('UTF-8'),
    "private": privateKey.decode('UTF-8'),
  }

  return tapoKeyPair


# Just wrap "get_random_bytes" to use the encryption module instead of the Crypto one
def getRandomBytes(size=16) -> bytes:
  return get_random_bytes(size)


# Calculate the auth hash used in the new encryption
# It is different from "calcSHA256" because you must calculate the SHA1 of the parameters
def calcAuthHash(username: bytes, password: bytes) -> bytes:
  return SHA256.new(SHA1.new(username).digest() + SHA1.new(password).digest()).digest()


# Just wrap SHA256 to use the encryption module instead of the Crypto one
def calcSHA256(text: bytes) -> bytes:
  return SHA256.new(text).digest()


# Just wrap b64encode to use the encryption module instead of the base64 one
def b64Encode(text: str) -> str:
  return base64.b64encode(text.encode('UTF-8')).decode('UTF-8')


def decodeTapoKey(tapoKey: str, tapoKeyPair: dict[str, str]) -> dict[str, bytes] | None:
  try:
    encrypt_data = base64.b64decode(tapoKey)
    rsa_key = RSA.importKey(tapoKeyPair["private"])

    cipher = PKCS1_v1_5.new(rsa_key)
    decryptedBytes = cipher.decrypt(encrypt_data, None)

    decodedTapoKey = {
      "secretKeySpec": decryptedBytes[:16],
      "ivParameterSpec": decryptedBytes[16:32],
    }
    return decodedTapoKey
  except Exception as e:
    raise e


def shaDigestEmail(email: str) -> str:
  email = str.encode(email)
  emailHash = SHA1.new(email).hexdigest()
  return emailHash


def encryptJsonData(decodedTapoKey: dict, jsonData: str) -> str:
    try:
        aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])
        padJsonData = Padding.pad(jsonData.encode('utf-8'), 16, 'pkcs7')
        encryptedJsonData = aes.encrypt(padJsonData)
        return base64.b64encode(encryptedJsonData).decode('UTF-8')
    except Exception as e:
        raise e


def encryptJsonDataNew(decodedTapoKey: dict, jsonData: str, seq: int) -> bytes:
    try:
        padJsonData = Padding.pad(jsonData.encode('utf-8'), 16, 'pkcs7')
        aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"] + seq.to_bytes(4, "big", signed=True))
        encryptedJsonData = aes.encrypt(padJsonData)
        return encryptedJsonData
    except Exception as e:
        raise e


def decryptJsonData(decodedTapoKey, encryptedJsonData) -> str:
    encryptedJsonData = base64.b64decode(encryptedJsonData)
    aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])

    decryptedJsonData = aes.decrypt(encryptedJsonData)
    return decryptedJsonData.decode('UTF-8').strip()


def decryptJsonDataNew(decodedTapoKey, encryptedJsonData, seq: int) -> str:
    aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"] + seq.to_bytes(4, "big", signed=True))

    decryptedJsonData = aes.decrypt(encryptedJsonData)
    decryptedJsonData = Padding.unpad(decryptedJsonData, 16, 'pkcs7')

    return decryptedJsonData.decode('UTF-8').strip()
