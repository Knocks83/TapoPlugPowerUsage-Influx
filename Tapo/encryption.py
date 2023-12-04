from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.Util import Padding
import base64


def generateKeyPair() -> dict[str, str]:
  key = RSA.generate(1024)
  privateKey = key.export_key(pkcs=8)
  publicKey = key.publickey().export_key(pkcs=8)

  tapoKeyPair = {
    "public": publicKey.decode('utf-8'),
    "private": privateKey.decode('utf-8'),
  }

  return tapoKeyPair


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


def encryptJsonData(decodedTapoKey, jsonData: str):
  try:
    aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])
    padJsonData = Padding.pad(jsonData.encode('utf-8'), 16, 'pkcs7')
    encryptedJsonData = aes.encrypt(padJsonData)
    return base64.b64encode(encryptedJsonData).decode()
  except Exception as e:
    raise e


def decryptJsonData(decodedTapoKey, encryptedJsonData) -> str:
    encryptedJsonData = base64.b64decode(encryptedJsonData)
    aes = AES.new(decodedTapoKey["secretKeySpec"], AES.MODE_CBC, IV=decodedTapoKey["ivParameterSpec"])

    decryptedJsonData = aes.decrypt(encryptedJsonData)
    return decryptedJsonData.decode().strip()
