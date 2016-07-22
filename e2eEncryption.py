#!/usr/bin/python

# Import dependencies
import sys
import os
if sys.version_info[0] == 2:
  standard_b64encode = lambda x: x.encode("base64")
  standard_b64decode = lambda x: x.decode("base64")
else:
  from base64 import standard_b64encode
  from base64 import standard_b64decode
try:
  from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
  from cryptography.hazmat.backends import default_backend as DefaultBackend
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as e:
  raise NoEncryptionModuleError(str(e))

# e2e class used to provide encrypt and decrypt functionality
class e2eClass():
  def __init__(self, encryptionPassword, salt):
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(), 
      length=32,
      salt=salt.encode("ASCII"),
      iterations=30000,
      backend=DefaultBackend()
    )
    self.encryptionKey = kdf.derive(encryptionPassword.encode("UTF-8"))

  def EncryptData(self, clearText):
    iv = os.urandom(12)
    encryptor = Cipher(
      algorithms.AES(self.encryptionKey),
      modes.GCM(iv),
      backend=DefaultBackend()
    ).encryptor()
    cipherText = encryptor.update(clearText.encode("UTF-8")) + encryptor.finalize()
    cipherText = b"1" + encryptor.tag + iv + cipherText
    message = standard_b64encode(cipherText).decode("ASCII")
    return message

  def DecryptData(self, message):
    cipherText = standard_b64decode(message)
    version = cipherText[0:1]
    tag = cipherText[1:17]
    iv = cipherText[17:29]
    cipherText = cipherText[29:]
    decryptor = Cipher(
      algorithms.AES(self.encryptionKey),
      modes.GCM(iv, tag),
      backend=DefaultBackend()
    ).decryptor()
    clearText = decryptor.update(cipherText) + decryptor.finalize()
    return clearText

# Set parameters
encryptionPassword = 'password'
salt = 'salt'
clearText = 'testing123'

# Create object
e2eObject = e2eClass(encryptionPassword, salt)

# Encrypt message
message = e2eObject.EncryptData(clearText)

# Decrypt and print message
clearText = e2eObject.DecryptData(message)
print(clearText)
