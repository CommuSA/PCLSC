import pyaes
from Crypto.Util.Padding import pad, unpad
from charm.toolbox.pairinggroup import *
import hashlib


group = PairingGroup('SS512')

key = hashlib.sha256(group.serialize(group.random(GT))).digest()
print(key)
aes = pyaes.AESModeOfOperationECB(key)

data = b'Hello, AES!'

padded_data = pad(data, 16)
ciphertext = aes.encrypt(padded_data)

print("Ciphertext:", ciphertext)

aes = pyaes.AESModeOfOperationECB(key)

decrypted_data = aes.decrypt(ciphertext)

original_data = unpad(decrypted_data, 16)

print("Decrypted Data:", original_data.decode('utf-8'))
