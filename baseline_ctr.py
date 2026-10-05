import json 
import pyaes, pbkdf2, binascii, os, secrets

def xor (data: bytes, key: bytes) -> bytes:
    return bytes(b1 ^ b2 for b1, b2 in zip(data, bytes((i for i in key * (len(data) // len(key) + 1)))))

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))



def xor_strings(s1: str, s2: str) -> str:
    # zip() stops at the length of the shorter string
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

with open('data.json', 'r', encoding = 'utf-8') as file:
    file_bytes = file.read()

print(file_bytes)

password = "s3cr3t*c0d3"
passwordSalt = os.urandom(16)
key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
print('AES encryption key:', binascii.hexlify(key))

iv = secrets.randbits(256)

aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
plaintext = file_bytes
ciphertext = aes.encrypt(plaintext)


print('Encrypted:', binascii.hexlify(ciphertext))


delta = xor_bytes (b"READ", b"DELE")
print("The xor: ", repr(delta))
print("The xor xor'd with DELE: ", xor_bytes(delta, b"DELE"))
print("The xor xor'd with READ: ", xor_bytes(delta, b"READ"))
# Xoring the other would return the other. The xor seems to be correct. 


offset = plaintext.index("READ")

tampered = bytearray(ciphertext)

for i, change in enumerate(delta): 
    tampered[offset + i] ^= change

tampered = bytes(tampered)


# Decrypt the ciphertext with the given key:
#   plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
tAes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
decrypted = aes.decrypt(ciphertext)
print('Original Decrypted:', decrypted)


tDecrypted = tAes.decrypt(tampered)
print('Tampered Decrypted:', tDecrypted)

