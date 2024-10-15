import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# AES Encryption Function
def aes_encrypt(plain_text):
    aes_key = get_random_bytes(16)  # Generate a random 16-byte AES key
    cipher = AES.new(aes_key, AES.MODE_CBC)  # Use CBC mode
    iv = cipher.iv  # Initialization Vector
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    
    # Return the IV, encrypted text, and AES key as base64 encoded strings
    return base64.b64encode(iv).decode(), base64.b64encode(encrypted).decode(), base64.b64encode(aes_key).decode()

# AES Decryption Function
def aes_decrypt(encrypted_text, iv, aes_key):
    cipher = AES.new(base64.b64decode(aes_key), AES.MODE_CBC, iv=base64.b64decode(iv))
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted.decode()

# RSA key generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# RSA encryption function
def rsa_encrypt(plain_text, public_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_data = cipher_rsa.encrypt(plain_text.encode())
    return base64.b64encode(encrypted_data).decode()

# RSA decryption function
def rsa_decrypt(cipher_text, private_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted_data = cipher_rsa.decrypt(base64.b64decode(cipher_text))
    return decrypted_data.decode()

# Example Usage
if __name__ == "__main__":
    # AES Encryption Example
    print("AES Encryption:")
    aes_input_text = "DFSJIDSKBF"
    iv, encrypted_text, aes_key = aes_encrypt(aes_input_text)
    print("Initialization Vector (IV):", iv)
    print("Encrypted Text:", encrypted_text)
    print("AES Key:", aes_key)

    # AES Decryption Example
    print("\nAES Decryption:")
    decrypted_text = aes_decrypt(encrypted_text, iv, aes_key)
    print("Decrypted Text:", decrypted_text)

    # RSA Key Generation
    print("\nRSA Key Generation:")
    private_key, public_key = generate_rsa_keys()
    print("RSA Private Key:", private_key.decode())
    print("RSA Public Key:", public_key.decode())

    # RSA Encryption Example
    rsa_input_text = "This is a test message."
    print("\nRSA Encryption:")
    rsa_encrypted = rsa_encrypt(rsa_input_text, public_key)
    print("RSA Encrypted Text:", rsa_encrypted)

    # RSA Decryption Example
    print("\nRSA Decryption:")
    rsa_decrypted = rsa_decrypt(rsa_encrypted, private_key)
    print("RSA Decrypted Text:", rsa_decrypted)
