# ENCRYPTING

from cryptography.fernet import Fernet

# Generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)

# Load the previously generated key
def load_key():
    return open('encryption_key.key', 'rb').read()

# Encrypt the file
def encrypt_file(filename):
    key = load_key()
    cipher = Fernet(key)

    # Read the file data
    with open(filename, 'rb') as file:
        file_data = file.read()

    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)

    # Write the encrypted data to a new file
    with open(f"{filename}.enc", 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

# First, generate the key
generate_key()

# Specify the file to encrypt (e.g., 'example.py')
file_to_encrypt = 'example.py'

# Encrypt the file
encrypt_file(file_to_encrypt)

print(f"File '{file_to_encrypt}' has been encrypted and saved as '{file_to_encrypt}.enc'.")

# DECRYPTION

from cryptography.fernet import Fernet

# Load the key from the file
def load_key():
    return open('encryption_key.key', 'rb').read()

# Decrypt the file
def decrypt_file(encrypted_filename):
    key = load_key()
    cipher = Fernet(key)

    # Read the encrypted file
    with open(encrypted_filename, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Write the decrypted data to a new file (removing the '.enc' extension)
    original_filename = encrypted_filename.replace('.enc', '')
    with open(original_filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

# Specify the file to decrypt (e.g., 'example.py.enc')
encrypted_file = 'example.py.enc'

# Decrypt the file
decrypt_file(encrypted_file)

print(f"File '{encrypted_file}' has been decrypted and saved as '{encrypted_file.replace('.enc', '')}'.")
