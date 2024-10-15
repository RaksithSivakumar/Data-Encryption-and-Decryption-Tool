import json
from cryptography.fernet import Fernet

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Save data securely
def save_secure_data(file_path, data, password):
    fernet = Fernet(password.encode())
    encrypted_data = fernet.encrypt(json.dumps(data).encode())
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

# Load secure data
def load_secure_data(file_path, password):
    fernet = Fernet(password.encode())
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    return json.loads(decrypted_data.decode())
