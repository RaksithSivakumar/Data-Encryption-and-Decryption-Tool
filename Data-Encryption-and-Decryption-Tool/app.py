import base64
import streamlit as st
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

# Streamlit Application
st.title("Data Encryption and Decryption Tool")

# Store RSA keys in session state
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'public_key' not in st.session_state:
    st.session_state.public_key = None

# Select Encryption Type
encryption_type = st.selectbox("Choose Encryption Algorithm", ["AES", "RSA"])

if encryption_type == "AES":
    st.subheader("AES Encryption")
    aes_input_text = st.text_area("Enter text to encrypt:")
    
    if st.button("Encrypt"):
        iv, encrypted_text, aes_key = aes_encrypt(aes_input_text)
        st.success("Encryption Successful!")
        st.write("Initialization Vector (IV):", iv)
        st.write("Encrypted Text:", encrypted_text)
        st.write("AES Key (keep it secure):", aes_key)

    st.subheader("AES Decryption")
    aes_encrypted_text = st.text_area("Enter AES encrypted text to decrypt:")
    aes_iv = st.text_area("Enter Initialization Vector (IV):")
    aes_key_input = st.text_area("Enter AES Key:")
    
    if st.button("Decrypt"):
        try:
            decrypted_text = aes_decrypt(aes_encrypted_text, aes_iv, aes_key_input)
            st.success("Decryption Successful!")
            st.write("Decrypted Text:", decrypted_text)
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")

elif encryption_type == "RSA":
    st.subheader("RSA Encryption")
    rsa_input_text = st.text_area("Enter text to encrypt:")
    
    if st.button("Generate RSA Keys"):
        st.session_state.private_key, st.session_state.public_key = generate_rsa_keys()
        st.success("RSA Keys Generated!")
        st.text_area("RSA Private Key:", st.session_state.private_key.decode(), height=100)
        st.text_area("RSA Public Key:", st.session_state.public_key.decode(), height=100)

    if st.button("Encrypt"):
        try:
            if st.session_state.public_key is None:
                st.error("Please generate RSA keys first.")
            else:
                rsa_encrypted = rsa_encrypt(rsa_input_text, st.session_state.public_key)
                st.success("Encryption Successful!")
                st.write("RSA Encrypted Text:", rsa_encrypted)
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")

    st.subheader("RSA Decryption")
    rsa_encrypted_text = st.text_area("Enter RSA encrypted text to decrypt:")
    rsa_private_key_input = st.text_area("Enter RSA Private Key:")
    
    if st.button("Decrypt"):
        try:
            rsa_decrypted = rsa_decrypt(rsa_encrypted_text, rsa_private_key_input)
            st.success("Decryption Successful!")
            st.write("Decrypted Text:", rsa_decrypted)
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")
