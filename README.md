# Data Encryption and Decryption Tool

## Description

The **Data Encryption and Decryption Tool** is a Python-based application designed to demonstrate various encryption algorithms, specifically AES and RSA. This tool allows users to encrypt and decrypt text or files using these algorithms, providing a user-friendly interface built with Streamlit.

## Features

- Encrypt and decrypt text using AES (Advanced Encryption Standard).
- Generate RSA keys for encryption and decryption.
- Encrypt and decrypt text using RSA (Rivest-Shamir-Adleman).
- User-friendly web interface.

## Prerequisites

- Python 3.6 or higher

- Required Python packages:
  - Streamlit
  - PyCryptodome

You can install the required packages using pip:
```bash
pip install -r requirements.txt
```
### Installation
Clone the repository:

```bash
Copy code
git clone https://github.com/yourusername/Data-Encryption-and-Decryption-Tool.git
cd Data-Encryption-and-Decryption-Tool
```
### Usage
#### Run the application:
```bash
Copy code
streamlit run app.py
```
Open your web browser and navigate to ```http://localhost:8501.```

### AES Encryption

- Select AES from the encryption algorithm dropdown.

- Enter text to encrypt.

- Click Encrypt with AES to generate the encrypted text and IV.

- To decrypt, enter the encrypted text and IV, then click Decrypt AES.

### RSA Encryption
- Select RSA from the encryption algorithm dropdown.

- Enter text to encrypt.

- Click Encrypt with RSA to generate the encrypted text.

- To decrypt, enter the encrypted text and click Decrypt RSA.

### Contributing
Contributions are welcome! If you have suggestions or improvements, please feel free to create a pull request or open an issue.


### Running the Tool

1. **Clone the Repository**: Use `git clone` to clone your project.
2. **Install Dependencies**: Run `pip install -r requirements.txt` to install required libraries.
3. **Run the App**: Execute `streamlit run app.py` to start the application.

### Summary
This structure and code organization will allow you to automate the **Data Encryption and Decryption Tool** effectively while providing a user-friendly interface for users to perform encryption and decryption operations using both AES and RSA algorithms. If you have any further requirements or changes, feel free to ask!
