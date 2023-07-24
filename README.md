# 🔏 SecureAEScape - Safeguarding Your Data in the Digital Realm! 🔏
This repository contains a client and server implementation for secure encryption and decryption of data using the Advanced Encryption Standard (AES).

The client.py script provides functionality to encrypt data and upload the **encrypted** super secret to the server, while the server.py script handles key management and secure key retrieval for decryption.

### Super Secret
The "Super Secret" refers to the key used for encrypting and decrypting data. It is a randomly generated 32-chars (256 bit) symmetric encryption key (AES key) that is unique to each encryption process. The "Super Secret" is never plainly transmitted over the network or locally stored; instead, it is encrypted using a key derived from the input file and the user-given encryption key, which is then securely stored on the server.

This two-step encryption process ensures that the encryption key remains confidential and can only be accessed by authorized parties.

### "su" (Super Secret Identifier)

The "su" value, which serves as a unique identifier for the encrypted super secret (superkey), is generated using the following steps:

1. **Encryption:** The contents of the file to be encrypted are encrypted using a randomly generated 32-byte "superkey" (referred to as "skey").

2. **Hashing:** The SHA256 hash of the encrypted contents (`emsg['ct']`) is computed. This produces a fixed-size hash value.

3. **Double Hashing:** The SHA256 hash of the previous hash value is computed, resulting in a unique and fixed-length identifier, which is the "su".

*Note: The "su" identifier ensures that each encrypted super secret has a unique identifier, making it easier for the server to manage multiple encrypted secrets.*

### "st" (Server Token)

The "st" value, known as the "Server Token," is used for authentication purposes when interacting with the server to add or remove encrypted super secrets. The "st" is generated as follows:

1. **Concatenation:** The SHA256 hash of the encrypted contents (`emsg['ct']`) is computed and concatenated with the user-defined "key" (password).

2. **Truncation:** The resulting concatenation is truncated to 32 bytes to create the "st."

*Note: The "st" ensures that only authorized clients can perform operations on their encrypted super secrets, as the server requires authentication based on this token.*

Both "su" and "st" values play crucial roles in securing the communication between the client and the server, ensuring that the encrypted data and superkeys are managed securely and accessed only by authorized clients.

## "websecret"

The "websecret" is a crucial component used in the `client.py` script for securely storing the encrypted "superkey" (referred to as "superkey") on the server. It allows the client to interact with the server while keeping the encrypted superkey hidden from potential adversaries.

The "websecret" is generated as follows:

1. **Encryption of Superkey:**
   The "superkey" is generated as a random 32-byte value, used for encrypting and decrypting the file contents. It is essential to keep this key secure and prevent unauthorized access.

2. **Encryption with User Key (Password):**
   To protect the "superkey," it is encrypted using a combination of the user-defined "key" (password) and a SHA256 hash of the encrypted file contents (`emsg['ct']`). This ensures that the "websecret" remains secure even if the "key" is compromised.

3. **Base64 Encoding:**
   The resulting encrypted "superkey" is encoded using Base64 to facilitate safe transmission and storage.

The "websecret" is then sent to the server and stored with the associated "su" identifier, making it possible for the client to later retrieve and decrypt the superkey when needed.

By using "websecret," the client can securely upload and store encrypted superkeys on the server, ensuring that the actual encryption key remains hidden and protected from unauthorized access.

### Components
`client.py` and `server.py` are two Python scripts that together form a secure communication system. `client.py` handles encryption, decryption, key storage, and communication with the server, while `server.py` sets up a Flask-based web server that manages encrypted super secrets (superkeys) identified by a unique "su" identifier. 

Further details about their functionalities will be provided in the following sections:

## Client.py

The `client.py` script is a command-line client for interacting with a remote server that stores encrypted super secret keys. The script allows you to perform various operations, including encryption, decryption, key removal, and retrieval of information.

### Prerequisites

Before running the script, make sure you have the following installed:

- Python 3.x
- Required Python packages (`Crypto`, `requests`)

You can install the required packages using `pip`:

```bash
pip install pycryptodome requests
```

### Usage

To use the `client.py` script, you can run it from the command line with the following options and arguments:

```
python client.py [options]
```

#### Options:

- `--infile`, `-i`: Path to the input file to be processed. If not provided, the script will read from STDIN.
- `--outfile`, `-o`: Path to the output file where the processed data will be written. If not provided, the script will write to STDOUT.
- `--server`, `-s`: The URL of the remote server to interact with. Default is `http://127.0.0.1:5000`.
- `--verbose`, `-v`: Enable verbose mode to print more information during execution.
- `--key`, `-k`: The encryption key to use for encrypting or decrypting data.
- `--remove-after`, `-a`: Number of allowed failed attempts for removing the superkey. This option is only applicable for the `remove` subcommand.

#### Subcommands:

The `client.py` script supports the following subcommands:

- `--encrypt`, `-e`: Encrypts the content of the input file and stores the encrypted data on the remote server.

  Usage: `python client.py --encrypt [options]`

- `--decrypt`, `-d`: Decrypts the content of the input file, retrieving the original data from the remote server.

  Usage: `python client.py --decrypt [options]`

- `--remove`, `-r`: Removes the superkey associated with the specified encrypted data from the remote server.

  Usage: `python client.py --remove [options]`

- `--info`, `-I`: Retrieves information about the specified encrypted data from the remote server.

  Usage: `python client.py --info [options]`

#### Examples:

1. Encrypt data:

   ```
   python client.py --encrypt -k <encryption_key> --infile plaintext.txt --outfile encrypted.json
   ```

2. Decrypt data:

   ```
   python client.py --decrypt -k <encryption_key> --infile encrypted.json --outfile decrypted.txt
   ```

3. Remove superkey:

   ```
   python client.py --remove -k <encryption_key> --infile encrypted.json
   ```

4. Retrieve information:

   ```
   python client.py --info -k <encryption_key> --infile encrypted.json
   ```

Note: The encrypted data is never sent to the server. Only the encrypted super secret (superkey) is transmitted, which is a secret key used for encryption and decryption.

## Server.py

The `server.py` script sets up a Flask-based web server to handle interactions with the client. It provides an API for adding, removing, and retrieving encrypted super secrets (superkeys) identified by the "su" identifier. The "su" identifier is generated by taking the SHA256 hash of the SHA256 hash of the encrypted contents of the file. The server listens on a specified host and port.

### Prerequisites

Before running the script, make sure you have the following installed:

- Python 3.x
- Required Python packages (`Flask`)

You can install the required packages using `pip`:

```bash
pip install Flask
```

### Usage

To run the server, use the following command:

```
python server.py [options]
```

#### Options:

- `--host`, `-H`: The listening host for the server. Default is `127.0.0.1`.
- `--port`, `-p`: The listening port for the server. Default is `5000`.

### API Endpoints

The server provides the following API endpoints to interact with the client:

1. **Add Super Secret** (PUT): `/api/add/<su>`

   Add a new super secret to the server with the specified "su" identifier. The "su" identifier is generated by taking the SHA256 hash of the SHA256 hash of the encrypted contents of the file. The encrypted super secret (superkey) is sent from the client to the server.

2. **Remove Super Secret** (DELETE): `/api/rem/<su>`

   Remove the superkey associated with the specified "su" identifier from the server.

3. **Retrieve Super Secret** (POST): `/api/get/<su>`

   Retrieve the encrypted super secret (superkey) associated with the specified "su" identifier from the server.

4. **Get Information** (GET): `/api/info/<su>`

   Retrieve information about the specified "su" identifier from the server, including the number of failed attempts and the optional removal after a certain number of failures.

### Examples:

1. Run the server on the default host and port:

   ```
   python server.py
   ```

2. Run the server on a specific host and port:

   ```
   python server.py --host 0.0.0.0 --port 8080
   ```

3. Use the server API endpoints to interact with the client (See `client.py` documentation for client usage examples).

Note: The `server.py` script provides API endpoints for the client to interact with, and the `client.py` script is used to communicate with the server by performing encryption, decryption, key removal, and information retrieval operations using the "su" identifier generated from the SHA256 hash of the encrypted contents of the file.
