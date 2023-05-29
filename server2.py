from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import psutil
import socket
import json

# Load private key
private_key = RSA.import_key(open("private.pem").read())

# Create a socket connection to listen to the client
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 6789)
server_socket.bind(server_address)
server_socket.listen(1)

while True:
    print("Waiting for a connection...")
    client_socket, client_address = server_socket.accept()

    start_time = time.time()

    # Receive the client's public key
    serialized_public_key = client_socket.recv(1024).decode()
    client_public_key = RSA.import_key(serialized_public_key)

    # Receive the encrypted symmetric key
    enc_symmetric_key = client_socket.recv(1024)
    print(f'Received encrypted symmetric key: {enc_symmetric_key.hex()}')

    # Decrypt the symmetric key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)

    # Send the ACK to the client
    client_socket.send("ACK".encode())

    # Receive the sensor data and signature
    received_data = json.loads(client_socket.recv(1024).decode())
    sensor_data, signature = received_data[0], received_data[1]

    # Verify the signature
    hash_of_sensor_data = SHA256.new(str(sensor_data).encode())
    try:
        pkcs1_15.new(client_public_key).verify(hash_of_sensor_data, bytes.fromhex(signature))
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")

    # Send the ACK to the client
    client_socket.send("ACK".encode())
    client_socket.close()

    # Calculate the latency
    end_time = time.time()
    latency = end_time - start_time
    print(f"Latency: {latency} seconds")

    # Calculate the CPU usage
    cpu_usage = psutil.cpu_percent()
    print(f"CPU Usage: {cpu_usage}%")