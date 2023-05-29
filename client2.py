from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import psutil
import socket
import json

# Load public key
public_key = RSA.import_key(open("receiver.pem").read())

# Generate RSA keys
private_key = RSA.generate(1024)

# Generate symmetric key
symmetric_key = "Thisisaverysecretkey".encode()

# Sensor data
sensor_data = {
    "GPS": "37.1426 N, 74.0060 W",
    "Accelerometer": "0.19 m/s²",
    "Light": "1000 lux"
}

# Sign the data
hash_of_sensor_data = SHA256.new(str(sensor_data).encode())
signature = pkcs1_15.new(private_key).sign(hash_of_sensor_data)

# Encrypt the symmetric key
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

print(f'Encrypted symmetric key before sending: {enc_symmetric_key.hex()}')

# Create a socket connection to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 6789)
client_socket.connect(server_address)

# Send the client's public key
serialized_public_key = private_key.publickey().export_key().decode()
client_socket.send(serialized_public_key.encode())

start_time = time.time()

# Send the encrypted symmetric key
client_socket.send(enc_symmetric_key)

print(f'Encrypted symmetric key after sending: {enc_symmetric_key.hex()}')

# Wait for the ACK from the server
server_response = client_socket.recv(1024).decode()
assert server_response == "ACK", "Error: Failed to get the ACK from the server"

# Send the sensor data and signature
client_socket.send(json.dumps((sensor_data, signature.hex())).encode())

# Wait for the server response
server_response = client_socket.recv(1024).decode()
assert server_response == "ACK", "Error: Failed to get the ACK from the server"

client_socket.close()

# Calculate the latency
end_time = time.time()
latency = end_time - start_time
print(f"Latency: {latency} seconds")

# Calculate the CPU usage
cpu_usage = psutil.cpu_percent()
print(f"CPU Usage: {cpu_usage}%")