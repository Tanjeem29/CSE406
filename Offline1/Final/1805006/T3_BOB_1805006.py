import socket
from T2_DiffieHellman_1805006 import *
from T1_AES_1805006 import *
# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
server_address = ('localhost', 12345)

# Connect to the server
client_socket.connect(server_address)
print('Connected to {}:{}'.format(*server_address))


# Receive the response from the server
nums = client_socket.recv(2048)
print('Received:', nums.decode())
init = nums.decode().split(" ")

k = int(init[0])
p = int(init[1])
g = int(init[2])
B = int(init[3])

b = generate_kbit_prime((k>>1)+1) 
A = modular_exponent(g,b,p)

Y = modular_exponent(B,b,p)
print("Y = " + str(Y))

key_str = int_to_ASCII_string(Y,k)
print("key string:", key_str)
print("Length:", len(key_str))





# Send data to the server
data = str(A)
client_socket.sendall(data.encode())

response = client_socket.recv(2048)
encrypted_text = response.decode()
# print('Received response:', response.decode())
decrypted_text = decrypt(response.decode(), key_str, k)
write_text_to_file("T3_text_BOB_1805006.txt", decrypted_text)
# write_text_to_file("text_BOB.txt",'abcdefs')
print("Encrypted Text:", encrypted_text)
print("Decrypted Text:", decrypted_text)
# write_text_to_file("text_BOB.txt", decrypted_txt)
# Close the socket
client_socket.close()

