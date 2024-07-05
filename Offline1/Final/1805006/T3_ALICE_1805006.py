import socket
from T2_DiffieHellman_1805006 import *
from T1_AES_1805006 import *


# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
server_address = ('localhost', 12345)

# Bind the socket to the server address
server_socket.bind(server_address)

# Listen for incoming connections
server_socket.listen(1)

print('Server listening on {}:{}'.format(*server_address))

while True:
    # Wait for a client to connect
    print('Waiting for a connection...')
    client_socket, client_address = server_socket.accept()
    print('Accepted connection from {}:{}'.format(*client_address))

    
    # Send a response back to the client
    # response = 'Hello from the server!'
    # client_socket.sendall(response.encode())
    k=128
    p = generate_kbit_safe_prime(k)
    g = generate_primitive_root_safe_prime(p, (p-1)/4, (p-1)/2)
    a = generate_kbit_prime((k>>1)+1)
    B = modular_exponent(g,a,p)
    
    send_msg =str(k) + " " + str(p) + " " + str(g) + " " + str(B)
    
    client_socket.sendall(send_msg.encode())
    
    # Receive data from the client
    data = client_socket.recv(2048)
    print('Received data:', data.decode())
    
    A=int(data.decode())
    
    X = modular_exponent(A,a,p)
    print("X = " + str(X))
    
    key_str = int_to_ASCII_string(X,k)
    # write_text_to_file("key_ALICE.txt", key_str)
    # print(key_str)
    # print(len(key_str))
    
    txt = read_text_from_file("T3_text_ALICE_1805006.txt")
    print(txt)
    
    
    encrypted_txt = encrypt(txt, key_str, k)
    print(encrypted_txt)
    
    
    client_socket.sendall(encrypted_txt.encode())
    # decrypted_txt = decrypt(encrypted_txt, key_str, k)
    # print(decrypted_txt)
    
    

    # Close the client socket
    client_socket.close()