import socket
import threading
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import plyvel

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind(ADDR)

def pseudorandom_permutation(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def inverse_permutation(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

def hash_text_sha256(input_text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_text.encode(FORMAT))
    return sha256_hash.hexdigest()

def hash_byte_string_sha3_256(input_bytes):
    sha3_256_hash = hashlib.sha3_256()
    sha3_256_hash.update(input_bytes)
    return sha3_256_hash.digest()

def hash_byte_string_blake2b(input_bytes): #(H1 Hash)
    blake2b_hash = hashlib.blake2b(digest_size=32)
    blake2b_hash.update(input_bytes)
    return blake2b_hash.digest()

def xor_bytes(b1, b2):
    # Adjust to handle different length byte strings
    max_len = max(len(b1), len(b2))
    b1 = b1.ljust(max_len, b'\x00')
    b2 = b2.ljust(max_len, b'\x00')
    return bytes([x ^ y for x, y in zip(b1, b2)])

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def hash_byte_string_sha384(input_bytes): #(H2 hash)
    sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
    sha384_hash.update(input_bytes)  # Update with the input byte string
    return sha384_hash.digest()  # Return the hash digest as bytes

def inverse_adjust_and_concatenate(combined):
    # Extract the last byte as the op value
    op_byte = combined[-1:]  # Last byte is the op value
    op = int.from_bytes(op_byte, byteorder='big')  # Convert byte to integer

    # Remaining bytes represent the ind (with potential padding)
    ind_bytes = combined[:-1]  # Exclude the last byte for op

    # Remove padding ('*') from ind_bytes
    ind = ind_bytes.rstrip(b'*').decode()  # Decode to string after removing padding

    return ind, op

def print_contents_of_T(T):
    # Print the content of T
    print("Contents of T:")
    with T.iterator() as it:
        for key, value in it:
            print(f"u:{key}, e:{value}")  # Decode keys and values for readability

# Algorithm Starts from here

def fast_server_setup():
    T = plyvel.DB('T.db', create_if_missing=True)
    print("Server Setup Completed - T initiated")
    return T

def fast_server_update(conn, addr, T):
    print(f"Connected by {addr}")
    
    try:
        while True:
            # Step 14: Receive u and e from client
            u = conn.recv(1024)  # Receive the u-value from the client
            print(f"Received u")
            e = conn.recv(1024)  # Receive the e-value from the client
            print(f"Received e")
            
            # If no data is received (client disconnected)
            if not u or not e:
                print(f"Client {addr} has disconnected.")
                break
            
            # print(f"Received u-value: {u}")
            # print(f"Received e-value: {e}")
            
            # Step 21: Store the entry in T (assuming T is a dictionary or some data structure)
            T.put(u, e)  # Storing the key-value pair in T

    except Exception as e:
        print(f"Error while communicating with {addr}: {e}")
    
    finally:
        conn.close()  # Ensure the connection is closed once done

        # # Print the content of T
        # print("Contents of T:")
        # with T.iterator() as it:
        #     for key, value in it:
        #         print(f"u:{key}, e:{value}")  # Decode keys and values for readability

        print(f"Connection with {addr} closed.")

    



def fast_server_search(conn, addr, T):

    print(f"Connected by {addr}")
    
    # Step 1: Receive the search token from the client
    tw = conn.recv(1024)
    print('Search Token received')

    stc = conn.recv(1024)
    print('Current state received')

    c = conn.recv(1024)
    print('Counter received')
    

    # Step 3: Initialize result set and set of deleted file identifiers
    ID = set()  # Using set for ID
    delta = set()  # Using set for Δ (delta)
    
    for i in range(c, 0, -1):  # Loop from c to 1
        u = hash_byte_string_blake2b(concatenate_byte_strings(tw,sti))  # Compute hash H1(tw || sti)
        e = T.get(u)  # Retrieve e from the database T
        if e is None:
            raise ValueError(f"Key {u} not found in database")

        # Decode e by XORing with H2(tw || sti)
        # decoded = bytes(a ^ b for a, b in zip(e, H2(tw + sti)))
        term = hash_byte_string_sha384(concatenate_byte_strings(tw,sti))
        decoded = xor_bytes(e,term)

        # ind = int.from_bytes(decoded[:4], 'big')  # Convert the first 4 bytes to an integer
        # op = decoded[4:7].decode()  # Convert the next 3 bytes to a string (e.g., "add" or "del")
        ki = decoded[-32:]  # last 32 bytes will be ki
        ind, op = inverse_adjust_and_concatenate(decoded[:-32])
        
        if op == 0: # op = delete
            delta.add(ind)  # Add `ind` to delta
        elif op == 1: # op = add
            if ind in delta:
                delta.remove(ind)  # Remove `ind` from delta
            else:
                ID.add(ind)  # Add `ind` to ID

        # Update sti using the inverse permutation function
        sti = inverse_permutation(ki, sti)
    
    conn.send(ID)
    conn.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SERVER = socket.gethostbyname(socket.gethostname())
    server.bind(ADDR)  # Replace with your actual server address and port
    server.listen()
    print(f"Server is listening on {SERVER}:{PORT}")
    while True:
        conn, addr = server.accept()
        print(f"Accepted connection from {addr}")
        thread = threading.Thread(target=fast_server_update, args=(conn, addr, T))
        thread.start()
        print(f"Active connections: {threading.active_count() - 1}")

    # conn, addr = server.accept()
    # print(f"Accepted connection from {addr}")
    # thread_1 = threading.Thread(target=fast_server_update, args=(conn, addr, T))
    # thread_1.start()
    # print(f"Active connections: {threading.active_count() - 1}")

    
    
    


T = fast_server_setup()
# Start the server
start_server()
print_contents_of_T()


# while True:
    #         # Step 14: Receive u and e from client
    #         u = conn.recv(1024)  # Receive the u-value from the client
    #         print(f"Received u")
    #         e = conn.recv(1024)  # Receive the e-value from the client
    #         print(f"Received e")
            
    #         # If no data is received (client disconnected)
    #         if not u or not e:
    #             print(f"Client {addr} has disconnected.")
    #             break
            
    #         # print(f"Received u-value: {u}")
    #         # print(f"Received e-value: {e}")
            
    #         # Step 21: Store the entry in T (assuming T is a dictionary or some data structure)
    #         T.put(u, e)  # Storing the key-value pair in T
   
            # Step 14: Receive u and e from client
    # u = conn.recv(1024)  # Receive the u-value from the client
    # print(f"Received u")
    # e = conn.recv(1024)  # Receive the e-value from the client
    # print(f"Received e")
            
    # # If no data is received (client disconnected)
    # # if not u or not e:
    # #     print(f"Client {addr} has disconnected.")
    # # break
            
    #         # print(f"Received u-value: {u}")
    #         # print(f"Received e-value: {e}")
            
    #         # Step 21: Store the entry in T (assuming T is a dictionary or some data structure)
    # T.put(u, e)  # Storing the key-value pair in T


# import socket
# import threading

# HEADER = 64
# PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER, PORT)
# FORMAT = 'utf-8'
# DISCONNECT_MESSAGE = "!DISCONNECT"

# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind(ADDR)

# def setup(lam):
#     T = {}
#     print("Setup Completed. Long term key initiated, State and Index map initiated")
#     return T

# def handle_client(conn, addr, T):
#     print(f"Connected by {addr}")
#     u = conn.recv(1024)  # Receive the u-value from the client
#     e = conn.recv(1024)  # Receive the e-value from the client
#     print(f"u-value: {u}")
#     print(f"e-value: {e}")
#     conn.close()

# def start_server():
#     server.listen()
#     print(f"Server is listening on {SERVER}:{PORT}")
#     while True:
#         conn, addr = server.accept()
#         thread = threading.Thread(target=handle_client, args=(conn, addr, T))
#         thread.start()
#         print(f"Active connections: {threading.active_count() - 1}")

# T = {"file1.txt": b'encrypted_data_1', "file2.txt": b'encrypted_data_2'}

# start_server()






        

    
    # # Step 4: Perform backward search in the update sequence
    # for (u, e) in reversed(T.items()):
    #     # Generate ephemeral key k_i for each entry
    #     k_i = hash_byte_string_sha3_256(concatenate_byte_strings(encrypted_keyword, u))
        
    #     # Recover previous state `st_i` using the ephemeral key
    #     previous_state = inverse_permutation(k_i, current_state)
        
    #     # Check if this entry is an "add" or "delete" update and process accordingly
    #     b_ind, b_op, _ = e[:32], e[32:33], e[33:]  # Extract components from `e`
    #     ind = b_ind.decode(FORMAT)
    #     op = int.from_bytes(b_op, 'big')  # Convert `b_op` to integer (0 for delete, 1 for add)
        
    #     if op == 0:  # Delete operation
    #         D.add(ind)  # Add `ind` to deleted set
    #     elif op == 1:  # Add operation
    #         if ind in D:
    #             D.remove(ind)  # Remove from `D` if it was previously deleted
    #         else:
    #             result_set.add(ind)  # Add to result set if not in `D`
        
    #     # Update current state to the previous state for the next iteration
    #     current_state = previous_state
    
    # # Send the result set back to the client
    # conn.send(str(result_set).encode(FORMAT))
    # conn.close()
    # print("Search completed. Results sent to the client.")

# Print the content of T
# print("Contents of T:")
# with T.iterator() as it:
#     for key, value in it:
#         print(f"u:{key}, e:{value}")  # Decode keys and values for readability

# Print contents of T (for debugging or logging purposes)
# for e in T.get(u):
#     print(f"u: {u}, e: {e}")

# print('Server - Done')

# # Print contents of T (for debugging or logging purposes)
# for key, value in T.items():
#     print(f"u: {key}, e: {value}")

# print('Server - Done')

# def fast_server_update(conn, addr, T):

#     print(f"Connected by {addr}")
    
#     # Step 14: Receive u and e from client
#     u = conn.recv(1024)  # Receive the u-value from the client
#     e = conn.recv(1024)  # Receive the e-value from the client
#     print(f"Received u-value: {u}")
#     print(f"Received e-value: {e}")
    
#     # Step 21: Store the entry in T
#     T.put(u, e)

#     # conn.close()


# def start_server():
#     server.listen()
#     print(f"Server is listening on {SERVER}:{PORT}")
#     while True:
#         conn, addr = server.accept()
#         thread = threading.Thread(target= fast_server_update, args=(conn, addr, T))
#         thread.start()
#         print(f"Active connections: {threading.active_count() - 1}")

# T = fast_server_setup()
# start_server()



# for key, value in T:
#     print(f"u: {key}, e: {value}")

# print('Server - Done')


# def start_server():
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind(ADDR)  # Replace with your actual server address and port
#     server.listen()
#     print(f"Server is listening on {SERVER}:{PORT}")
    
#     while True:
#         conn, addr = server.accept()
#         print(f"Accepted connection from {addr}")
#         thread = threading.Thread(target=fast_server_update, args=(conn, addr, T))
#         thread.start()
#         thread.join()  # Wait for the thread to complete before proceeding
#         print("Received all data. Printing contents of T.")
        
        # # Print all contents of T
        # with T.iterator() as it:
        #     for key, value in it:
        #         print(f"u: {key}, e: {value}")

    # conn, addr = server.accept()
    # print(f"Accepted connection from {addr}")
    # thread = threading.Thread(target=fast_server_update, args=(conn, addr, T))
    # thread.start()
    # print(f"Active connections: {threading.active_count() - 1}")









