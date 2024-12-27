import socket
import threading
import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

# Hash functions modeled as random oracles
def H1(data):
    return hashlib.sha256(data).hexdigest()

def H2(data):
    return hashlib.sha256(data).digest()

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def xor_bytes(b1, b2):
    # Adjust to handle different length byte strings
    max_len = max(len(b1), len(b2))
    b1 = b1.ljust(max_len, b'\x00')
    b2 = b2.ljust(max_len, b'\x00')
    return bytes([x ^ y for x, y in zip(b1, b2)])

def set_to_bytes(input_set):
    """
    Converts the elements of a set to bytes.

    Parameters:
        input_set (set): A set containing elements to be converted to bytes.
    
    Returns:
        set: A new set with elements converted to bytes.
    
    Raises:
        ValueError: If any element in the set is not serializable to bytes.
    """
    if not isinstance(input_set, set):
        raise TypeError("Input must be a set.")
    
    try:
        return {bytes(str(element), 'utf-8') for element in input_set}
    except Exception as e:
        raise ValueError(f"Error converting elements to bytes: {e}")



def setup_server(conn, addr):
    print(f"Connected by {addr}")
    
    # # Receive EDB from client
    # D = conn.recv(1024)
    # T = conn.recv(1024)  # Receive the EDB from the client
    # # D, T  = EDB

    # # Setting up T and D on the server side itself 
    # T = {}
    # D = {}
    print(f"Setup T-value complete: {T}")
    print(f"Setup D-value complete: {D}")

    return D, T


def server_update(conn, addr, D, T):

    print(f"Connected by {addr}")

    # D, T  = EDB
    
    # Receive label and e from client
    label = conn.recv(1024)  # Receive the label from the client
    e = conn.recv(1024)  # Receive the e-value from the client
    print(f"Received label-value: {label}")
    print(f"Received e-value: {e}")
    
    # Step 21: Store the entry in T
    T[label] = e

    print(f'D:{D}')
    print(f'T:{T}')
    
    conn.close()

def server_search(conn, addr, D, T):
    """
    Server-side search function.

    :return: Result set containing document indices for the keyword `w`.
    """
    print(f"Connected by {addr}")

    # D, T  = EDB

    # Receive labelw, kw and cw from client
    labelw = conn.recv(1024)  # Receive the labelw from the client
    kw = conn.recv(1024)  # Receive the kw-value from the client
    cw = conn.recv(1024)  # Receive the cw-value from the client
    print(f"Received labelw-value: {labelw}")
    print(f"Received kw-value: {kw}")
    print(f"Received cw-value: {cw}")

    # result_set = []  # Initialize the result set
    AuxSet = set()  # Initialize AuxSet to store document identifiers

    if kw:
        c = 0
        while c <= cw:
            label = H1(concatenate_byte_strings(kw,c))
            e = T[label]
            pad = H2(concatenate_byte_strings(kw,c))

            # Decrypt the encrypted entry
            b_ind = xor_bytes(e,pad)

            # Extract the operation indicator (add or delete)
            b = int(b_ind[0])

            # Extract the document identifier
            ind = b_ind[1:].decode()

            if b == 0:  # Handle "add" operation
                AuxSet.add(ind)  # Add the identifier to AuxSet
            else:  # Handle "delete" operation
                if ind in AuxSet:
                    AuxSet.remove(ind)  # Remove the identifier if it exists
            if label in T:
                del T[label]  # Remove the entry from T
            
            c = c + 1
    
     # Line 27: Compute the new tag set (PSet) using AuxSet
    PSet = {H1(concatenate_byte_strings(kw,ind)) for ind in AuxSet}

    D[labelw] = list(AuxSet) #line 28

    # server.send(set_to_bytes(AuxSet))

    for result in set_to_bytes(AuxSet):
        server.send(result)
                



    # # Iterate over all entries in the server state T
    # for label, e in T.items():
    #     # Check if the current label matches the search label
    #     if label.startswith(labelw):
    #         # Compute the pad using H2 and the provided kw and cw
    #         pad = H2(f"{kw}{cw}")

    #         # Decrypt the encrypted entry
    #         b_ind = bytes(a ^ b for a, b in zip(e, pad))

    #         # Extract the operation indicator (add or delete)
    #         b = int(b_ind[0])

    #         # Extract the document identifier
    #         ind = b_ind[1:].decode()

    #         # Include the document in the result set if it's an "add" operation
    #         if b == 0:
    #             result_set.append(ind)

        

    # # Return the result set to the client
    # return result_set

# Example use
import threading

D = {}
T = {}

def start_server():
    server.listen()
    print(f"Server is listening on {SERVER}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=(server_update), args=(conn, addr, D, T))
        thread.start()
        print(f"Active connections: {threading.active_count() - 1}")

start_server()

# def handle_client(conn, addr):
#     """
#     Handles individual client connections.
#     """
#     print(f"[NEW CONNECTION] {addr} connected.")

#     while True:
#         try:
#             # Receive message from the client
#             msg = conn.recv(1024).decode(FORMAT)
#             if not msg:
#                 break

#             # Handle the disconnect message
#             if msg == DISCONNECT_MESSAGE:
#                 print(f"[DISCONNECT] {addr} disconnected.")
#                 break

#             # Parse the client command
#             command, *args = msg.split(' ')
#             print(f"[COMMAND RECEIVED] {command} from {addr}")

#             # Handle commands
#             if command == "search":
#                 response = server_search(*args)
#             elif command == "update":
#                 response = server_update(*args)
#             else:
#                 response = f"Unknown command: {command}"

#             # Send the response back to the client
#             conn.send(response.encode(FORMAT))

#         except Exception as e:
#             print(f"[ERROR] {e}")
#             break

#     conn.close()
        
# def start_server():
#     """
#     Starts the server to listen for connections.
#     """
#     server.listen()
#     print(f"[STARTING] Server is listening on {SERVER}:{PORT}")

#     while True:
#         conn, addr = server.accept()
#         thread = threading.Thread(target=handle_client, args=(conn, addr))
#         thread.start()
#         print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


# # Start the server
# if __name__ == "__main__":
#     print("[STARTING] Server is starting...")
#     start_server()

