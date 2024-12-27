import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import hashlib
import plyvel
import pickle

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


def pseudorandom_function(key, message):
    # pseudo random funciton (prf) --  cryptographic function that, given an input and a secret key, produces
    # output that is indistinguishable from a truly random function to anyone without knowledge of the secret key.
    # this execution is using hmac and sha256
    # A pseudorandom Function cant be reversed, by any chance we can never figure out the encoded message

    return hmac.new(key, message.encode(), hashlib.sha256).digest()

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

def hash_byte_string_blake2b(input_bytes):
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

def hash_byte_string_sha384(input_bytes):
    sha384_hash = hashlib.sha384()  # Initialize SHA-384 hash object
    sha384_hash.update(input_bytes)  # Update with the input byte string
    return sha384_hash.digest()  # Return the hash digest as bytes

def adjust_and_concatenate(ind, op):
    # Convert op to a single byte (0 or 1)
    op_byte = bytes([op])  # This will give a byte with value 0 or 1

    # Convert ind to bytes
    ind_bytes = ind.encode()

    # Calculate available space for ind (48 bytes total minus 1 byte for op)
    max_ind_size = 16 - len(op_byte)

    # Truncate ind if necessary
    if len(ind_bytes) > max_ind_size:
        ind_bytes = ind_bytes[:max_ind_size]

    # If the combined length is less than 48 bytes, pad ind with '*'
    if len(ind_bytes) < max_ind_size:
        ind_bytes = ind_bytes.ljust(max_ind_size, b'*')  # Pad with '*'

    # Combine ind and op_byte
    combined = ind_bytes + op_byte

    return combined

# Algorithm starts from here

def fast_client_setup():
    # size = int(lam / 8)
    ks = os.urandom(32)
    S = plyvel.DB('S.db', create_if_missing=True)
    print("S - Setup successfully!")
    # S = {}
    return S, ks

def fast_client_update(key, S, ind, w, op, client):
    # Step 4: Calculate tw
    tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
    # Step 5-6: Retrieve stc and initialize c
    pickled_value = S.get(w.encode(), default=None)

    # Check if the value was found in the database
    if pickled_value is not None:
        stc, c = pickle.loads(pickled_value)
    else:
        stc = None
        c = 0

    # Step 7-10: Generate a new state if stc is None
    if stc is None:
        stc = os.urandom(32)  # Generate a random 32-byte value for stc
        c = 0  # Initialize c to 0
    
    # Step 9: Generate new key kc+1
    kc_next = os.urandom(32)
    
    # Step 10: Calculate new stc+1
    stc_next = pseudorandom_permutation(kc_next, stc)

    # Serialize the new state
    value = pickle.dumps((stc_next, c + 1))

    # Store the serialized value in the database
    S.put(w.encode(), value)
    
    # Step 11-12: Create e
    term1 = concatenate_byte_strings(adjust_and_concatenate(ind, op), kc_next) # this will always be of size 48 bytes, op will be at the end, and the ind will be truncated or padded acc to size
    term2 = hash_byte_string_sha384(concatenate_byte_strings(tw, stc_next))# this will alwayys be of size 48 bytes
    e = xor_bytes(term1, term2) # of 48 bytes
    
    # Step 13: Calculate u
    u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))
    
    # Step 14: Send u and e to server
    client.send(u)
    print(f'SENT - u')
    client.send(e)
    print(f'SENT - e')

def fast_client_search(key, S, w):
    # Step 4: Calculate tw
    tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
    # Step 5-6: Retrieve stc and initialize c
    pickled_value = S.get(w.encode(), default=None)

    # Check if the value was found in the database
    if pickled_value is not None:
        stc, c = pickle.loads(pickled_value)
    else:
        stc = None
        c = 0

    # Step 7-10: if stc is None, return 0
    if stc is None:
        return 0 
    
    # # Step 2: Generate the encrypted keyword (search token)
    # encrypted_keyword = pseudorandom_permutation(key, string_to_byte_string(hash_text_sha256(w)))
    
    # # Step 3: Concatenate the encrypted keyword and current state as the search token
    # search_token = concatenate_byte_strings(encrypted_keyword, stc)
    
    # Step 4: Send the search token, state and c to the server
    client.send(tw)
    print("Search token sent to the server.")

    client.send(stc)
    print("Current State sent to the server.")

    client.send(c)
    print("counter sent to the server.")
    
    # Step 5: Receive and print search results
    search_results = client.recv(4096)
    print("Search results received from server:", search_results.decode(FORMAT))



def start_client():
    # SERVER = 'localhost'  # Update with your server IP
    # PORT = 12345          # Ensure this matches the server's PORT

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER, PORT))

        # Example of using multiple indices and operations
        ind1 = 'file1.txt'
        ind2 = 'file2.txt'
        w1 = 'crypto'
        w2 = 'graphical'
        op1 = 1  # Use 0 for delete, 1 for add
        op2 = 0

        # fast_client_update(ks, S, ind1, w1, op1, client_socket)

        for i in range(1, 5):
            if i % 2 == 0:
                fast_client_update(ks, S, ind1, w1, op1, client_socket)
            else:
                fast_client_update(ks, S, ind2, w2, op2, client_socket)
        
        
        print("Client - Done")

# setup of 'S' and 'ks' 
S, ks = fast_client_setup()

# Start the client
start_client()



# import socket
# import os
# import time
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import hashlib

# HEADER = 64
# PORT = 5050
# SERVER = socket.gethostbyname(socket.gethostname())
# ADDR = (SERVER, PORT)
# FORMAT = 'utf-8'
# DISCONNECT_MESSAGE = "!DISCONNECT"

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect(ADDR)

# def pseudorandom_permutation(key, data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return cipher.encrypt(pad(data.encode(), AES.block_size))

# def inverse_permutation(key, encrypted_data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()

# def hash_text_sha256(input_text):
#     sha256_hash = hashlib.sha256()
#     sha256_hash.update(input_text.encode(FORMAT))
#     return sha256_hash.hexdigest()

# def hash_byte_string_sha3_256(input_bytes):
#     sha3_256_hash = hashlib.sha3_256()
#     sha3_256_hash.update(input_bytes)
#     return sha3_256_hash.digest()

# def hash_byte_string_blake2b(input_bytes):
#     blake2b_hash = hashlib.blake2b(digest_size=32)
#     blake2b_hash.update(input_bytes)
#     return blake2b_hash.digest()

# def xor_bytes(b1, b2):
#     if len(b1) != len(b2):
#         raise ValueError("Byte strings must be of the same length to XOR")
#     return bytes([x ^ y for x, y in zip(b1, b2)])

# def concatenate_byte_strings(*byte_strings):
#     return b''.join(byte_strings)

# def string_to_byte_string(input_string):
#     return input_string.encode(FORMAT)

# def setup(lam):
#     size = int(lam / 8)
#     ks = os.urandom(size)
#     S = {}
#     return S, ks

# def fast_update(key, S, ind, w, op):
#     tw = pseudorandom_permutation(key, hash_text_sha256(w))
#     stc = S[w]

#     kc_next = os.urandom(32)
#     if stc:
#         stc_next = pseudorandom_permutation(kc_next, stc.decode(FORMAT))
#     else:
#         stc_next = pseudorandom_permutation(kc_next, "init_state")

#     # c += 1
#     S[w] = stc_next

#     b_ind = string_to_byte_string(ind)
#     b_op = string_to_byte_string(str(op))

#     term1 = concatenate_byte_strings(b_ind, b_op, kc_next)
#     term2 = hash_byte_string_sha3_256(concatenate_byte_strings(tw, stc_next))

#     e = xor_bytes(term1, term2)
#     u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))

#     # Send u and e to server
#     client.send(u)
#     time.sleep(1)
#     client.send(e)

# S = {"crypto": b'initial_state_crypto', "encryption": b'initial_state_encryption'}
# T = {"file1.txt": b'encrypted_data_1', "file2.txt": b'encrypted_data_2'}

# key = os.urandom(32)
# ind = 'file1.txt'
# w = 'crypto'
# op = 0

# fast_update(key, S, ind, w, op)





# def fast_client_update(key, S, ind, w, op):
#     # Step 4: Calculate tw
#     tw = pseudorandom_function(key, hash_text_sha256(w)) # this is of size 32 bytes
    
#     # Step 5-6: Retrieve stc and initialize c
#     stc, c = S.get(w.encode(), default=None), 0

#     # Retrieve the pickled value from the database
#     pickled_value = S.get(w.encode(), default = pickle.dump(None,None))

#     stc, c = pickle.loads(pickled_value)
    
#     # Step 7-10: Generate a new state if stc is None
#     if stc is None:
#         stc = os.urandom(32)
#         c = 0

#     # Retrieve the pickled value from the database (using None as the default if the key doesn't exist)
#     pickled_value = S.get(w.encode(), default=None)

#     # Check if the value was found in the database
#     if pickled_value is not None:
#     # Deserialize the pickled value (it should be a tuple: (stc, c))
#         stc, c = pickle.loads(pickled_value)
#     else:
#     # If no value is found, initialize stc and c
#         stc = None
#         c = 0

#     # Step 7-10: Generate a new state if stc is None
#     if stc is None:
#         stc = os.urandom(32)  # Generate a random 32-byte value for stc
#         c = 0  # Initialize c to 0
    
#     # Step 9: Generate new key kc+1
#     kc_next = os.urandom(32)
    
#     # Step 10: Calculate new stc+1
#     stc_next = pseudorandom_permutation(kc_next, stc)

#     # since stc_next is bytes and c is an integer (since plyvel cant store multiple values for single key)
#     # used pickle to club stc_next and c+1 together
#     value = pickle.dumps((stc_next, c + 1))  # Serialize the tuple

#     # Store the serialized value
#     S.put(w.encode(), value)
    
#     # Step 11-12: Create e
#     # b_ind = string_to_byte_string(ind) # this byte string is of random length which I need to figure out
#     # b_op = bytes([op])  # Using 0 or 1 as op
#     term1 = concatenate_byte_strings(adjust_and_concatenate(ind, op), kc_next) # this will always be of size 48 bytes, op will be at the end, and the ind will be truncated or padded acc to size
#     term2 = hash_byte_string_sha384(concatenate_byte_strings(tw, stc_next)) # this will alwayys be of size 48 bytes
#     e = xor_bytes(term1, term2)
    
#     # Step 13: Calculate u
#     u = hash_byte_string_blake2b(concatenate_byte_strings(tw, stc_next))
    
#     # Step 14: Send u and e to server
#     client.send(u)
#     client.send(e)
#     # S.close()




    



# S, ks = fast_client_setup()
# ind1 = 'file1.txt'
# ind2 = 'file2.txt'
# w1 = 'crypto'
# w2 = 'graphical'
# op1 = 1  # Use 0 for delete, 1 for add
# op2 = 0

# for i in range(1, 5):  
#     if i % 2 == 0:  
#         fast_client_update(ks,S,ind1,w1,op1)
#     else:  
#         fast_client_update(ks,S,ind2,w2,op2)  

# print('Client - Done')  


# def start_client():
#     # Assuming server is running on the same machine, you can replace with server IP and port
#     # SERVER = 'localhost'
#     # PORT = 12345  # Ensure this matches the server's PORT

#     # Create a socket connection
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.connect((SERVER, PORT))
        
#         try:
#             while True:
#                 u_value = input("Enter u-value: ").encode('utf-8')
#                 e_value = input("Enter e-value: ").encode('utf-8')

#                 # Send u and e to the server
#                 client_socket.send(u_value)
#                 client_socket.send(e_value)
                
#                 # Optionally wait for a response from the server (if implemented)
#                 # response = client_socket.recv(1024)
#                 # print(f"Server response: {response.decode('utf-8')}")
                
#                 # Exit condition for the client (if needed)
#                 exit_condition = input("Do you want to send more data? (y/n): ").lower()
#                 if exit_condition != 'y':
#                     break
#         except Exception as e:
#             print(f"Error with the connection: {e}")
#         finally:
#             print("Client disconnected.")

# # Start the client
# start_client()

        









# fast_update(key, S, ind, w1, op)
# fast_update(key, S, ind, w2, op)
# print(S)

# def fast_client_search(key, S, w):
#     # Step 4: Calculate tw
#     tw = pseudorandom_permutation(key, string_to_byte_string(hash_text_sha256(w)))

#     # Step 5-6: Retrieve stc and initialize c
#     (stc, c) = S.get(w, (None, 0))

#     if not stc:
#         return 0
#     else:
#         # send tw, current state and c to server
#         client.send(tw)
#         time.sleep(1)

#         client.send(stc)
#         time.sleep(1)

#         client.send(c)
#         time.sleep(1)







