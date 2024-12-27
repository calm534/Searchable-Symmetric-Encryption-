import socket
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

HEADER = 64
PORT = 5050
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

import os
from collections import defaultdict



# import hashlib
# import hmac



# Hash functions modeled as random oracles
def H1(data):
    return hashlib.sha256(data).hexdigest()

def H2(data):
    return hashlib.sha256(data).digest()

def pseudorandom_function(key, message):
    # pseudo random funciton (prf) --  cryptographic function that, given an input and a secret key, produces
    # output that is indistinguishable from a truly random function to anyone without knowledge of the secret key.
    # this execution is using hmac and sha256
    # A pseudorandom Function cant be reversed, by any chance we can never figure out the encoded message

    return hmac.new(key, message.encode(), hashlib.sha256).digest()

def concatenate_byte_strings(*byte_strings):
    return b''.join(byte_strings)

def concatenate_integers(a: int, b: int) -> int:
    """
    Concatenates two integers by treating them as strings and returning the result as an integer.

    Args:
        a (int): The first integer.
        b (int): The second integer.

    Returns:
        int: The concatenated result as an integer.
    """
    # Convert integers to strings, concatenate, and convert back to integer
    concatenated = int(str(a) + str(b))
    return concatenated

def string_to_byte_string(input_string):
    return input_string.encode(FORMAT)

def xor_bytes(b1, b2):
    # Adjust to handle different length byte strings
    max_len = max(len(b1), len(b2))
    b1 = b1.ljust(max_len, b'\x00')
    b2 = b2.ljust(max_len, b'\x00')
    return bytes([x ^ y for x, y in zip(b1, b2)])

def client_setup():
    # Generate random secret keys kt and kd
    kt = os.urandom(32)  
    kd = os.urandom(32)

    # Initialize the maps
    W = defaultdict(lambda: (None, -1))  # W initialized with (verw, cw) = (None, -1)
    # T = {}  # T is an empty map
    # D = {}  # D is an empty map

    # Return the encrypted database (EDB) and stc
    # EDB = (D, T)
    stc = (kt, kd, W)

    # client.send(D)
    # client.send(T)
    
    return stc

# Update function
def client_update(op, w, ind, stc):
    """
    Performs an update operation (add/del) on the keyword-document pair (w, ind).
    
    :param op: Operation type (add or del). 0 for add, 1 for delete.
    :param w: Keyword (string).
    :param ind: Document identifier (string).
    :param stc: Client state, contains keys kt, kd and map W.
    :param T: Server state, stores encrypted entries (label, e).
    """
    # Extract the state components
    kt, kd, W = stc

    # Get version and counter for

        # the keyword w
    (verw, cw) = W.get(w, (0, -1))

    # Update the counter and version if it's a new keyword
    if (verw, cw) == (None, -1):
        verw, cw = 0, -1
    
    # Increment the counter
    cw += 1

    # converting w, cw and verw to byte strings for concatenation
    bw = string_to_byte_string(w)   
    b_verw = string_to_byte_string(str(verw)) 
    bcw = string_to_byte_string(str(cw))
    b_ind = string_to_byte_string(ind)

    # Compute the keyword key kw using PRF
    kw = pseudorandom_function(kt, concatenate_byte_strings(bw, b_verw).decode('utf-8'))

    # Compute label and pad using the hash functions
    label = H1(concatenate_byte_strings(kw, bcw))
    pad = H2(concatenate_byte_strings(kw, bcw))

    # Set the value of b (0 for add, 1 for delete)
    b = 0 if op == "add" else 1
    b = string_to_byte_string(str(b))

    # Compute encrypted value e
    b_ind = concatenate_byte_strings(b,b_ind)  # Concatenate b and ind

    # forming e, by xoring b_ind and pad
    e = xor_bytes(b_ind, pad)  # XOR b||ind with pad

    # Update the W map with the new version and counter
    W[w] = (verw, cw)

    # Send (label, e) to the server (simulated by adding to T)
    client.send(string_to_byte_string(label))
    client.send(e)



def client_search(w, stc, D):
    """
    Client-side search function.

    :param w: Keyword to search for (string).
    :param stc: Client state, containing keys kt, kd, and map W.
    :param D: Client result set, storing the result of previous searches for keywords.
    :return: labelw, kw, cw (query components) and updated client state `stc`.
    """
    # Extract client state components
    kt, kd, W = stc

    # Check if keyword w exists in W
    if w not in W:
        return 0  # Return 0 if verw or cw does not exist

    # Retrieve verw and cw for the keyword w
    verw, cw = W[w]  # No default values; strictly use existing data

    # Compute label for keyword w
    labelw = pseudorandom_function(kd,w)

    # converting w, cw and verw to byte strings for concatenation
    bw = string_to_byte_string(w)   
    b_verw = string_to_byte_string(verw)

    if cw != -1:
        # Compute the keyword key kw using PRF
        kw = pseudorandom_function(kt, concatenate_byte_strings(bw, b_verw))
        verw = verw + 1
        cw = -1

        # Update version if `kw` is revealed during this search
        W[w] = (verw + 1, cw)  # Update verw and cw in the client state
    else:
        kw = 0

    client.send(labelw)
    client.send(kw)
    client.send(cw)



# Example use

# Setting up the client
stc = client_setup()
D = {}
# Add keyword-document pairs
# client_update("add", "apple", "doc1", stc)

# client_update("add", "banana", "doc2", stc)

client_update('del', "apple", "doc3", stc)
client_update('add', "apple", "doc3", stc)
# client_update("add", "sahil", "doc4", stc)
# client_update("del", "apple", "doc3", stc)
# client_search("apple", stc, D)


