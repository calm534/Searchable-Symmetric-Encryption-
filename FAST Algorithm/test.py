# import plyvel
# import pickle
# import hashlib

# # Utility functions
# def hash_text_sha256(text):
#     return hashlib.sha256(text.encode()).digest()

# def pseudorandom_function(key, data):
#     # Simulate a pseudorandom function using HMAC-SHA256
#     import hmac
#     return hmac.new(key.encode(), data, hashlib.sha256).digest()

# # Create a test plyvel database
# db = plyvel.DB('test_db', create_if_missing=True)

# # Insert test data into the database
# test_data = {
#     'crypto': (b'state_crypto', 10),
#     'graphical': (b'state_graphical', 20),
# }
# for keyword, (stc, c) in test_data.items():
#     db.put(keyword.encode(), pickle.dumps((stc, c)))

# # Test fast_client_search
# key = "my_secret_key"

# def fast_client_search(key, S, w):
#     tw = pseudorandom_function(key, hash_text_sha256(w))  # This is of size 32 bytes
    
#     pickled_value = S.get(w.encode(), default=None)

#     if pickled_value is not None:
#         stc, c = pickle.loads(pickled_value)
#     else:
#         stc = None
#         c = 0

#     # Step 7-10: if stc is None, return 0
#     if stc is None:
#         return b"exit", b"exit", 0 

#     return tw, stc, c

# # Test cases
# test_keywords = ['crypto', 'graphical', 'nonexistent']
# for w in test_keywords:
#     tw, stc, c = fast_client_search(key, db, w)
#     print(f"Keyword: {w}")
#     print(f"  Search Token (tw): {tw}")
#     print(f"  State (stc): {stc}")
#     print(f"  Counter (c): {c}")
#     print()

# # Close the database
# db.close()

# integer = 4
# integer.from_bytes
# import plyvel


# db = plyvel.DB('test_db', create_if_missing=True)
# db.put(b'key-1', b'value-1')
# db.put(b'key-5', b'value-5')
# db.put(b'key-3', b'value-3')
# db.put(b'key-2', b'value-2')
# db.put(b'key-4', b'value-4')

# print('Normal iterator:')
# for key, value in db:
#     print(key)
#     print(value)

# it = db.iterator(include_value=False)
# print(next(it))
# print("Raw iterator results:")

# import plyvel

# def insert_with_linked_list(db, key, value):
#     """
#     Inserts a key-value pair while maintaining a linked list structure.
#     """
#     last_key = db.get(b'__last_inserted_key__')
#     db.put(key, value)
#     if last_key:
#         db.put(key + b'__prev', last_key)  # Store the previous key link
#     db.put(b'__last_inserted_key__', key)  # Update last inserted key

# def print_in_insert_order(db):
#     """
#     Prints key-value pairs in insertion order using the linked list approach.
#     """
#     key = db.get(b'__last_inserted_key__')
#     while key:
#         value = db.get(key)
#         print(key.decode(), "->", value.decode())
#         key = db.get(key + b'__prev')  # Move to the previous key

# # Example Usage
# db = plyvel.DB('T', create_if_missing=True)
# insert_with_linked_list(db, b'key1', b'value1')
# insert_with_linked_list(db, b'key4', b'value4')
# insert_with_linked_list(db, b'key3', b'value3')

# print_in_insert_order(db)

# db.close()

# import plyvel

# # Create or open a Plyvel (LevelDB) database
# db_path = "example_db"
# db = plyvel.DB(db_path, create_if_missing=True)

# # Insert some key-value pairs
# db.put(b'key4', b'value1')
# db.put(b'key7', b'value2')
# db.put(b'key3', b'value3')

# # Using raw_iterator() to iterate over the database
# print("Database Contents (Using raw_iterator()):")

# it = db.raw_iterator()  # Get a raw iterator
# it.seek_to_first()  # Move to the first key-value pair

# while it.valid():  # Check if iterator is valid
#     print(f"Key: {it.key().decode()} -> Value: {it.value().decode()}")
#     it.next()  # Move to the next item

# # Close the database
# db.close()

# import plyvel

# # Create or open a Plyvel (LevelDB) database
# # db_path = "example_db"
# db = plyvel.DB('test', create_if_missing=True)

# # Insert some key-value pairs, tracking insertion order manually
# insertion_order = []  # List to track the insertion order
# db.put(b'key3', b'value3')
# insertion_order.append(b'key3')
# db.put(b'key1', b'value1')
# insertion_order.append(b'key1')
# db.put(b'key7', b'value7')
# insertion_order.append(b'key7')

# # Print the database contents in insertion order
# print("Database Contents (In Insertion Order):")
# for key in insertion_order:
#     value = db.get(key)
#     print(f"Key: {key} -> Value: {value}")

# # Close the database
# db.close()

# import plyvel

# # Open or create a LevelDB database
# db = plyvel.DB('test_db/', create_if_missing=True)

# # List of key-value pairs to store
# pairs = [
#     (b'u3', b'e3'),
#     (b'u2', b'e2'),
#     (b'u1', b'e1'),
#     (b'u4', b'e4'),
# ]

# # Insert the key-value pairs in reverse order
# for u, e in reversed(pairs):
#     db.put(u, e)

# # Iterate over the database and print the key-value pairs
# for u, e in db:
#     print(f"Key: {u.decode()}, Value: {e.decode()}")

# # Close the database
# db.close()

import plyvel

# # Open or create a LevelDB database
# db = plyvel.DB('test_db/', create_if_missing=True)

# # List of key-value pairs to store
# pairs = [
#     (b'u3', b'e3'),
#     (b'u2', b'e2'),
#     (b'u1', b'e1'),
#     (b'u4', b'e4'),
# ]

# # Insert the key-value pairs with a custom order key
# for idx, (u, e) in enumerate(pairs):
#     # Use an incrementing index as part of the key to preserve order
#     ordered_key = f"{idx:04d}_{u.decode()}".encode()  # e.g., b'0000_u3', b'0001_u2', etc.
#     db.put(ordered_key, e)

# # Retrieve and print the key-value pairs in insertion order
# for key, value in db:
#     # Decode the key to extract the original key
#     original_key = key.split(b'_', 1)[1]  # Split on the first underscore
#     print(f"Key: {original_key.decode()}, Value: {value.decode()}")

# # Close the database
# db.close()

# import plyvel

# # Open the plyvel database (replace with your actual database path)
# # T = plyvel.DB('path_to_your_database')

# db = plyvel.DB('test_db', create_if_missing=True)
# db.put(b'key-1', b'value-1')
# db.put(b'key-5', b'value-5')
# db.put(b'key-3', b'value-3')
# db.put(b'key-2', b'value-2')
# db.put(b'key-4', b'value-4')

# # Use the iterator to print the key-value pairs as they are
# for key, value in db.iterator():
#     print(f"Key: {key}, Value: {value}")

# import bsddb

# # Open the Berkeley DB
# db = bsddb.btopen('path_to_your_database', 'r')

# # Print the key-value pairs
# for key, value in db.items():
#     print(f"Key: {key}, Value: {value}")



