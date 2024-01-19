# UNAUDITED: DO NOT USE IN PRODUCTION

from ECC import (
    bytes_to_int,
    privtopub,
    multiply, 
    add,
    N, 
    G,
)
from py_ecc.typing import PlainPoint2D
from random import randint
from sha3 import keccak_256

def int_to_bytes(integer) -> int:
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big')


# do not use, just for testing
def randomPrivateKey() -> int:
    return randint(0, N)


# ACTIONS OF THE PAYER
def generate_stealth_address_from_stealth_meta_address(stealth_meta_address: PlainPoint2D) -> (PlainPoint2D, PlainPoint2D, int):
    # generate ephemeral key pair
    ephemeral_priv_key = randomPrivateKey()
    ephemeral_public_key = privtopub(int_to_bytes(ephemeral_priv_key))
    
    # calculate shared secret
    shared_secret = multiply(stealth_meta_address, ephemeral_priv_key)
    
    # calculate the stealth meta address
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    
    view_tag = Q[0] # most significant byte
    stealth_public_key = add(multiply(G, bytes_to_int(Q)), stealth_meta_address)
    
    return (stealth_public_key, ephemeral_public_key, view_tag)



# ACTIONS OF USERS THAT HAVE BROADCASTED THEIR STEALTH META ADDRESS AND SCANNING TO DETECT IF/WHEN THEY RECEIVE A PAYMENT
def get_stealth_address_private_key(stealth_public_key: PlainPoint2D, ephemeral_public_key: PlainPoint2D, view_tag: int) -> int:
    # calculate shared secret
    shared_secret = multiply(ephemeral_public_key, global_stealth_meta_priv_key)
    
    # calculate the stealth meta address
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    # compare view tags
    if Q[0] != view_tag:
        return 0
    
    # confirm it's the same address
    calc_stealth_public_key = add(multiply(G, bytes_to_int(Q)), global_stealth_meta_address)
    # compare stealth public keys
    if calc_stealth_public_key != stealth_public_key:
        return 0
    
    # get the priv key
    stealth_priv_key = (bytes_to_int(Q) + global_stealth_meta_priv_key) % N
    
    # is always be true, sanity check
    assert stealth_public_key == multiply(G, stealth_priv_key)
    
    # priv key
    return stealth_priv_key





global_stealth_meta_priv_key = randomPrivateKey()
global_stealth_meta_address = privtopub(int_to_bytes(global_stealth_meta_priv_key))

(global_stealth_public_key, global_ephemeral_public_key, global_view_tag) = generate_stealth_address_from_stealth_meta_address(global_stealth_meta_address)
print("global_stealth_public_key:", global_stealth_public_key, "\nglobal_ephemeral_public_key:", global_ephemeral_public_key, "\nglobal_view_tag:", global_view_tag, "\n")
print("Stealth address private key:", get_stealth_address_private_key(global_stealth_public_key, global_ephemeral_public_key, global_view_tag))