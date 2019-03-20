#!/usr/bin/env python3
import json
from hashlib import sha256 as H
from Crypto.Cipher import AES
from Crypto.Random import random
import time
from struct import pack, unpack
import requests

#NODE_URL = "http://6857coin.csail.mit.edu"
NODE_URL = "http://localhost:8080"

"""
    This is a bare-bones miner compatible with 6857coin, minus the final proof of
    work check. We have left lots of opportunities for optimization. Partial
    credit will be awarded for successfully mining any block that appends to
    a tree rooted at the genesis block. Full credit will be awarded for mining
    a block that adds to the main chain. Note that the faster you solve the proof
    of work, the better your chances are of landing in the main chain.

    Feel free to modify this code in any way, or reimplement it in a different
    language or on specialized hardware.

    Good luck!
"""


def solve_block(b):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    d = b["difficulty"]
    while True:
        b["nonces"] = [rand_nonce() for i in range(3)]
        #   Compute Ai, Aj, Bi, Bj
        ciphers = compute_ciphers(b)
        #   Parse the ciphers as big-endian unsigned integers
        Ai, Aj, Bi, Bj = [unpack_uint128(cipher) for cipher in ciphers]
        #   TODO: Verify PoW
        MSK = (1 << 128) - 1
        dist = bin(((Ai + Bj) & MSK) ^ ((Aj + Bi) & MSK)).count('1')
        if dist <= 128 - d:
            break


def main():
    """
    Repeatedly request next block parameters from the server, then solve a block
    containing our team name.

    We will construct a block dictionary and pass this around to solving and
    submission functions.
    """
    # TODO: Change me to your team members!
    block_contents = "staff"
    while True:
        #   Next block's parent, version, difficulty
        next_header = get_next()
        #   Construct a block with our name in the contents that appends to the
        #   head of the main chain
        new_block = make_block(next_header, block_contents)
        #   Solve the POW
        print("Solving block...")
        print(new_block)
        solve_block(new_block)
        #   Send to the server
        add_block(new_block, block_contents)


def get_next():
    """
       Parse JSON of the next block info
           difficulty      uint64
           parentid        HexString
           version         single byte
    """
    return requests.get(NODE_URL + "/next").json()


def add_block(h, contents):
    """
       Send JSON of solved block to server.
       Note that the header and block contents are separated.
            header:
                difficulty      uint64
                parentid        HexString
                root            HexString
                timestampe      uint64
                version         single byte
            block:          string
    """
    add_block_request = {"header": h, "block": contents}
    print("Sending block to server...")
    print(json.dumps(add_block_request))
    r = requests.post(NODE_URL + "/add", json=add_block_request)
    print(r)
    if r.ok:
        print("Successfully added block:")
        print(r.json())


def hash_block_to_hex(b):
    """
    Computes the hex-encoded hash of a block header. First builds an array of
    bytes with the correct endianness and length for each arguments. Then hashes
    the concatenation of these bytes and encodes to hexidecimal.

    Not used for mining since it includes all nonces, but serves as the unique
    identifier for a block when querying the explorer.
    """
    packed_data = bytearray()
    packed_data.extend(bytes.fromhex(b["parentid"]))
    packed_data.extend(bytes.fromhex(b["root"]))
    packed_data.extend(pack('>Q', b["difficulty"]))
    packed_data.extend(pack('>Q', b["timestamp"]))
    #   Bigendian 64bit unsigned
    for n in b["nonces"]:
        #   Bigendian 64bit unsigned
        packed_data.extend(pack('>Q', n))
    packed_data.extend(pack('>b', b["version"]))
    if len(packed_data) != 105:
        print("invalid length of packed data")
    h = H()
    h.update(packed_data)
    return h.hexdigest()


def compute_ciphers(b):
    """
    Computes the ciphers Ai, Aj, Bi, Bj of a block header.
    """

    packed_data = bytearray()
    packed_data.extend(bytes.fromhex(b["parentid"]))
    packed_data.extend(bytes.fromhex(b["root"]))
    packed_data.extend(pack('>Q', b["difficulty"]))
    packed_data.extend(pack('>Q', b["timestamp"]))
    packed_data.extend(pack('>Q', b["nonces"][0]))
    packed_data.extend(pack('>b', b["version"]))
    if len(packed_data) != 89:
        print("invalid length of packed data")
    h = H()
    h.update(packed_data)
    seed = h.digest()

    if len(seed) != 32:
        print("invalid length of packed data")
    h = H()
    h.update(seed)
    seed2 = h.digest()

    A = AES.new(seed)
    B = AES.new(seed2)

    i = pack('>QQ', 0, b["nonces"][1])
    j = pack('>QQ', 0, b["nonces"][2])

    Ai = A.encrypt(i)
    Aj = A.encrypt(j)
    Bi = B.encrypt(i)
    Bj = B.encrypt(j)

    return Ai, Aj, Bi, Bj


def unpack_uint128(x):
    h, l = unpack('>QQ', x)
    return (h << 64) + l


def hash_to_hex(data):
    """Returns the hex-encoded hash of a byte string."""
    h = H()
    h.update(data)
    return h.hexdigest()


def make_block(next_info, contents):
    """
    Constructs a block from /next header information `next_info` and sepcified
    contents.
    """
    block = {
        "version": next_info["version"],
        #   for now, root is hash of block contents (team name)
        "root": hash_to_hex(contents.encode('ascii')),
        "parentid": next_info["parentid"],
        #   nanoseconds since unix epoch
        "timestamp": int(time.time()*1000*1000*1000),
        "difficulty": next_info["difficulty"]
    }
    return block


def rand_nonce():
    """
    Returns a random uint64
    """
    return random.getrandbits(64)


if __name__ == "__main__":
    main()
