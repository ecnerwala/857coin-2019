#!/usr/bin/env python3
import json
from hashlib import sha256 as H
import time
from struct import pack, unpack
import requests
from random import randint

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


modulus = 32420940066761377073822203008568487340520716029590695882785276948946647098540634852251945955581505518333400893165659768177465251805732877874332490491041935323641879090718180983335475999954043569989824159397343386039323761999256232745942994005221413223409039438367895101615370225200842862162707097865077364897


def solve_block(b):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    d = b["difficulty"]
    b["nonces"][0] = 0  # arbitrary

    g = compute_g(b)
    target = modulus // 2 // d

    gt = g
    t = 0

    while not (t > d and gt <= target):
        gt = gt * gt % modulus
        gt = min(gt, modulus - gt)
        t += 1

    l = compute_proof_challenge(t, g, gt)
    q = (1 << t) // l

    pi = pow(g, q, modulus)
    pi = min(pi, modulus - pi)

    b["nonces"][1] = t
    b["proofs"] = [gt, pi]


def compute_g(b):
    """
    Computes the starting group element g
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

    g_bytes = bytearray()
    for i in range(4):
        h = H()
        h.update(packed_data + pack('>b', i))
        g_bytes += h.digest()

    g = int.from_bytes(g_bytes, byteorder='big')
    g %= modulus
    g = min(g, modulus - g)
    return g


def probably_prime(p):
    """
    Checks if an element is probably prime.

    Uses 10 iterations of the Miller-Rabin primality test
    """
    q = p-1
    s = 0
    while q & 1 == 0:
        q >>= 1
        s += 1

    for _ in range(10):
        a = pow(randint(2, p-2), q, p)
        if a == 1 or a == p-1:
            continue

        for _ in range(s-1):
            a = a * a % p
            if a == 1:
                return False
            elif a == p-1:
                break
        else:
            return False
    return True


def compute_proof_challenge(t, g, gt):
    """
    Compute the proof challenge prime l given t, g, and g^{2^t}
    """

    packed_data = bytearray()
    packed_data.extend(pack('>Q', t))
    packed_data.extend(g.to_bytes(128, byteorder='big'))
    packed_data.extend(gt.to_bytes(128, byteorder='big'))

    i = 0
    while True:
        h = H()
        h.update(packed_data + pack(">Q", i))
        l = int.from_bytes(h.digest(), byteorder='big')
        if probably_prime(l):
            break
        i += 1

    return l


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
        print()


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


def make_block(next_info, contents):
    """
    Constructs a block from /next header information `next_info` and sepcified
    contents.
    """
    block = {
        "version": next_info["version"],
        #   for now, root is hash of block contents (team name)
        "root": hash_data_to_hex(contents.encode('ascii')),
        "parentid": next_info["parentid"],
        #   nanoseconds since unix epoch
        "timestamp": int(time.time()*1000*1000*1000),
        "difficulty": next_info["difficulty"],
        "nonces": [0, 0],
        "proofs": [0, 0],
    }
    return block


def hash_data_to_hex(data):
    """Returns the hex-encoded hash of a byte string."""
    h = H()
    h.update(data)
    return h.hexdigest()


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
    for n in b["proofs"]:
        packed_data.extend(n.to_bytes(128, byteorder='big'))
    packed_data.extend(pack('>b', b["version"]))
    if len(packed_data) != 353:
        print("invalid length of packed data")
    h = H()
    h.update(packed_data)
    return h.hexdigest()


if __name__ == "__main__":
    main()
