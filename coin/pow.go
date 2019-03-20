package coin

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type Header struct {
	ParentID   Hash                  `json:"parentid"`
	MerkleRoot Hash                  `json:"root"`
	Difficulty uint64                `json:"difficulty"`
	Timestamp  int64                 `json:"timestamp"`
	Nonces     [2]uint64             `json:"nonces"`
	Proofs     [2]*G                  `json:"proofs"`
	Version    uint8                 `json:"version"`
}

const MAX_BLOCK_SIZE = 1000

type Block string

func (h *Header) Sum() Hash {
	b := make([]byte, HashSize+HashSize+8+8+8+8+GSize+GSize+1)
	offset := 0

	offset += copy(b[offset:], h.ParentID[:])
	offset += copy(b[offset:], h.MerkleRoot[:])
	binary.BigEndian.PutUint64(b[offset:], h.Difficulty)
	offset += 8
	binary.BigEndian.PutUint64(b[offset:], uint64(h.Timestamp))
	offset += 8
	for _, n := range h.Nonces {
		binary.BigEndian.PutUint64(b[offset:], n)
		offset += 8
	}
	for _, g := range h.Proofs {
		buf := g.Bytes()
		offset += copy(b[offset:], buf[:])
	}

	b[offset] = h.Version
	offset += 1

	return sha256.Sum256(b)
}

func computeTarget(diff uint64) *big.Int {
	return new(big.Int).Div(groupOrder, new(big.Int).SetUint64(diff))
}

func (h *Header) computeG() *G {
	b := make([]byte, HashSize+HashSize+8+8+8+1+1)
	offset := 0

	offset += copy(b[offset:], h.ParentID[:])
	offset += copy(b[offset:], h.MerkleRoot[:])
	binary.BigEndian.PutUint64(b[offset:], h.Difficulty)
	offset += 8
	binary.BigEndian.PutUint64(b[offset:], uint64(h.Timestamp))
	offset += 8
	binary.BigEndian.PutUint64(b[offset:], h.Nonces[0])
	offset += 8

	b[offset] = h.Version
	offset += 1

	buf := [GSize]byte{}
	for i := 0; i < GSize / HashSize; i++ {
		b[offset] = byte(i)
		hash := sha256.Sum256(b)
		copy(buf[i*HashSize:(i+1)*HashSize], hash[:])
	}
	return new(G).SetBytes(buf).Cannonize()
}

func computeL(t uint64, g, gt *G) *big.Int {
	b := make([]byte, 8+GSize+GSize+8)
	offset := 0

	binary.BigEndian.PutUint64(b[offset:], t)
	offset += 8

	gb := g.Bytes()
	offset += copy(b[offset:], gb[:])

	gtb := gt.Bytes()
	offset += copy(b[offset:], gtb[:])

	l := new(big.Int)
	for i := 0; true; i++ {
		binary.BigEndian.PutUint64(b[offset:], uint64(i))

		hash := sha256.Sum256(b)
		l.SetBytes(hash[:])
		if l.ProbablyPrime(3) {
			break
		}
	}

	return l
}

func (h *Header) Valid(b Block) error {
	if len(b) > MAX_BLOCK_SIZE {
		return ErrBlockSize
	}

	// Header first validation
	if err := h.validPoW(); err != nil {
		return err
	}

	// Ensure header commits block
	if err := h.validMerkleTree(b); err != nil {
		return err
	}

	return nil
}

func (h *Header) validPoW() error {
	t := h.Nonces[1]
	if t <= h.Difficulty {
		return ErrInvalidPoW
	}

	gt := h.Proofs[0]
	if !gt.Valid() {
		return ErrInvalidPoW
	}
	pi := h.Proofs[1]
	if !pi.Valid() {
		return ErrInvalidPoW
	}

	target := computeTarget(h.Difficulty)
	if target.Cmp((*big.Int)(gt)) < 0 {
		return ErrInvalidPoW
	}

	g := h.computeG()

	l := computeL(t, g, gt)

	r := new(big.Int).Exp(bigTwo, new(big.Int).SetUint64(t), l)

	test := new(G).Mul(new(G).Exp(pi, l), new(G).Exp(g, r))
	if !test.Equals(gt) {
		return ErrInvalidPoW
	}

	return nil
}

func (h *Header) validMerkleTree(b Block) error {
	if h.Version == 0 {
		if h.MerkleRoot == computeMerkleTreeV0(b) {
			return nil
		}
	}

	return ErrUnkownVersion
}

func computeMerkleTreeV0(b Block) Hash {
	return sha256.Sum256([]byte(b))
}

func (h *Header) MineBlock(b Block) {
	h.MerkleRoot = computeMerkleTreeV0(b)

	h.Nonces[0] = 0


	g := h.computeG()
	gt := new(G).Set(g)
	t := uint64(0)
	for t <= h.Difficulty {
		gt.Mul(gt, gt)
		t ++
	}

	target := computeTarget(h.Difficulty)
	for target.Cmp((*big.Int)(gt)) < 0 {
		gt.Mul(gt, gt)
		t ++
	}

	l := computeL(t, g, gt)
	q := new(big.Int).Exp(bigTwo, new(big.Int).SetUint64(t), nil)
	q.Div(q, l)
	pi := new(G).Exp(g, q)

	h.Nonces[1] = t
	h.Proofs[0] = new(G).Set(gt)
	h.Proofs[1] = new(G).Set(pi)
}
