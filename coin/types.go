package coin

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var (
	bigOne = new(big.Int).SetUint64(1)
	bigTwo = new(big.Int).SetUint64(2)
)

var (
	ErrUnkownVersion    = errors.New("unknown version")
	ErrInvalidPoW       = errors.New("invalid PoW")
	ErrInvalidNonceHash = errors.New("Hash(n | data) cannt be 0")
	ErrBlockSize        = errors.New("block is too large")
)

type Hash [sha256.Size]byte

func NewHash(hexstr string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(hexstr)
	if err != nil {
		return h, err
	}
	if len(b) != sha256.Size {
		return h, fmt.Errorf("short hash value")
	}
	copy(h[:], b)

	return h, nil
}

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// TODO speed up
func (h Hash) MarshalJSON() ([]byte, error) {
	return []byte("\"" + h.String() + "\""), nil
}

func (h *Hash) UnmarshalJSON(b []byte) (err error) {
	if b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("expecting string for hash value")
	}
	*h, err = NewHash(string(b[1 : len(b)-1]))

	return err
}

type G big.Int

const GSize = 1024 / 8
var modulus, _ = new(big.Int).SetString("32420940066761377073822203008568487340520716029590695882785276948946647098540634852251945955581505518333400893165659768177465251805732877874332490491041935323641879090718180983335475999954043569989824159397343386039323761999256232745942994005221413223409039438367895101615370225200842862162707097865077364897", 10)
var groupOrder = new(big.Int).Div(modulus, bigTwo)

func (g *G) String() string {
	return (*big.Int)(g).String()
}

func (z *G) Set(g *G) *G {
	(*big.Int)(z).Set((*big.Int)(g))
	return z
}

func (g *G) Valid() bool {
	n := (*big.Int)(g)
	if !(n.Sign() > 0) {
		return false
	}
	if !(n.Cmp(modulus) < 0) {
		return false
	}
	return true
}

func (g *G) Cannonize() *G {
	n := (*big.Int)(g)
	n.Mod(n, modulus)
	o := new(big.Int).Sub(modulus, n)
	if n.Cmp(o) > 0 {
		n.Set(o)
	}
	return g
}

func (z *G) Mul(x, y *G) *G {
	n := (*big.Int)(z)
	n.Mul((*big.Int)(x), (*big.Int)(y))
	z.Cannonize()
	return z
}

func (z *G) Exp(g *G, p *big.Int) *G {
	n := (*big.Int)(z)
	n.Exp((*big.Int)(g), p, modulus)
	z.Cannonize()
	return z
}

func (z *G) Equals(g *G) bool {
	return (*big.Int)(z).Cmp((*big.Int)(g)) == 0
}

func (g *G) Bytes() (b [GSize]byte) {
	copy(b[:], (*big.Int)(g).Bytes())
	return
}

func (g *G) SetBytes(b [GSize]byte) *G {
	(*big.Int)(g).SetBytes(b[:])
	return g
}

func (g *G) MarshalJSON() ([]byte, error) {
	return (*big.Int)(g).MarshalJSON()
}

func (g *G) UnmarshalJSON(b []byte) error {
	return (*big.Int)(g).UnmarshalJSON(b)
}

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
	b := make([]byte, sha256.Size+sha256.Size+8+8+8+8+GSize+GSize+1)
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
	b := make([]byte, sha256.Size+sha256.Size+8+8+8+1+1)
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
	for i := 0; i < GSize / sha256.Size; i++ {
		b[offset] = byte(i)
		hash := sha256.Sum256(b)
		copy(buf[i*sha256.Size:(i+1)*sha256.Size], hash[:])
	}
	return new(G).SetBytes(buf).Cannonize()
}

func computeLAndR(t uint64, g, gt *G) (*big.Int, *big.Int) {
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

	r := new(big.Int).Exp(bigTwo, new(big.Int).SetUint64(t), l)

	return l, r
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

	l, r := computeLAndR(t, g, gt)

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

	l, _ := computeLAndR(t, g, gt)
	q := new(big.Int).Exp(bigTwo, new(big.Int).SetUint64(t), nil)
	q.Div(q, l)
	pi := new(G).Exp(g, q)

	h.Nonces[1] = t
	h.Proofs[0] = new(G).Set(gt)
	h.Proofs[1] = new(G).Set(pi)
}
