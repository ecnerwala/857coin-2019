package coin

import (
	"crypto/sha256"
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

const HashSize = sha256.Size
type Hash [HashSize]byte

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
	buf := (*big.Int)(g).Bytes()
	copy(b[GSize - len(buf):], buf)
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
