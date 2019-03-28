package main

import "math/big"
import "crypto/rand"
import "fmt"

func safePrime() *big.Int {
	for {
		q, err := rand.Prime(rand.Reader, 511)
		if err != nil {
			panic(err)
		}
		p := new(big.Int).Add(q, q)
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(3) {
			return p
		}
	}
}

func main() {
	p1 := safePrime()
	p2 := safePrime()
	N := new(big.Int).Mul(p1, p2)
	fmt.Println(N)
}
