package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ecnerwala/857coin-2019/coin"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type (
	exploreBlock struct {
		ID              coin.Hash   `json:"id"`
		Header          coin.Header `json:"header"`
		Block           coin.Block  `json:"block"`
		BlockHeight     uint64      `json:"blockheight"`
		IsMainChain     bool        `json:"ismainchain"`
		EverMainChain   bool        `json:"evermainchain"`
		TotalDifficulty uint64      `json:"totaldiff"`
		NextDifficulty  uint64      `json:"nextdiff"`
		Timestamp       time.Time   `json:"timestamp"`
	}

	compositeBlock struct {
		Header coin.Header `json:"header"`
		Block  coin.Block  `json:"block"`
	}
)

func newExploreBlock(pheader *processedHeader, b coin.Block) *exploreBlock {
	return &exploreBlock{
		ID:              pheader.Header.Sum(),
		Header:          pheader.Header,
		Block:           b,
		BlockHeight:     pheader.BlockHeight,
		IsMainChain:     pheader.IsMainChain,
		EverMainChain:   pheader.EverMainChain,
		TotalDifficulty: pheader.TotalDifficulty,
		NextDifficulty:  pheader.NextDifficulty,
		Timestamp:       time.Unix(0, pheader.Header.Timestamp),
	}
}

func addHandler(w http.ResponseWriter, r *http.Request) {
	req := new(compositeBlock)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		httpError(w, http.StatusBadRequest, "error parsing block json: %s", err)
		return
	}

	ph, err := bchain.AddBlock(req.Header, req.Block)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to add block: %s", err)
		return
	}

	fullBlock := newExploreBlock(ph, req.Block)

	j, err := json.MarshalIndent(fullBlock, "", "  ")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding error: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func nextHandler(w http.ResponseWriter, r *http.Request) {
	var head *processedHeader
	if r.URL.Path == "" {
		bchain.Lock()
		head = &bchain.head
		bchain.Unlock()
	} else {
		hsh, err := coin.NewHash(r.URL.Path)
		if err != nil {
			httpError(w, http.StatusBadRequest, "error reading hash: %s", err)
			return
		}
		bchain.Lock()
		head, err = bchain.getHeader(hsh)
		if err != nil {
			bchain.Unlock()
			httpError(w, http.StatusNotFound, "header not found: %x", hsh[:])
			return
		}
		bchain.Unlock()
	}

	nextHeader := coin.Header{
		ParentID:   head.Header.Sum(),
		Difficulty: head.NextDifficulty,
		Version:    0x00,
	}

	j, err := json.MarshalIndent(nextHeader, "", "  ")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding error: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func headHandler(w http.ResponseWriter, r *http.Request) {
	bchain.Lock()
	head := bchain.head
	bchain.Unlock()

	j, err := json.MarshalIndent(head.Header, "", "  ")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding error: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	bchain.Lock()

	matches := make(map[coin.Hash]coin.Block)
	iter := bchain.db.NewIterator(util.BytesPrefix([]byte(BlockBucket)), nil)
	for iter.Next() {
		contents := string(iter.Value())
		if !strings.Contains(contents, r.URL.Path) {
			continue
		}

		hex := hex.EncodeToString(iter.Key()[6:])
		hash, err := coin.NewHash(hex)
		if err != nil {
			bchain.Unlock()
			httpError(w, http.StatusInternalServerError, "failed to make hash: %s", err)
			return
		}

		matches[hash] = coin.Block(contents)
	}

	blocks := make([]exploreBlock, len(matches))
	i := 0
	for id, b := range matches {
		pheader, err := bchain.getHeader(id)
		if err != nil {
			bchain.Unlock()
			httpError(w, http.StatusInternalServerError, "failed to load block header: %s", err)
			return
		}

		blocks[i] = *newExploreBlock(pheader, b)
		i++
	}
	bchain.Unlock()

	j, err := json.MarshalIndent(blocks, "", "  ")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding err: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func blockHandler(w http.ResponseWriter, r *http.Request) {
	h, err := coin.NewHash(r.URL.Path)
	if err != nil {
		httpError(w, http.StatusBadRequest, "error reading hash: %s", err)
		return
	}

	// Lock and load header, then block
	bchain.Lock()
	ph, err := bchain.getHeader(h)
	if err != nil {
		bchain.Unlock()
		httpError(w, http.StatusNotFound, "header not found: %x", h[:])
		return
	}
	blockBytes, err := bchain.getBlock(h)
	if err != nil {
		bchain.Unlock()
		httpError(w, http.StatusNotFound, "block not found: %x", h[:])
		return
	}
	bchain.Unlock()

	fullBlock := newExploreBlock(ph, coin.Block(blockBytes))

	j, err := json.MarshalIndent(fullBlock, "", "  ")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding error: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

type scoreReport struct {
	Height          uint64         `json:"height"`
	TotalDifficulty uint64         `json:"totaldifficulty"`
	MainScores      map[string]int `json:"mainchain"`
	EverScores      map[string]int `json:"everinmainchain"`
	Scores          map[string]int `json:"total"`
}

func scoresHandler(w http.ResponseWriter, r *http.Request) {
	bchain.Lock()
	sr := scoreReport{
		Height:          bchain.head.BlockHeight + 1,
		TotalDifficulty: bchain.head.TotalDifficulty,
		MainScores:      bchain.mainscores,
		EverScores:      bchain.everscores,
		Scores:          bchain.scores,
	}
	j, err := json.MarshalIndent(sr, "", "  ")
	bchain.Unlock()

	if err != nil {
		httpError(w, http.StatusInternalServerError, "json encoding error: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("templates/index.html")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "error reading index: %s", err)
	}
	w.Write(data)
}

func httpError(w http.ResponseWriter, status int, format string, v ...interface{}) {
	s := fmt.Sprintf(http.StatusText(status)+": "+format, v...)
	log.Print(s)
	http.Error(w, s, status)
}
