package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb/util"
)

// TODO currently updates every minute, but could update every new block
type explorer struct {
	mu       sync.RWMutex
	buf      []byte
	err      error
	tick     *time.Ticker
	template *template.Template
}

type explorerTemplateData struct {
	Nodes  template.JS
	Edges  template.JS
	HeadId template.JS
}

func NewExplorer() *explorer {
	e := &explorer{
		tick:     time.NewTicker(1 * time.Minute),
		template: template.Must(template.ParseFiles("templates/explore.html")),
	}

	e.update()

	return e
}

func (e *explorer) handler(w http.ResponseWriter, r *http.Request) {
	select {
	case <-e.tick.C:
		e.update()
	default:
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.err != nil {
		httpError(w, http.StatusInternalServerError, "error updating explorer: %s", e.err)
		return
	}
	w.Write(e.buf)
}

func (e *explorer) update() {
	buf, err := e.executeTemplate()

	if err != nil {
		log.Println("error updating explorer: ", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.buf, e.err = buf, err
}

func (e *explorer) executeTemplate() ([]byte, error) {
	nodes := new(bytes.Buffer)
	edges := new(bytes.Buffer)

	bchain.Lock()
	headId := bchain.head.Header.Sum()
	totalHeight := bchain.head.BlockHeight
	iter := bchain.db.NewIterator(util.BytesPrefix([]byte(HeaderBucket)), nil)
	for iter.Next() {
		// Load header
		headerBytes := iter.Value()
		var pheader processedHeader
		if err := json.Unmarshal(headerBytes, &pheader); err != nil {
			bchain.Unlock()
			return nil, err
		}

		if pheader.BlockHeight > totalHeight {
			continue
		}

		parentID := pheader.Header.ParentID

		hash := pheader.Header.Sum()
		label, err := bchain.getBlock(hash)
		if err != nil {
			bchain.Unlock()
			return nil, err
		}
		trunc := 5
		if len(label) < trunc {
			trunc = len(label)
		}
		label = label[:trunc]

		var color string
		if pheader.IsMainChain {
			color = "green"
		} else if pheader.EverMainChain {
			color = "blue"
		} else {
			color = "black"
		}

		fmt.Fprintf(nodes, "{id:'%x',level:%d,label:'%s',color:'%s'},\n",
			hash[:], pheader.BlockHeight, template.JSEscapeString(label), color)
		fmt.Fprintf(edges, "{from:'%s',to:'%x',color:'%s'},\n",
			parentID, hash[:], color)
	}
	bchain.Unlock()

	data := &explorerTemplateData{
		Nodes:  template.JS(nodes.String()),
		Edges:  template.JS(edges.String()),
		HeadId: template.JS(hex.EncodeToString(headId[:])),
	}

	buf := new(bytes.Buffer)
	if err := e.template.Execute(buf, data); err != nil {
		return nil, fmt.Errorf("template error: %s", err)
	}
	return buf.Bytes(), nil
}
