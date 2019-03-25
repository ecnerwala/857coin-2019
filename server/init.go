package server

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	accessLogger    *log.Logger
	accessLogBuffer *bufio.Writer

	bchain *blockchain
)

func init() {
	logPath := "logs/" + time.Now().Format("2006-01-02_15:04:05")
	accessFile, err := os.Create(logPath)
	if err != nil {
		log.Fatalf("%v", err)
	}
	accessLogBuffer = bufio.NewWriter(accessFile)
	accessLogger = log.New(accessLogBuffer, "", log.LstdFlags)

	// Initialize 857 blockcahin

	if bchain, err = newBlockchain(); err != nil {
		log.Println("[init]", err)
		panic(err)
	}
}

func LogHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessLogger.Printf("%s %s %s %s %q %q", stripPort(r.RemoteAddr), r.Method, r.URL, r.Proto, r.Referer(), r.UserAgent())
		h.ServeHTTP(w, r)
	})
}

func stripPort(s string) string {
	if i := strings.LastIndex(s, ":"); i != -1 {
		return s[:i]
	}
	return s
}

func Start(addr string) error {
	server := &http.Server{
		Addr:        addr,
		Handler:     LogHandler(http.DefaultServeMux),
		ReadTimeout: 10 * time.Second,
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/add", addHandler)
	http.Handle("/next/", http.StripPrefix("/next/", http.HandlerFunc(nextHandler)))
	http.HandleFunc("/head", headHandler)
	http.HandleFunc("/scores", scoresHandler)
	http.Handle("/search/", http.StripPrefix("/search/", http.HandlerFunc(searchHandler)))
	http.Handle("/block/", http.StripPrefix("/block/", http.HandlerFunc(blockHandler)))

	e := NewExplorer()
	http.HandleFunc("/explore", e.handler)

	staticHandler := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", staticHandler))

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	return err
}
