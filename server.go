package main

import (
	"flag"
	"runtime"

	"github.com/ecnerwala/857coin-2019/server"
)

var (
	addr = flag.String("addr", ":8080", "http service address")
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	server.Start(*addr)
}
