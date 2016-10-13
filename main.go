package main

import (
	"github.com/whiteblue/simple-shadowsocks/shadowsocks"
	"time"
	"github.com/go-playground/log/handlers/console"
	"github.com/go-playground/log"
)

func RunServer() {
	shadowsocks.ListenPort("9000", "rc4-md5", "whiteblue", 2 * time.Second)
}

func main() {

	cLog := console.New()

	log.RegisterHandler(cLog, log.AllLevels...)

	RunServer()

}


