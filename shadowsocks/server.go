package shadowsocks

import (
	"io"
	"net"
	"fmt"
	"encoding/binary"
	"strconv"
	"errors"
	"syscall"
	"time"
	"github.com/go-playground/log"
)

const (
	indexType = 0

	indexIP = 1
	indexDmLen = 1
	indexDm = 2

	typeIPv4 = 1
	typeDm = 3
	typeIPv6 = 4

	lenIPv4 = net.IPv4len
	lenIPv6 = net.IPv6len
	lenPort = 2

	OneTimeAuthMask byte = 0x10
	AddrMask byte = 0xf
)


// rebuild request
func unSerializeRequest(conn *Conn) (string, error) {
	// buffer size: 1(addrType) + 1(lenByte) + 256(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 270)

	if _, err := io.ReadFull(conn, buf[:indexType + 1]); err != nil {
		return "", err
	}

	var reqStart, reqEnd int

	addrType := buf[indexType] & AddrMask
	switch  addrType{
	case typeIPv4:
		reqStart, reqEnd = indexIP, indexIP + lenIPv4 + lenPort
	case typeIPv6:
		reqStart, reqEnd = indexIP, indexIP + lenIPv6 + lenPort
	case typeDm:
		// read domain length
		if _, err := io.ReadFull(conn, buf[indexType + 1:indexDmLen + 1]); err != nil {
			return "", err
		}
		reqStart, reqEnd = indexDm, int(indexDm + buf[indexDmLen] + lenPort)
	default:
		return "", fmt.Errorf("addr type %d not supported", addrType & AddrMask)
	}

	if _, err := io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return "", err
	}

	var host string
	switch addrType {
	case typeIPv4:
		host = net.IP(buf[indexIP:indexIP + net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[indexIP:indexIP + net.IPv6len]).String()
	case typeDm:
		host = string(buf[indexDm:indexDm + buf[indexDmLen]])
	}

	port := binary.BigEndian.Uint16(buf[reqEnd - 2:reqEnd ])

	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	if addrType & OneTimeAuthMask > 0 {
		return "", errors.New("one time auth is not supported")
	}

	return host, nil
}

func handleConnection(conn *Conn, timeout time.Duration) error {
	log.Debugf("new client %s", conn.RemoteAddr())

	var host string
	var closed bool

	defer func() {
		log.Debugf("closed pipe %s<->%s", conn.RemoteAddr(), host)
		if !closed {
			conn.Close()
		}
	}()

	host, err := unSerializeRequest(conn)
	if err != nil {
		log.Debugf("unsopported request %s", conn.RemoteAddr())
	}

	log.Debugf("connecting %s", host)

	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			log.Info("reach process open file limits")
		} else {
			log.Error("error connecting to:", host, err)
		}
		return err
	}

	//remote => client
	go PipeConnection(conn, remote, timeout)

	PipeConnection(remote, conn, timeout)

	closed = true

	return nil
}

func ListenPort(port, method, password string, timeout time.Duration) error {
	ln, err := net.Listen("tcp", ":" + port)
	if err != nil {
		log.Error("error listening port: ", port, ", error:", err)
		return err
	}

	baseCipher, err := NewCipher(method, password)
	if err != nil {
		log.Error("error get cipher: ", port, ", error:", err)
		return err
	}

	log.Infof("server listening at port %v", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept failed, error: ", err)
		}
		go handleConnection(NewConn(conn, baseCipher.newInstance()), timeout)
	}

}

