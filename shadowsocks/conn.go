package shadowsocks

import (
	"net"
	"io"
	"sync"
	"time"
	"github.com/go-playground/log"
)

const bufSize = 4108 // data.len(2) + hmacsha1(10) + data(4096)

type Conn struct {
	net.Conn
	*Cipher
	readBuf  []byte
	writeBuf []byte
	chunkId  uint32
}

//buffer pool, with gc
var bufPool = &sync.Pool{New:func() interface{} {
	return make([]byte, bufSize)
}}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	rBuf, _ := bufPool.Get().([]byte)
	wBuf, _ := bufPool.Get().([]byte)

	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:   rBuf,
		writeBuf:  wBuf,
	}
}

func (c *Conn) readClientIV() ([]byte, error) {
	iv := make([]byte, c.info.ivLen)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return iv, err
	}
	return iv, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.encode == nil {
		err := c.initEncrypt()
		if err != nil {
			return 0, err
		}
	}

	buf := c.writeBuf
	//dataSize := len(b) + len(c.iv)
	//if dataSize > len(buf) {
	//	buf = make([]byte, dataSize)
	//} else {
	//	buf = buf[:dataSize]
	//}

	//copy iv to buffer
	copy(buf, c.iv)

	c.encrypt(buf[len(c.iv):], b)

	// write buffer data
	n, err := c.Conn.Write(buf)
	return n, err
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.decode == nil {
		iv, err := c.readClientIV()
		if err != nil {
			return 0, err
		}
		if err = c.initDecrypt(iv); err != nil {
			return 0, err
		}
	}

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err := c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return n, err
}

func PipeConnection(src, dst net.Conn, timeout time.Duration) {
	defer dst.Close()

	buf, _ := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	src.SetReadDeadline(time.Now().Add(timeout))

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				log.Debugf("error when write to dst, error: %s", err)
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Errorf("error when read from src, error: %s", err)
			}
			break
		}
	}
}