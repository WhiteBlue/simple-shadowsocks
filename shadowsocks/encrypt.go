package shadowsocks

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"io"
	"crypto/rand"
	"crypto/aes"
	"crypto/des"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"github.com/codahale/chacha20"
	"errors"
	"github.com/go-playground/log"
)

// A copy from shadowsocks-go

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type DecOrEnc int

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

type Cipher struct {
	encode cipher.Stream
	decode cipher.Stream
	key    []byte
	info   *cipherInfo
	iv     []byte
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-cfb": {16, 16, newAESStream},
	"aes-192-cfb": {24, 16, newAESStream},
	"aes-256-cfb": {32, 16, newAESStream},
	"des-cfb":     {8, 8, newDESStream},
	"bf-cfb":      {16, 8, newBlowFishStream},
	"cast5-cfb":   {16, 8, newCast5Stream},
	"rc4-md5":     {16, 16, newRC4MD5Stream},
	"chacha20":    {32, 8, newChaCha20Stream},
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}


// password (keyLen) => key
func evpBytesToKey(password string, keyLen int) []byte {
	const md5Len = 16

	//cnt: 与md5长度的倍数
	cnt := (keyLen - 1) / md5Len + 1

	m := make([]byte, cnt * md5Len)
	copy(m, md5sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len + len(password))

	// 每段: [md5(password)中的16字节|password]*n
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len

		//inner_code: 16字节md5(password) | 密码
		copy(d, m[start - md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], md5sum(d))
	}
	return m[:keyLen]
}

func newStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newAESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newBlowFishStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newCast5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}

func NewCipher(method, password string) (*Cipher, error) {
	m, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := evpBytesToKey(password, m.keyLen)

	c := &Cipher{key: key, info: cipherMethod[method]}

	c.generateIV()

	return c, nil
}

// generate an IV for a cipher instance
func (c *Cipher) generateIV() {
	iv := make([]byte, c.info.ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error("error when generate IV, error: ", err)
	}
	c.iv = iv
}

// init encode stream
func (c *Cipher) initEncrypt() error {
	encode, err := c.info.newStream(c.key, c.iv, Encrypt)
	c.encode = encode
	return err
}

// init decode stream
func (c *Cipher) initDecrypt(iv []byte) error {
	decode, err := c.info.newStream(c.key, iv, Decrypt)
	c.decode = decode
	return err
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.encode.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.decode.XORKeyStream(dst, src)
}

func (c *Cipher) newInstance() *Cipher {
	nc := &Cipher{}
	nc.info = c.info
	nc.key = c.key
	nc.generateIV()
	return nc
}
