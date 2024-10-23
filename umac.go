package umac

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"hash"
	"math"
)

func kdf(cip cipher.Block, index uint8, dst []byte) []byte {
	srcBuf := make([]byte, aes.BlockSize)
	srcBuf[7] = index
	i := 1
	v := int(math.Ceil(float64(len(dst)) / float64(aes.BlockSize)))
	for ; i < v; i++ {
		srcBuf[15] = uint8(i)
		cip.Encrypt(dst, srcBuf)
		dst = dst[aes.BlockSize:]
	}
	if len(dst) > 0 {
		srcBuf[15] = uint8(i)
		cip.Encrypt(srcBuf, srcBuf)
		copy(dst, srcBuf)
	}
	return dst
}

type pdfCtx struct {
	cip   cipher.Block        // AES cipher for pdf
	cache [aes.BlockSize]byte // cache from previous aes output
	nonce [aes.BlockSize]byte // nonce for aes, the input
}

func (c *pdfCtx) init(cip cipher.Block) {
	// reuse the cache to store kdf output, it will be rewritten soon
	kdf(cip, 0, c.cache[:])

	// the input of NewCipher is controlled, so we can always ignore the error
	c.cip, _ = aes.NewCipher(c.cache[:])

	// store aes(kdf(key), {0*16}) -> cache
	// nonce is 0 now, so we use it as input
	c.cip.Encrypt(c.cache[:], c.nonce[:])
}

func (c *pdfCtx) genXor8(nonce [8]byte, buf []byte) {
	_ = buf[7]

	const loBitMask = 0x01
	ndx := nonce[7] & loBitMask
	var t [4]byte
	copy(t[:], nonce[4:])
	t[3] &= ^byte(loBitMask)

	if !bytes.Equal(t[:], c.nonce[4:]) || !bytes.Equal(nonce[:4], c.nonce[:4]) {
		copy(c.nonce[:4], nonce[:4])
		copy(c.nonce[4:8], t[:])
		c.cip.Encrypt(c.cache[:], c.nonce[:])
	}

	subtle.XORBytes(buf, buf, c.cache[ndx*8:])
}

func (c *pdfCtx) genXor16(nonce [8]byte, buf []byte) {
	_ = buf[7]

	var t [4]byte
	copy(t[:], nonce[4:])

	if !bytes.Equal(t[:], c.nonce[4:]) || !bytes.Equal(nonce[:4], c.nonce[:4]) {
		copy(c.nonce[:4], nonce[:4])
		copy(c.nonce[4:8], t[:])
		c.cip.Encrypt(c.cache[:], c.nonce[:])
	}

	subtle.XORBytes(buf, buf, c.cache[:])
}

// UMAC8 is the 8-byte output version of UMAC.
// also known as UMAC-64
type UMAC8 struct {
	pdf  pdfCtx
	hash uhash8
	out  [8]byte
}

func (u *UMAC8) Write(p []byte) (n int, err error) {
	u.hash.update(p)
	return len(p), nil
}

// Sum uses the argument as nonce, which should be 8 bytes long.
// WARNING: it's not standard hash.Hash behavior.
func (u *UMAC8) Sum(b []byte) []byte {
	_ = b[7]
	out := u.out[:]
	u.hash.final(out)
	u.pdf.genXor8([8]byte(b), out)
	b = b[:0]
	return append(b, out...)
}

func (u *UMAC8) Reset() {
	u.hash.reset()
}

func (u *UMAC8) Size() int {
	return 8
}

func (u *UMAC8) BlockSize() int {
	return 1
}

// UMAC16 is the 16-byte output version of UMAC.
// also known as UMAC-128
type UMAC16 struct {
	pdf  pdfCtx
	hash uhash16
	out  [16]byte
}

func (u *UMAC16) Write(p []byte) (n int, err error) {
	u.hash.update(p)
	return len(p), nil
}

// Sum uses the argument as nonce, which should be 8 bytes long.
// WARNING: it's not standard hash.Hash behavior.
func (u *UMAC16) Sum(b []byte) []byte {
	_ = b[7]
	out := u.out[:]
	u.hash.final(out)
	u.pdf.genXor16([8]byte(b), out)
	b = b[:0]
	return append(b, out...)
}

func (u *UMAC16) Reset() {
	u.hash.reset()
}

func (u *UMAC16) Size() int {
	return 16
}

func (u *UMAC16) BlockSize() int {
	return 1
}

func New8(key []byte) hash.Hash {
	u := &UMAC8{}
	cip, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	u.pdf.init(cip)
	u.hash.init(cip)
	return u
}

func New16(key []byte) hash.Hash {
	u := &UMAC16{}
	cip, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	u.pdf.init(cip)
	u.hash.init(cip)
	return u
}
