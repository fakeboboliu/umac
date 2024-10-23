//go:build !(ppc64 || mips || mips64)

// not these BE architectures, we can assume LE and consider only byte order of LE.
// nobody use those BE architectures anyway.

package umac

import (
	"crypto/cipher"
	"math/bits"
)

const (
	// STREAMS is Number of times hash is applied, 64 and 128 bits
	STREAMS8        = 2
	STREAMS16       = 4
	L1_KEY_LEN      = 1024 // Internal key bytes
	L1_KEY_SHIFT    = 16   // Toeplitz key shift between streams
	L1_PAD_BOUNDARY = 32   // pad message to boundary multiple
	HASH_BUF_BYTES  = 64   // nh_aux_hb buffer multiple
)

// region nh 8 bytes
type nhCtx8 struct {
	key       [L1_KEY_LEN + L1_KEY_SHIFT*(STREAMS8-1)]byte
	data      [HASH_BUF_BYTES]byte
	nextEmpty int
	hashed    int
	state     [STREAMS8]uint64
}

func nhAux8(k, d []uint32, hp []uint64, dlen int) {
	batches := dlen / 32

	kache := k[0:4]
	for batches > 0 {
		// boundary assert
		_ = d[7]
		_ = k[11]

		hp[0] += uint64(kache[0]+d[0])*uint64(k[4]+d[4]) +
			uint64(kache[1]+d[1])*uint64(k[5]+d[5]) +
			uint64(kache[2]+d[2])*uint64(k[6]+d[6]) +
			uint64(kache[3]+d[3])*uint64(k[7]+d[7])

		hp[1] += uint64(k[4]+d[0])*uint64(k[8]+d[4]) +
			uint64(k[5]+d[1])*uint64(k[9]+d[5]) +
			uint64(k[6]+d[2])*uint64(k[10]+d[6]) +
			uint64(k[7]+d[3])*uint64(k[11]+d[7])

		kache = k[8:12]

		k = k[8:]
		d = d[8:]
		batches--
	}
}

func (c *nhCtx8) transform(buf []byte) {
	nhAux8(toUint32(c.key[c.hashed:]), toUint32(buf), c.state[:], len(buf))
}

func (c *nhCtx8) reset() {
	c.nextEmpty = 0
	c.hashed = 0
	c.state[0] = 0
	c.state[1] = 0
}

func (c *nhCtx8) init(cip cipher.Block) {
	kdf(cip, 1, c.key[:])
	array := toUint32(c.key[:])
	for i := range array {
		array[i] = bits.ReverseBytes32(array[i])
	}
	c.reset()
}

func (c *nhCtx8) update(buf []byte) {
	j := c.nextEmpty
	n := len(buf)
	if (j + n) >= HASH_BUF_BYTES {
		if j != 0 {
			i := HASH_BUF_BYTES - j
			copy(c.data[j:], buf[:i])
			c.transform(c.data[:])
			n -= i
			buf = buf[i:]
			c.hashed += HASH_BUF_BYTES
		}
		if n >= HASH_BUF_BYTES {
			i := n & ^(HASH_BUF_BYTES - 1)
			c.transform(buf[:i])
			n -= i
			buf = buf[i:]
			c.hashed += i
		}
		j = 0
	}
	copy(c.data[j:], buf)
	c.nextEmpty = j + n
}

func (c *nhCtx8) final(result []uint64) {
	_ = result[1]

	if c.nextEmpty != 0 {
		nhLen := (c.nextEmpty + (L1_PAD_BOUNDARY - 1)) & ^(L1_PAD_BOUNDARY - 1)
		copy(c.data[c.nextEmpty:], make([]byte, nhLen-c.nextEmpty))
		c.transform(c.data[:nhLen])
		c.hashed += c.nextEmpty
	} else if c.hashed == 0 {
		copy(c.data[:], make([]byte, L1_PAD_BOUNDARY))
		c.transform(c.data[:L1_PAD_BOUNDARY])
	}

	nbits := c.hashed << 3
	result[0] = c.state[0] + uint64(nbits)
	result[1] = c.state[1] + uint64(nbits)
	c.reset()
}

func (c *nhCtx8) hash(buf []byte, paddedLen, unpaddedLen int, result []uint64) {
	nbits := uint64(unpaddedLen << 3)
	result[0] = nbits
	result[1] = nbits
	nhAux8(toUint32(c.key[:]), toUint32(buf), result, paddedLen)
}

//endregion

// region nh 16 bytes
type nhCtx16 struct {
	key       [L1_KEY_LEN + L1_KEY_SHIFT*(STREAMS16-1)]byte
	data      [HASH_BUF_BYTES]byte
	nextEmpty int
	hashed    int
	state     [STREAMS16]uint64
}

func nhAux16(k, d []uint32, hp []uint64, dlen int) {
	batches := dlen / 32

	for batches > 0 {
		// boundary assert
		_ = d[7]
		_ = k[19]

		hp[0] += uint64(k[0]+d[0])*uint64(k[4]+d[4]) +
			uint64(k[1]+d[1])*uint64(k[5]+d[5]) +
			uint64(k[2]+d[2])*uint64(k[6]+d[6]) +
			uint64(k[3]+d[3])*uint64(k[7]+d[7])

		hp[1] += uint64(k[4]+d[0])*uint64(k[8]+d[4]) +
			uint64(k[5]+d[1])*uint64(k[9]+d[5]) +
			uint64(k[6]+d[2])*uint64(k[10]+d[6]) +
			uint64(k[7]+d[3])*uint64(k[11]+d[7])

		hp[2] += uint64(k[8]+d[0])*uint64(k[12]+d[4]) +
			uint64(k[9]+d[1])*uint64(k[13]+d[5]) +
			uint64(k[10]+d[2])*uint64(k[14]+d[6]) +
			uint64(k[11]+d[3])*uint64(k[15]+d[7])

		hp[3] += uint64(k[12]+d[0])*uint64(k[16]+d[4]) +
			uint64(k[13]+d[1])*uint64(k[17]+d[5]) +
			uint64(k[14]+d[2])*uint64(k[18]+d[6]) +
			uint64(k[15]+d[3])*uint64(k[19]+d[7])

		k = k[8:]
		d = d[8:]
		batches--
	}
}

func (c *nhCtx16) transform(buf []byte) {
	nhAux16(toUint32(c.key[c.hashed:]), toUint32(buf), c.state[:], len(buf))
}

func (c *nhCtx16) reset() {
	c.nextEmpty = 0
	c.hashed = 0
	c.state[0] = 0
	c.state[1] = 0
	c.state[2] = 0
	c.state[3] = 0
}

func (c *nhCtx16) init(cip cipher.Block) {
	kdf(cip, 1, c.key[:])
	array := toUint32(c.key[:])
	for i := range array {
		array[i] = bits.ReverseBytes32(array[i])
	}
	c.reset()
}

func (c *nhCtx16) update(buf []byte) {
	j := c.nextEmpty
	n := len(buf)
	if (j + n) >= HASH_BUF_BYTES {
		if j != 0 {
			i := HASH_BUF_BYTES - j
			copy(c.data[j:], buf[:i])
			c.transform(c.data[:])
			n -= i
			buf = buf[i:]
			c.hashed += HASH_BUF_BYTES
		}
		if n >= HASH_BUF_BYTES {
			i := n & ^(HASH_BUF_BYTES - 1)
			c.transform(buf[:i])
			n -= i
			buf = buf[i:]
			c.hashed += i
		}
		j = 0
	}
	copy(c.data[j:], buf)
	c.nextEmpty = j + n
}

func (c *nhCtx16) final(result []uint64) {
	if c.nextEmpty != 0 {
		nhLen := (c.nextEmpty + (L1_PAD_BOUNDARY - 1)) & ^(L1_PAD_BOUNDARY - 1)
		copy(c.data[c.nextEmpty:], make([]byte, nhLen-c.nextEmpty))
		c.transform(c.data[:nhLen])
		c.hashed += c.nextEmpty
	} else if c.hashed == 0 {
		copy(c.data[:], make([]byte, L1_PAD_BOUNDARY))
		c.transform(c.data[:L1_PAD_BOUNDARY])
	}

	nbits := c.hashed << 3
	result[0] = c.state[0] + uint64(nbits)
	result[1] = c.state[1] + uint64(nbits)
	result[2] = c.state[2] + uint64(nbits)
	result[3] = c.state[3] + uint64(nbits)
	c.reset()
}

func (c *nhCtx16) hash(buf []byte, paddedLen, unpaddedLen int, result []uint64) {
	nbits := uint64(unpaddedLen << 3)
	result[0] = nbits
	result[1] = nbits
	result[2] = nbits
	result[3] = nbits
	nhAux16(toUint32(c.key[:]), toUint32(buf), result, paddedLen)
}

//endregion
