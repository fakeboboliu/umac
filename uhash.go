//go:build !(ppc64 || mips || mips64)

// not these BE architectures, we can assume LE and consider only byte order of LE.
// nobody use those BE architectures anyway.

package umac

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
)

// region uhash helper
const (
	p36 = 0x0000000FFFFFFFFB // 2^36 - 5
	p64 = 0xFFFFFFFFFFFFFFC5 // 2^64 - 59
	m36 = 0x0000000FFFFFFFFF // The low 36 of 64 bits
)

func poly64(cur uint64, key uint64, data uint64) uint64 {
	keyHi := uint32(key >> 32)
	keyLo := uint32(key)
	curHi := uint32(cur >> 32)
	curLo := uint32(cur)
	x := uint64(keyHi)*uint64(curLo) + uint64(curHi)*uint64(keyLo)
	xLo := uint32(x)
	xHi := uint32(x >> 32)
	res := (uint64(keyHi)*uint64(curHi)+uint64(xHi))*59 + uint64(keyLo)*uint64(curLo)
	t := uint64(xLo) << 32
	res += t
	if res < t {
		res += 59
	}
	res += data
	if res < data {
		res += 59
	}
	return res
}

func ipAux(t uint64, ipkp []uint64, data uint64) uint64 {
	t += ipkp[0] * (uint64)(uint16(data>>48))
	t += ipkp[1] * (uint64)(uint16(data>>32))
	t += ipkp[2] * (uint64)(uint16(data>>16))
	t += ipkp[3] * (uint64)(uint16(data))
	return t
}

func ipReduceP36(t uint64) uint32 {
	ret := (t & m36) + 5*(t>>36)
	if ret >= p36 {
		ret -= p36
	}
	return (uint32)(ret)
}

//endregion

// region uhash 8 bytes
type uhash8 struct {
	nh         nhCtx8               // nh_ctx hash
	polyKey    [STREAMS8]uint64     // poly_key_8
	polyResult [STREAMS8]uint64     // poly_accum
	ipKeys     [STREAMS8 * 4]uint64 // ip_keys
	ipTrans    [STREAMS8]uint32     // ip_trans
	msgLen     uint32               // msg_len
}

func (u *uhash8) polyHash(data64 []uint64) {
	for i := 0; i < STREAMS8; i++ {
		if uint32(data64[i]>>32) == 0xffffffff {
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], p64-1)
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], data64[i]-59)
		} else {
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], data64[i])
		}
	}
}

func (u *uhash8) ipShort(in []byte, out []byte) {
	_ = in[15]
	_ = out[7]

	nhp := toUint64(in)
	t := ipAux(0, u.ipKeys[:], nhp[0])
	binary.BigEndian.PutUint32(out, ipReduceP36(t)^u.ipTrans[0])
	t = ipAux(0, u.ipKeys[4:], nhp[1])
	binary.BigEndian.PutUint32(out[4:], ipReduceP36(t)^u.ipTrans[1])
}

func (u *uhash8) ipLong(out []byte) {
	_ = out[7]

	if u.polyResult[0] >= p64 {
		u.polyResult[0] -= p64
	}
	if u.polyResult[1] >= p64 {
		u.polyResult[1] -= p64
	}

	t := ipAux(0, u.ipKeys[:], u.polyResult[0])
	binary.BigEndian.PutUint32(out, ipReduceP36(t)^u.ipTrans[0])
	t = ipAux(0, u.ipKeys[4:], u.polyResult[1])
	binary.BigEndian.PutUint32(out[4:], ipReduceP36(t)^u.ipTrans[1])
}

func (u *uhash8) reset() {
	u.nh.reset()
	u.msgLen = 0
	u.polyResult[0] = 1
	u.polyResult[1] = 1
}

func (u *uhash8) init(cip cipher.Block) {
	buf := [(8*STREAMS8 + 4) * 8]byte{}
	u.nh = nhCtx8{}
	u.nh.init(cip)
	kdf(cip, 2, buf[:])
	for i := 0; i < STREAMS8; i++ {
		u.polyKey[i] = binary.BigEndian.Uint64(buf[24*i:])
		u.polyKey[i] &= 0x01ffffff<<32 + 0x01ffffff
		u.polyResult[i] = 1
	}
	kdf(cip, 3, buf[:])
	for i := 0; i < STREAMS8; i++ {
		from := toUint64(buf[(8*i+4)*8:])[:4]
		u.ipKeys[4*i] = bits.ReverseBytes64(from[0])
		u.ipKeys[4*i+1] = bits.ReverseBytes64(from[1])
		u.ipKeys[4*i+2] = bits.ReverseBytes64(from[2])
		u.ipKeys[4*i+3] = bits.ReverseBytes64(from[3])
	}
	for i := 0; i < STREAMS8; i++ {
		u.ipKeys[i*4] %= p36
		u.ipKeys[i*4+1] %= p36
		u.ipKeys[i*4+2] %= p36
		u.ipKeys[i*4+3] %= p36
	}
	kdf(cip, 4, buf[:STREAMS8*4])
	from := toUint32(buf[:STREAMS8*4])
	for i := 0; i < STREAMS8; i++ {
		u.ipTrans[i] = bits.ReverseBytes32(from[i])
	}
}

func (u *uhash8) update(buf []byte) {
	result := [STREAMS8]uint64{}
	bufLen := uint32(len(buf))

	if u.msgLen+bufLen <= L1_KEY_LEN {
		u.nh.update(buf)
		u.msgLen += bufLen
	} else {
		bytesHashed := u.msgLen % L1_KEY_LEN
		if u.msgLen == L1_KEY_LEN {
			bytesHashed = L1_KEY_LEN
		}

		if bytesHashed+bufLen >= L1_KEY_LEN {
			if bytesHashed != 0 {
				bytesRemaining := L1_KEY_LEN - bytesHashed
				u.nh.update(buf[:bytesRemaining])
				u.nh.final(result[:])
				u.msgLen += bytesRemaining
				u.polyHash(result[:])
				buf = buf[bytesRemaining:]
				bufLen -= bytesRemaining
			}

			for bufLen >= L1_KEY_LEN {
				u.nh.hash(buf, L1_KEY_LEN, L1_KEY_LEN, result[:])
				u.msgLen += L1_KEY_LEN
				buf = buf[L1_KEY_LEN:]
				bufLen -= L1_KEY_LEN
				u.polyHash(result[:])
			}
		}

		if bufLen != 0 {
			u.nh.update(buf)
			u.msgLen += bufLen
		}
	}
}

func (u *uhash8) final(out []byte) {
	result := [STREAMS8]uint64{}
	if u.msgLen > L1_KEY_LEN {
		if u.msgLen%L1_KEY_LEN != 0 {
			u.nh.final(result[:])
			u.polyHash(result[:])
		}
		u.ipLong(out)
	} else {
		u.nh.final(result[:])
		rb := toBytes(result[:])
		u.ipShort(rb, out)
	}
	u.reset()
}

//endregion

// region uhash 16 bytes
type uhash16 struct {
	nh         nhCtx16               // nh_ctx hash
	polyKey    [STREAMS16]uint64     // poly_key_8
	polyResult [STREAMS16]uint64     // poly_accum
	ipKeys     [STREAMS16 * 4]uint64 // ip_keys
	ipTrans    [STREAMS16]uint32     // ip_trans
	msgLen     uint32                // msg_len
}

func (u *uhash16) polyHash(data64 []uint64) {
	for i := 0; i < STREAMS16; i++ {
		if uint32(data64[i]>>32) == 0xffffffff {
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], p64-1)
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], data64[i]-59)
		} else {
			u.polyResult[i] = poly64(u.polyResult[i], u.polyKey[i], data64[i])
		}
	}
}

func (u *uhash16) ipShort(in []byte, out []byte) {
	_ = in[31]
	_ = out[15]

	nhp := toUint64(in)
	t := ipAux(0, u.ipKeys[:], nhp[0])
	binary.BigEndian.PutUint32(out, ipReduceP36(t)^u.ipTrans[0])
	t = ipAux(0, u.ipKeys[4:], nhp[1])
	binary.BigEndian.PutUint32(out[4:], ipReduceP36(t)^u.ipTrans[1])
	t = ipAux(0, u.ipKeys[8:], nhp[2])
	binary.BigEndian.PutUint32(out[8:], ipReduceP36(t)^u.ipTrans[2])
	t = ipAux(0, u.ipKeys[12:], nhp[3])
	binary.BigEndian.PutUint32(out[12:], ipReduceP36(t)^u.ipTrans[3])
}

func (u *uhash16) ipLong(out []byte) {
	_ = out[15]

	if u.polyResult[0] >= p64 {
		u.polyResult[0] -= p64
	}
	if u.polyResult[1] >= p64 {
		u.polyResult[1] -= p64
	}
	if u.polyResult[2] >= p64 {
		u.polyResult[2] -= p64
	}
	if u.polyResult[3] >= p64 {
		u.polyResult[3] -= p64
	}

	t := ipAux(0, u.ipKeys[:], u.polyResult[0])
	binary.BigEndian.PutUint32(out, ipReduceP36(t)^u.ipTrans[0])
	t = ipAux(0, u.ipKeys[4:], u.polyResult[1])
	binary.BigEndian.PutUint32(out[4:], ipReduceP36(t)^u.ipTrans[1])
	t = ipAux(0, u.ipKeys[8:], u.polyResult[2])
	binary.BigEndian.PutUint32(out[8:], ipReduceP36(t)^u.ipTrans[2])
	t = ipAux(0, u.ipKeys[12:], u.polyResult[3])
	binary.BigEndian.PutUint32(out[12:], ipReduceP36(t)^u.ipTrans[3])
}

func (u *uhash16) reset() {
	u.nh.reset()
	u.msgLen = 0
	for i := 0; i < STREAMS16; i++ {
		u.polyResult[i] = 1
	}
}

func (u *uhash16) init(cip cipher.Block) {
	buf := [(8*STREAMS16 + 4) * 8]byte{}
	u.nh = nhCtx16{}
	u.nh.init(cip)
	kdf(cip, 2, buf[:])
	for i := 0; i < STREAMS16; i++ {
		u.polyKey[i] = binary.BigEndian.Uint64(buf[24*i:])
		u.polyKey[i] &= 0x01ffffff<<32 + 0x01ffffff
		u.polyResult[i] = 1
	}
	kdf(cip, 3, buf[:])
	for i := 0; i < STREAMS16; i++ {
		from := toUint64(buf[(8*i+4)*8:])[:4]
		u.ipKeys[4*i] = bits.ReverseBytes64(from[0])
		u.ipKeys[4*i+1] = bits.ReverseBytes64(from[1])
		u.ipKeys[4*i+2] = bits.ReverseBytes64(from[2])
		u.ipKeys[4*i+3] = bits.ReverseBytes64(from[3])
	}
	for i := 0; i < STREAMS16; i++ {
		u.ipKeys[i*4] %= p36
		u.ipKeys[i*4+1] %= p36
		u.ipKeys[i*4+2] %= p36
		u.ipKeys[i*4+3] %= p36
	}
	kdf(cip, 4, buf[:STREAMS16*4])
	from := toUint32(buf[:STREAMS16*4])
	for i := 0; i < STREAMS16; i++ {
		u.ipTrans[i] = bits.ReverseBytes32(from[i])
	}
}

func (u *uhash16) update(buf []byte) {
	result := [STREAMS16]uint64{}
	bufLen := uint32(len(buf))

	if u.msgLen+bufLen <= L1_KEY_LEN {
		u.nh.update(buf)
		u.msgLen += bufLen
	} else {
		bytesHashed := u.msgLen % L1_KEY_LEN
		if u.msgLen == L1_KEY_LEN {
			bytesHashed = L1_KEY_LEN
		}

		if bytesHashed+bufLen >= L1_KEY_LEN {
			if bytesHashed != 0 {
				bytesRemaining := L1_KEY_LEN - bytesHashed
				u.nh.update(buf[:bytesRemaining])
				u.nh.final(result[:])
				u.msgLen += bytesRemaining
				u.polyHash(result[:])
				buf = buf[bytesRemaining:]
				bufLen -= bytesRemaining
			}

			for bufLen >= L1_KEY_LEN {
				u.nh.hash(buf, L1_KEY_LEN, L1_KEY_LEN, result[:])
				u.msgLen += L1_KEY_LEN
				buf = buf[L1_KEY_LEN:]
				bufLen -= L1_KEY_LEN
				u.polyHash(result[:])
			}
		}

		if bufLen != 0 {
			u.nh.update(buf)
			u.msgLen += bufLen
		}
	}
}

func (u *uhash16) final(out []byte) {
	result := [STREAMS16]uint64{}
	if u.msgLen > L1_KEY_LEN {
		if u.msgLen%L1_KEY_LEN != 0 {
			u.nh.final(result[:])
			u.polyHash(result[:])
		}
		u.ipLong(out)
	} else {
		u.nh.final(result[:])
		rb := toBytes(result[:])
		u.ipShort(rb, out)
	}
	u.reset()
}

//endregion
