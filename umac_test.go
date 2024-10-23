package umac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

// A case shown by evaluating ssh, could test if msgLen corrupted
func TestUMAC16_SSHCase(t *testing.T) {
	writes := []string{"000004bc0e", "320000000f7465737463657274696669636174650000000e7373682d636f6e6e656374696f6e000000097075626c69636b657900000000217273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d000004500000001c7373682d7273612d636572742d763031406f70656e7373682e636f6d0000002010a47dc6785791b8bfa603faebd563047e97553611d32c75c2e9c2b4e223ce350000000301000100000101009eea3328cb5c4242089991927b822e8d2e3e2e46acf639a5062bf3896194df06a2be4a54bd8b298096e1eef4af9c738fb4ab1c74827edd45325620d4a0cef71ae9ac987bdf7910a803d6113992b87d047d1b46b5c1fa11aacac95c64e80b34efaff236288c29506d1b444f6b52fb16f8937dc60ae2f9c2095adbbf7466039082cee1b905231b44bc7355be118b7a7c8e1c584fc3784067bfdb2aaf24bcace6f43db33a59477b5c169dc324855984145f47a2e7a18db75d99e20003106945415fce9d5d0fbe74dc00c194974adf4e83e02788e0a2058aa13556b99f70c80ff1fb62d12d1be09b66bdebd8a0f77eff007d22d16abe173a9f2bb11743df587f92bf00000000000000000000000100000008757365726e616d65000000130000000f7465737463657274696669636174650000000000000000ffffffffffffffff0000000000000082000000157065726d69742d5831312d666f7277617264696e6700000000000000177065726d69742d6167656e742d666f7277617264696e6700000000000000167065726d69742d706f72742d666f7277617264696e67000000000000000a7065726d69742d707479000000000000000e7065726d69742d757365722d7263000000000000000000000117000000077373682d727361000000030100010000010100be0f5d43d2111b9f656096fe18449f2964dc878c81a6bed8770d6390aeafbedaf1f632e8e61900f17ebe12544f46a4c065294de5c066e9808071020eb265c3527e8e8f59553d00283a34c14efb233373631a1befe769074d8d27b0cb01798f6ae434ed9739a5624554ab66ba1ed81fda6362d35748c397c9eee4d3a3c11b35feced22dee73d6bc3f5f4769997934a8963781086647c1d96757611242541b068108f7744fc6ac4987f5020dab503e1a436f2bdeaebd99bc1f58e39aeab31e99566bb945797731f054d54db55bfe226b6762dcfc9bc83e2b4a65686a6d1e7dcab1a3a7012921dedba385a13b92f7381d1f488258bdfbbea385989ede1fdd4cde73000001140000000c7273612d736861322d353132000001008a567d92ec52588574d155b733d438b51cbcf583961a7b958185dd13838ef55e4370ef295c08adb75a7af38f51b1ad6d285820861d13ad527c505de8b5c4d5adf0738d37e79e69fac9499251e9a95ddd87783af797947353ea61033e0a918f8079e8e3e8637dcbce968595066567a53d297c92b2135a0938d5a77a234e3eae3cdc5cb8e9c6f4ee5e9843c2d9e68ce1062ccf872a1cd27d496584bbe1c8420a71e52335daa72babf2a137a589846dde74bd5802cc647f5fd31c471f8bac2fb078be0ca7b0279859f3bebffe36a98c704a03d481ee0b02acbc779bed1723c4e45946536491c44c91c756324df318d1bccbf981628bbd1b33ed27269cdd7e7242fa3e9a54afba3059a66f6e9ac87528"}
	nonce, _ := hex.DecodeString("0000000000000003")
	key, _ := hex.DecodeString("e5d3a843d10e9e66e77c97703491217c")
	umac := New16(key)
	for _, w := range writes {
		buf, _ := hex.DecodeString(w)
		umac.Write(buf)
	}
	tag := umac.Sum(nonce)
	target, _ := hex.DecodeString("e03ab558b445896adb8a4a9bd64cacd4")
	if !bytes.Equal(tag, target) {
		t.Errorf("UMAC16 failed: %x, expected %x", tag, target)
	}
}

func TestUMAC(t *testing.T) {
	lengths := []int{0, 3, 1024, 32768}
	results := []string{"4D61E4F5AAB959C8B800A2BE546302AD",
		"67C1700CA30B532DCD9B970655B47B45",
		"05CB9405EC38D9F0B356D9E6D5BC5D03",
		"048C543CB72443A46011A76438BA2AF4"}

	data := make([]byte, 32*1024)
	for i := range data {
		data[i] = 'a'
	}

	umac := New8([]byte("abcdefghijklmnop"))
	for i, length := range lengths {
		nonce := []byte("abcdefgh")
		umac.Write(data[:length])
		tag := umac.Sum(nonce)
		umac.Reset()
		target, _ := hex.DecodeString(results[i])
		if !bytes.Equal(tag, target[:8]) {
			t.Errorf("UMAC8 failed: %x, expected %x", tag, target)
		}
	}

	umac = New16([]byte("abcdefghijklmnop"))
	for i, length := range lengths {
		nonce := []byte("abcdefgh")
		umac.Write(data[:length])
		tag := umac.Sum(nonce)
		umac.Reset()
		target, _ := hex.DecodeString(results[i])
		if !bytes.Equal(tag, target[:16]) {
			t.Errorf("UMAC16 failed: %x, expected %x", tag, target)
		}
	}
}

func benchHash(b *testing.B, h hash.Hash, buf []byte) {
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
		mac := h.Sum(nil)
		h.Reset()
		buf[1] = mac[1]
	}
}

func benchUMAC(b *testing.B, h hash.Hash, buf []byte) {
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
		mac := h.Sum([]byte("abcdefgh"))
		h.Reset()
		buf[1] = mac[1]
	}
}

func BenchmarkHMACSHA256_1K(b *testing.B) {
	key := make([]byte, 32)
	buf := make([]byte, 1024)
	benchHash(b, hmac.New(sha256.New, key), buf)
}

func BenchmarkHMACSHA256_32(b *testing.B) {
	key := make([]byte, 32)
	buf := make([]byte, 32)
	benchHash(b, hmac.New(sha256.New, key), buf)
}

func BenchmarkHMACMD5_1K(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 1024)
	benchHash(b, hmac.New(md5.New, key), buf)
}

func BenchmarkHMACMD5_32(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 32)
	benchHash(b, hmac.New(md5.New, key), buf)
}

func BenchmarkUMAC64_1K(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 1024)
	benchUMAC(b, New8(key), buf)
}

func BenchmarkUMAC64_32(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 32)
	benchUMAC(b, New8(key), buf)
}

func BenchmarkUMAC128_1K(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 1024)
	benchUMAC(b, New16(key), buf)
}

func BenchmarkUMAC128_32(b *testing.B) {
	key := make([]byte, 16)
	buf := make([]byte, 32)
	benchUMAC(b, New16(key), buf)
}
