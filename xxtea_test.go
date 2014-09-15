package xxtea

import (
	"crypto/aes"
	"testing"
)

func CheckBuff(b1, b2 []byte, t *testing.T) bool {
	if len(b1) != len(b2) {
		t.Error("buffcheck", b1, b2)
	}
	for i := 0; i < len(b1); i++ {
		if b1[i] != b2[i] {
			t.Error("buffcheck", b1, b2)
		}
	}
	return true
}

func Test_Padding(t *testing.T) {
	buff := make([]byte, 0, 1000)
	out := PKCS5Padding(buff, 4)
	out = PKCS5UnPadding(out)
	CheckBuff(buff, out, t)

	var b byte = 0
	for i := 0; i < cap(buff); i++ {
		out = PKCS5Padding(buff, 4)
		out = PKCS5UnPadding(out)
		CheckBuff(buff, out, t)
		b++
		buff = append(buff, b)
	}
}

func Test_Encrypt(t *testing.T) {
	buff := make([]byte, 0, 1000)
	k := []byte("1234567890abcdef")

	var b byte = 0
	for i := 0; i < cap(buff); i++ {
		b++
		buff = append(buff, b)

		out, err := Encrypt(buff, k)
		if err != nil {
			t.Error("encrpyt", err)
			return
		}
		out, err = Decrypt(out, k)
		if err != nil {
			t.Error("encrpyt", err)
			return
		}
		CheckBuff(buff, out, t)
	}
}

func Benchmark_Encrypt(b *testing.B) {
	buff := []byte("hello")
	k := []byte("1234567890123456")

	for i := 0; i < b.N; i++ {
		Encrypt(buff, k)
	}
}

func Benchmark_Decrypt(b *testing.B) {
	k := []byte("1234567890123456")

	for i := 0; i < b.N; i++ {
		buff := []byte{207, 101, 31, 130, 189, 135, 196, 204}
		Decrypt(buff, k)
	}
}

func Benchmark_AES(b *testing.B) {
	bankkey := []byte("1234567890123456")
	block, err := aes.NewCipher(bankkey)
	if err != nil {
		b.Error("bankCardEncrypt|NewCipher|%v", err)
	}
	blockSize := block.BlockSize()

	for i := 0; i < b.N; i++ {
		origData := PKCS5Padding([]byte("hello"), blockSize)

		c := len(origData) / blockSize
		crypted := make([]byte, len(origData))
		for i := 0; i < c; i++ {
			block.Encrypt(crypted[i*blockSize:i*blockSize+blockSize], origData[i*blockSize:i*blockSize+blockSize])
		}
	}
}
