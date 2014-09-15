package xxtea

/*
#include <stdio.h>

#define MX (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (k[p&3^e]^z);

long btea(int* v, int n, const int* k) {
    unsigned int z=v[n-1], y=v[0], sum=0, e, DELTA=0x9e3779b9;
    long p, q ;
    if (n > 1) {
        q = 6 + 52/n;
        while (q-- > 0) {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++) y = v[p+1], z = v[p] += MX;
            y = v[0];
            z = v[n-1] += MX;
        }
        return 0 ;
    } else if (n < -1) {
        n = -n;
        q = 6 + 52/n;
        sum = q*DELTA ;
        while (sum != 0) {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--) z = v[p-1], y = v[p] -= MX;
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        return 0;
    }
    return 1;
}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"
)

var (
	KeyError   = errors.New("key_error")
	ValueError = errors.New("value_error")
	XXTeaError = errors.New("xxtea_error")
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func Encrypt(v, k []byte) ([]byte, error) {
	if len(k) != 16 {
		return nil, KeyError
	}
	if len(v) < 8 {
		v = PKCS5Padding(v, 8)
	} else {
		v = PKCS5Padding(v, 4)
	}
	r := C.btea((*C.int)(unsafe.Pointer(&v[0])), C.int(len(v)/4), (*C.int)(unsafe.Pointer(&k[0])))
	if r != 0 {
		return nil, XXTeaError
	}
	return v, nil
}

func Decrypt(v, k []byte) ([]byte, error) {
	if len(k) != 16 {
		return nil, KeyError
	}
	r := C.btea((*C.int)(unsafe.Pointer(&v[0])), C.int(-len(v)/4), (*C.int)(unsafe.Pointer(&k[0])))
	if r != 0 {
		return nil, XXTeaError
	}
	return PKCS5UnPadding(v), nil
}

func main() {
	k := []byte("1234567890123456")
	v, err := Encrypt([]byte("hello"), k)
	fmt.Println(v, err)
	v, err = Decrypt(v, k)
	fmt.Printf("%s, %v\n", v, err)
}
