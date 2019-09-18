package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/walkert/go-evp"
)

// RandomString is a simple function to generate a random string of a defined
// length for use as salt/password
func RandomString(length int) string {
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		rn, err := rand.Int(rand.Reader, big.NewInt(57))
		if err != nil {
			panic(err) // out of randomness, should never happen
		}
		bytes[i] = byte(65 + int(rn.Int64()))
	}
	return string(bytes)
}

// EncryptString encrypts the string data with the salt and password and returns
// the encrypted bytes
func EncryptString(data, salt, pass string) ([]byte, error) {
	return EncryptBytes([]byte(data), salt, pass)
}

// EncryptBytes encrypts the byte data with the salt and password and returns
// the encrypted bytes
func EncryptBytes(data []byte, salt, pass string) ([]byte, error) {
	// make a local copy of data
	ldata := make([]byte, len(data))
	copy(ldata, data)
	key, iv := evp.BytesToKey256([]byte(salt), []byte(pass), 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ldata = pKCS5Padding(ldata, block.BlockSize())
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ldata, ldata)
	return ldata, nil
}

// DecryptString decrypts the string data with the salt and password and returns
// the decrypted bytes
func DecryptString(data, salt, pass string) ([]byte, error) {
	return DecryptBytes([]byte(data), salt, pass)
}

// DecryptBytes decrypts the byte data with the salt and password and returns
// the decrypted bytes
func DecryptBytes(data []byte, salt, pass string) ([]byte, error) {
	// make a local copy of data
	ldata := make([]byte, len(data))
	copy(ldata, data)
	key, iv := evp.BytesToKey256([]byte(salt), []byte(pass), 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ldata, ldata)
	errVal := fmt.Errorf("data could not be decrypted - bad salt/pass")
	// Don't try and unpad an empty byte slice
	if len(ldata) == 0 {
		return nil, errVal
	}
	d, err := pKCS5UnPadding(ldata, block.BlockSize())
	if err != nil {
		return nil, errVal
	}
	return d, nil
}

// pKCS5Padding returns a modified byte slice of src which has been padded to blockSize
func pKCS5Padding(src []byte, blockSize int) []byte {
	// Always pad. Even if the length of the src bytes == blockSize, pad another blockSize count of bytes
	// This ensures we can safely unpad on the other side.
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// pKCS5UnPadding returns a modified byte slice of src which has been stripped of blockSize padding
func pKCS5UnPadding(src []byte, blockSize int) ([]byte, error) {
	srcLen := len(src)
	// Since we always pad, take the integer value of the last byte and trim off that many bytes
	paddingLen := int(src[srcLen-1])
	if paddingLen >= srcLen || paddingLen > blockSize {
		return nil, fmt.Errorf("unexpected padding size\n")
	}
	return src[:srcLen-paddingLen], nil
}
