package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// BlockSize is 16

var key = []byte("example key 1234")
var plaintext = []byte("You know the thing about a shark, he’s got lifeless eyes. Black eyes like a doll’s eyes. When he comes at ya, he doesn’t seem to be living until he bites ya and those black eyes roll over and white and then, ah, then you hear that terrible high-pitch screaming. The ocean turns red and despite all the pounding and hollering, they all come in and they rip you to pieces.")
var emptyBytes = []byte("")
var blockSize = 16

func Generate(w http.ResponseWriter, r *http.Request) {
	ciphertext, err := encrypt(plaintext)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Something went wrong!", 500)
	}
	fmt.Fprintf(w, ciphertext)
}

func Decrypt(w http.ResponseWriter, r *http.Request) {
	ciphertext := r.URL.Query().Get("ciphertext")
	if ciphertext == "" {
		http.Error(w, "Ciphertext is required", 500)
	}
	_, err := decrypt(ciphertext)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), 500)
	}
	fmt.Fprintf(w, "OK")
}

func main() {
	http.HandleFunc("/generate", Generate)
	http.HandleFunc("/decrypt", Decrypt)
	http.ListenAndServe(":8080", nil)
}

// encrypt encrypts and returns base64 encoded version
func encrypt(plaintext []byte) (string, error) {

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	plaintext = pad(plaintext)
	if len(plaintext)%blockSize != 0 {
		return "", errors.New("Padding error")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func pad(plaintext []byte) []byte {
	// Pad a full block
	if len(plaintext)%blockSize == 0 {
		for i := 0; i < blockSize; i++ {
			plaintext = append(plaintext, byte(blockSize))
		}
		return plaintext
	}

	var padding int
	if len(plaintext) < blockSize {
		padding = blockSize - len(plaintext)
	} else {
		padding = blockSize - (len(plaintext) % blockSize)
	}
	for i := 0; i < padding; i++ {
		plaintext = append(plaintext, byte(padding))
	}

	return plaintext
}

func stripPadding(plaintext []byte) ([]byte, error) {

	paddingError := errors.New("invalid padding")
	lastByte := len(plaintext) - 1

	// Check for invalid padding values above block size
	if int(plaintext[lastByte]) > blockSize {
		return emptyBytes, paddingError
	}

	paddingValue := int(plaintext[lastByte])

	if paddingValue == 0 {
		return emptyBytes, paddingError
	}

	// check for padding values longer than string
	if paddingValue > len(plaintext) {
		return emptyBytes, paddingError
	}

	for checked := 0; checked < paddingValue; checked++ {
		if int(plaintext[len(plaintext)-1]) != paddingValue {
			return emptyBytes, paddingError
		}
		// Strip padding byte
		plaintext = plaintext[:len(plaintext)-1]
	}
	return plaintext, nil
}

func decrypt(encoded string) ([]byte, error) {

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return emptyBytes, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return emptyBytes, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return emptyBytes, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return emptyBytes, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	// Check padding
	return stripPadding(ciphertext)
}
