package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var blockSize = 16
var emptyBytes = []byte("")

func main() {
	cipher := getCipher()
	fmt.Println("ciphertext>> ", cipher)
	data, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		fmt.Println(err)
	}

	if len(data)%blockSize != 0 {
		panic("BAD LENGTH")
	}

	doOracle(data)
}

func doOracle(data []byte) {

	blocks := breakIntoBlocks(data)
	fmt.Println("Decrypting", len(blocks), "blocks")
	realIV := blocks[0]
	blocks = blocks[1:]

	var solved []byte

	for currentBlock := len(blocks) - 1; currentBlock >= 0; currentBlock-- {
		fmt.Println("Decoding block", currentBlock)

		block := blocks[currentBlock]
		intermediates := make(map[int]byte)

		for currentByte := blockSize - 1; currentByte >= 0; currentByte-- {

			// Initialize empty iv
			var iv []byte
			for i := 0; i < blockSize; i++ {
				iv = append(iv, 0x00)
			}

			numPad := blockSize - currentByte

			for i, value := range intermediates {
				iv[i] = (value ^ byte(numPad))
			}

			var intermediate byte

			for lastByte := 0; lastByte < 256; lastByte++ {
				iv[currentByte] = byte(lastByte)
				ciphertext := append([]byte(nil), iv...)
				ciphertext = append(ciphertext, block...)
				baseEncoded := base64.StdEncoding.EncodeToString(ciphertext)
				if validPadding(baseEncoded) {

					intermediate = byte(lastByte) ^ byte(blockSize-currentByte)
					intermediates[currentByte] = intermediate
					var decrypted byte
					if currentBlock == 0 {
						decrypted = (intermediate ^ realIV[currentByte])
					} else {
						decrypted = (intermediate ^ blocks[currentBlock-1][currentByte])
					}
					solved = append(solved, decrypted)
				}
			}
		}
		depadded, _ := stripPadding(reverse(solved))
		fmt.Println(">> ", string(depadded))
	}
	solved, err := stripPadding(reverse(solved))
	if err != nil {
		panic("Got plaintext with bad padding!")
	}
	fmt.Println("Plaintext:")
	fmt.Println(string(solved))
}

func reverse(slice []byte) []byte {
	numItems := len(slice)
	reversed := make([]byte, numItems)
	for i := 0; i < len(slice); i++ {
		reversed[i] = slice[numItems-1-i]
	}
	return reversed
}

func breakIntoBlocks(ciphertext []byte) [][]byte {
	if len(ciphertext)%blockSize != 0 {
		panic("bad blocksize in call to breakIntoBlocks")
	}
	numBlocks := len(ciphertext) / blockSize
	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		b := make([]byte, blockSize)
		b = ciphertext[i*blockSize : i*blockSize+blockSize]
		blocks[i] = b
	}
	return blocks
}

func validPadding(cipher string) bool {
	requestURL := ("http://localhost:8080/decrypt?ciphertext=" + url.QueryEscape(cipher))
	resp, err := http.Get(requestURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if strings.Contains(string(body), "invalid padding") {
		return false
	} else {
		return true
	}
}

func getCipher() string {
	resp, err := http.Get("http://localhost:8080/generate")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
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
