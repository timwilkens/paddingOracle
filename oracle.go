package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var blockSize = 16

func main() {
	cipher := getCipher()
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

	fmt.Println(data)
	blocks := breakIntoBlocks(data)
	realIV := blocks[0]
	fmt.Println("IV ", realIV)
	blocks = blocks[1:]
	for i := 0; i < len(blocks); i++ {
		fmt.Println(blocks[i])
	}

	var solved []byte

	for currentBlock := len(blocks) - 1; currentBlock >= 0; currentBlock-- {

		// Last block first
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
	}
	for i := len(solved) - 1; i >= 0; i-- {
		fmt.Print(string(solved[i]))
	}
	fmt.Println()
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
