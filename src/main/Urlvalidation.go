package main

import (
	"WXConnect/src/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	token       = "aidogijaieoj293u98e08ha98yv740y9"
	appID       = "wx2a08c65012d0777d"
	encodingKey = "lVI2zz4rR1qTQnoto90tlo3iEoh1uKfxOqACAuvhrAT"
)

var aesKey []byte

func encodingAESKey2AESKey(encodingKey string) []byte {
	data, _ := base64.StdEncoding.DecodeString(encodingKey + "=")
	return data
}

func makeSignature(timestamp, nonce string) string {
	sl := []string{token, timestamp, nonce}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

func validateUrl(w http.ResponseWriter, r *http.Request) bool {
	timestamp := strings.Join(r.Form["timestamp"], "")
	nonce := strings.Join(r.Form["nonce"], "")
	signatureGen := makeSignature(timestamp, nonce)
	signatureIn := strings.Join(r.Form["signature"], "")
	if signatureGen != signatureIn {
		return false
	}
	echostr := strings.Join(r.Form["echostr"], "")
	fmt.Fprintf(w, echostr)
	return true
}

func aesDecrypt(cipherData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey) //PKCS#7
	if len(cipherData)%k != 0 {
		return nil, errors.New("crypto/cipher: ciphertext size is not multiple of aes key length")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plainData, cipherData)
	return plainData, nil
}

func procRequest(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	encryptType := strings.Join(r.Form["encrypt_type"], "")
	msgSignature := strings.Join(r.Form["msg_signature"], "")
	nonce := strings.Join(r.Form["nonce"], "")
	timestamp := strings.Join(r.Form["timestamp"], "")

	if !validateUrl(w, r) {
		log.Println("Wechat Service: this http request is not from Wechat platform!")
		return
	}

	if r.Method == "POST" {
		if encryptType == "aes" {
			fmt.Println("wx in safe model")
			fmt.Println("msgSignature = ", msgSignature)
			aesKey = encodingAESKey2AESKey(encodingKey)

			encryptRequestBody := models.ParseEncryptRequestBody(r)
			// Decode base64
			cipherData, err := base64.StdEncoding.DecodeString(encryptRequestBody.Encrypt)
			if err != nil {
				log.Println("Wechat Service: Decode base64 error:", err)
				return
			}

			// AES Decrypt
			plainData, err := aesDecrypt(cipherData, aesKey)
			if err != nil {
				fmt.Println(err)
				return
			}

			//Xml decoding
			textRequestBody, _ := models.ParseEncryptTextRequestBody(plainData, appID)
			fmt.Printf("user:%s\ncontent:%s\n", textRequestBody.FromUserName, textRequestBody.Content)

			num, result := isContainKeyWord(textRequestBody.Content)
			response := ""
			if result == true {
				fmt.Println("num = ", num)
				response = "conversion " + strconv.Itoa(num) + " integral"
			} else {
				fmt.Println("num = ", num)
				response = "do you want to conversion integral"
			}

			fmt.Println("response = ", response)
			responseEncryptTextBody, _ := models.MakeEncryptResponseBody(textRequestBody.ToUserName,
				textRequestBody.FromUserName,
				response,
				nonce, timestamp, appID, aesKey, token)
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, string(responseEncryptTextBody))
		}
	}
}

func isContainKeyWord(word string) (int, bool) {
	subString := substring(word, len([]rune(word))-2, len([]rune(word)))
	numString := substring(word, 0, len([]rune(word))-2)
	if subString == "积分" {
		num, err := strconv.Atoi(numString)
		if err != nil {
			fmt.Println("not a number,num = ", num)
			return num, false
		} else {
			fmt.Println("is number,num = ", num)
			return num, true
		}
	}
	return 0, false
}

func substring(source string, start int, end int) string {
	var r = []rune(source)
	length := len(r)

	if start < 0 || end > length || start > end {
		return ""
	}

	if start == 0 && end == length {
		return source
	}

	return string(r[start:end])
}

func main() {
	log.Println("Wechat Service: Start!")
	http.HandleFunc("/wx_exc_integral", procRequest)
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal("Wechat Service: ListenAndServe failed, ", err)
	}
	log.Println("Wechat Service: Stop!")
}
