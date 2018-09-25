package models

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type TextResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATAText
	FromUserName CDATAText
	CreateTime   string
	MsgType      CDATAText
	Content      CDATAText
}


type EncryptResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      CDATAText
	MsgSignature CDATAText
	TimeStamp    string
	Nonce        CDATAText
}

func MakeEncryptResponseBody(fromUserName, toUserName, content, nonce, timestamp string,appID string,aesKey []byte,token string) ([]byte, error) {
	encryptBody := &EncryptResponseBody{}
	encryptXmlData, _ := makeEncryptXmlData(fromUserName, toUserName, timestamp, content,appID,aesKey)
	encryptBody.Encrypt = Value2CDATA(encryptXmlData)
	encryptBody.MsgSignature = Value2CDATA(makeMsgSignature(timestamp, nonce, encryptXmlData,token))
	encryptBody.TimeStamp = timestamp
	encryptBody.Nonce = Value2CDATA(nonce)
	return xml.MarshalIndent(encryptBody, " ", "  ")
}

func makeEncryptXmlData(fromUserName, toUserName, timestamp, content string,appID string,aesKey []byte) (string, error) {
	// Encrypt part3: Xml Encoding
	textResponseBody := &TextResponseBody{}
	textResponseBody.FromUserName = Value2CDATA(fromUserName)
	textResponseBody.ToUserName = Value2CDATA(toUserName)
	textResponseBody.MsgType = Value2CDATA("text")
	textResponseBody.Content = Value2CDATA(content)
	textResponseBody.CreateTime = timestamp
	body, err := xml.MarshalIndent(textResponseBody, " ", "  ")
	if err != nil {
		return "", errors.New("xml marshal error")
	}

	// Encrypt part2: Length bytes
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, int32(len(body)))
	if err != nil {
		fmt.Println("Binary write err:", err)
	}
	bodyLength := buf.Bytes()

	// Encrypt part1: Random bytes
	randomBytes := []byte("abcdefghijklmnop")

	// Encrypt Part, with part4 - appID
	plainData := bytes.Join([][]byte{randomBytes, bodyLength, body, []byte(appID)}, nil)
	cipherData, err := aesEncrypt(plainData, aesKey)
	if err != nil {
		return "", errors.New("aesEncrypt error")
	}

	return base64.StdEncoding.EncodeToString(cipherData), nil
}


func makeMsgSignature(timestamp, nonce, msg_encrypt string,token string) string {
	sl := []string{token, timestamp, nonce, msg_encrypt}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

func aesEncrypt(plainData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey)
	if len(plainData)%k != 0 {
		plainData = PKCS7Pad(plainData, k)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipherData := make([]byte, len(plainData))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cipherData, plainData)

	return cipherData, nil
}

func PKCS7Pad(message []byte, blocksize int) (padded []byte) {
	// block size must be bigger or equal 2
	if blocksize < 1<<1 {
		panic("block size is too small (minimum is 2 bytes)")
	}
	// block size up to 255 requires 1 byte padding
	if blocksize < 1<<8 {
		// calculate padding length
		padlen := PadLength(len(message), blocksize)

		// define PKCS7 padding block
		padding := bytes.Repeat([]byte{byte(padlen)}, padlen)

		// apply padding
		padded = append(message, padding...)
		return padded
	}
	// block size bigger or equal 256 is not currently supported
	panic("unsupported block size")
}

func PadLength(slice_length, blocksize int) (padlen int) {
	padlen = blocksize - slice_length%blocksize
	if padlen == 0 {
		padlen = blocksize
	}
	return padlen
}
