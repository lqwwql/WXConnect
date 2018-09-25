package models

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type TextRequestBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string
	FromUserName string
	CreateTime   time.Duration
	MsgType      string
	Content      string
	MsgId        int
}

type EncryptRequestBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string
	Encrypt    string
}

func ParseEncryptRequestBody(r *http.Request) *EncryptRequestBody {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	requestBody := &EncryptRequestBody{}
	xml.Unmarshal(body, requestBody)
	return requestBody
}

func ParseEncryptTextRequestBody(plainText []byte,appID string) (*TextRequestBody, error) {
	// Read length
	buf := bytes.NewBuffer(plainText[16:20])
	var length int32
	binary.Read(buf, binary.BigEndian, &length)

	// appID validation
	appIDstart := 20 + length
	id := plainText[appIDstart : int(appIDstart)+len(appID)]
	if !ValidateAppId(id,appID) {
		log.Println("Wechat Service: appid is invalid!")
		return nil, errors.New("Appid is invalid")
	}
	log.Println("Wechat Service: appid validation is ok!")

	// xml Decoding
	textRequestBody := &TextRequestBody{}
	xml.Unmarshal(plainText[20:20+length], textRequestBody)
	return textRequestBody, nil
}

func ValidateAppId(id []byte,appID string)bool{
	appid := string(id)
	if appid == appID{
		return true
	}
	return false
}

