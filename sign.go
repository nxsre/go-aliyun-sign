package sign

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sign a request with application credentials (appKey, appSecret)
func Sign(req *http.Request, appKey, appSecret string) error {
	ts := time.Now().UnixNano() / 1000000
	req.Header.Set(HTTPHeaderCATimestamp, strconv.FormatInt(ts, 10))
	r := strconv.FormatInt(time.Now().UnixNano(), 10)
	req.Header.Set(HTTPHeaderCANonce, r)
	req.Header.Set(HTTPHeaderCAKey, appKey)

	str, hdrKeys, err := buildStringToSign(req)
	if err != nil {
		return err
	}
	log.Printf("Sign string: %s", str)
	log.Printf("Signed Headers: %+v", hdrKeys)
	hasher := hmac.New(sha256.New, []byte(appSecret))
	hasher.Write([]byte(str))
	hash := base64.StdEncoding.EncodeToString(hasher.Sum([]byte{}))
	log.Printf("Signature: %s", hash)

	req.Header.Set(HTTPHeaderCASignature, hash)
	req.Header.Set(HTTPHeaderCASignatureHeaders, strings.Join(hdrKeys, ","))
	return nil
}

// SignServerRequest a request with application credentials (appKey, appSecret)
func SignRequest(req *http.Request, appKey, appSecret string) (*http.Request, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	tmpReq := req.Clone(req.Context())

	// clone body
	req.Body = io.NopCloser(bytes.NewReader(body))
	tmpReq.Body = io.NopCloser(bytes.NewReader(body))

	ts := time.Now().UnixNano() / 1000000
	tmpReq.Header.Set(HTTPHeaderCATimestamp, strconv.FormatInt(ts, 10))
	r := strconv.FormatInt(time.Now().UnixNano(), 10)
	tmpReq.Header.Set(HTTPHeaderCANonce, r)
	tmpReq.Header.Set(HTTPHeaderCAKey, appKey)

	str, hdrKeys, err := buildStringToSign(tmpReq)
	if err != nil {
		return nil, err
	}
	log.Printf("Sign string: %s", str)
	log.Printf("Signed Headers: %+v", hdrKeys)
	hasher := hmac.New(sha256.New, []byte(appSecret))
	hasher.Write([]byte(str))
	hash := base64.StdEncoding.EncodeToString(hasher.Sum([]byte{}))
	log.Printf("Signature: %s", hash)

	//req.Header.Set(HTTPHeaderCASignature, hash)
	//req.Header.Set(HTTPHeaderCASignatureHeaders, strings.Join(hdrKeys, ","))
	return tmpReq, nil
}

func buildStringToSign(req *http.Request) (string, []string, error) {
	s := ""
	s += strings.ToUpper(req.Method) + "\n"

	s += req.Header.Get(HTTPHeaderAccept) + "\n"
	s += req.Header.Get(HTTPHeaderContentMD5) + "\n"
	s += req.Header.Get(HTTPHeaderContentType) + "\n"
	s += req.Header.Get(HTTPHeaderDate) + "\n"

	hdrStr, hdrKeys, err := buildHeaderStringToSign(req.Header)
	if err != nil {
		return "", nil, err
	}
	s += hdrStr

	paramStr, err := buildParamStringToSign(req)
	if err != nil {
		return "", nil, err
	}
	s += paramStr
	return s, hdrKeys, nil
}

func buildHeaderStringToSign(hdr http.Header) (string, []string, error) {
	sorted, sorter := sortedKeyValues(hdr, nil)
	defer headerSorterPool.Put(sorter)

	hdrList := make([]string, 0)
	hdrKeyList := make([]string, 0)
	for _, kv := range sorted {
		if len(kv.values) != 1 {
			return "", nil, fmt.Errorf("do not support list of header values")
		}
		if strings.HasPrefix(http.CanonicalHeaderKey(kv.key), HTTPHeaderCAPrefix) {
			hdrKeyList = append(hdrKeyList, kv.key)
			hdrList = append(hdrList, kv.key+":"+kv.values[0]+"\n")
		}
	}
	return strings.Join(hdrList, ""), hdrKeyList, nil
}

func buildParamStringToSign(req *http.Request) (string, error) {
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	newReq := *req
	req.Body = io.NopCloser(bytes.NewBuffer(buf))
	newReq.Body = io.NopCloser(bytes.NewBuffer(buf))

	if err := newReq.ParseForm(); err != nil {
		return "", err
	}

	sorted, sorter := sortedKeyValues(newReq.Form, nil)
	defer headerSorterPool.Put(sorter)

	paramList := make([]string, 0)
	for _, kv := range sorted {
		if len(kv.key) == 0 {
			continue
		}
		if len(kv.values) == 0 || len(kv.values[0]) == 0 {
			paramList = append(paramList, kv.key)
		} else if len(kv.values) == 1 {
			paramList = append(paramList, kv.key+"="+kv.values[0])
		} else {
			return "", fmt.Errorf("do not support list of form values")
		}
	}
	params := strings.Join(paramList, "&")
	if params != "" {
		params = "?" + params
	}
	return req.URL.Path + params, nil
}
