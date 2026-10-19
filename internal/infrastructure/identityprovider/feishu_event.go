package identityprovider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Feishu signature and AES-CBC envelope follow the official Go SDK:
// https://github.com/larksuite/oapi-sdk-go/blob/v3_main/event/event.go
// https://open.feishu.cn/document/server-docs/contact-v3/user/events/deleted
type FeishuEventPolicy struct {
	Enabled                       bool
	AppID, TenantKey, WorkspaceID string
	VerificationToken, EncryptKey string
}

type FeishuEvent struct {
	Schema    string `json:"schema"`
	Type      string `json:"type"`
	Token     string `json:"token"`
	Challenge string `json:"challenge"`
	Header    struct {
		EventID   string `json:"event_id"`
		EventType string `json:"event_type"`
		Token     string `json:"token"`
		AppID     string `json:"app_id"`
		TenantKey string `json:"tenant_key"`
	} `json:"header"`
	Event struct {
		Object struct {
			UnionID string `json:"union_id"`
		} `json:"object"`
	} `json:"event"`
}

func (p FeishuEventPolicy) Ready() bool {
	return p.Enabled && p.AppID != "" && p.TenantKey != "" && p.WorkspaceID != "" && p.VerificationToken != "" && p.EncryptKey != ""
}

func (p FeishuEventPolicy) Verify(body []byte, headers http.Header, now time.Time) (FeishuEvent, error) {
	invalid := errors.New("invalid Feishu event")
	if !p.Ready() {
		return FeishuEvent{}, invalid
	}
	var envelope struct {
		Encrypt string `json:"encrypt"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Encrypt == "" {
		return FeishuEvent{}, invalid
	}
	encrypted, err := base64.StdEncoding.DecodeString(envelope.Encrypt)
	if err != nil || len(encrypted) < 2*aes.BlockSize || (len(encrypted)-aes.BlockSize)%aes.BlockSize != 0 {
		return FeishuEvent{}, invalid
	}
	key := sha256.Sum256([]byte(p.EncryptKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return FeishuEvent{}, invalid
	}
	plain := make([]byte, len(encrypted)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, encrypted[:aes.BlockSize]).CryptBlocks(plain, encrypted[aes.BlockSize:])
	// Official SDK extracts the JSON object from the decrypted padded frame.
	start, end := bytes.IndexByte(plain, '{'), bytes.LastIndexByte(plain, '}')
	if start < 0 || end < start {
		return FeishuEvent{}, invalid
	}
	var event FeishuEvent
	if json.Unmarshal(plain[start:end+1], &event) != nil {
		return FeishuEvent{}, invalid
	}
	equal := func(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
	if event.Type == "url_verification" {
		if !equal(event.Token, p.VerificationToken) || strings.TrimSpace(event.Challenge) == "" || len(event.Challenge) > 4096 {
			return FeishuEvent{}, invalid
		}
		return event, nil
	}
	timestamp, nonce, signature := headers.Get("X-Lark-Request-Timestamp"), headers.Get("X-Lark-Request-Nonce"), headers.Get("X-Lark-Signature")
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || nonce == "" || len(nonce) > 256 || seconds < now.Add(-5*time.Minute).Unix() || seconds > now.Add(5*time.Minute).Unix() {
		return FeishuEvent{}, invalid
	}
	digest := sha256.Sum256(append([]byte(timestamp+nonce+p.EncryptKey), body...))
	expected := hex.EncodeToString(digest[:])
	if !equal(signature, expected) || !equal(event.Header.Token, p.VerificationToken) || event.Schema != "2.0" || event.Header.AppID != p.AppID || event.Header.TenantKey != p.TenantKey || event.Header.EventID == "" {
		return FeishuEvent{}, invalid
	}
	if event.Header.EventType == "contact.user.deleted_v3" && strings.TrimSpace(event.Event.Object.UnionID) == "" {
		return FeishuEvent{}, invalid
	}
	return event, nil
}
