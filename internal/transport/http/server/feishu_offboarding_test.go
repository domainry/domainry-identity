package httpserver

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/identityprovider"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestVerifiedFeishuOffboardingArchivesOnlyLinkedUserAndIsIdempotent(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "offboarding.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "domainry.template.json"))
	cfg.AuthFeishuOffboardingEnabled = true
	cfg.AuthFeishuOffboardingAppID = "test-app"
	cfg.AuthFeishuOffboardingTenantKey = "test-tenant"
	cfg.AuthFeishuOffboardingWorkspaceID = "workspace-primary"
	cfg.AuthFeishuEventVerificationToken = "test-token"
	cfg.AuthFeishuEventEncryptKey = "test-encryption-key"
	server, err := New(t.Context(), cfg, testServerAssemblyOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseContext(t.Context())
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	for _, id := range []string{"departed", "unlinked-same-email", "untouched"} {
		if err := server.core.Identity.UpsertUser(ctx, identitymodel.IdentityUser{ID: id, Name: id, Email: id + "@example.test", Status: identitymodel.IdentityStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.core.Auth.BindExternalAccount(ctx, "workspace-primary", "departed", authmodel.AuthExternalIdentityAssertion{Provider: "feishu", Subject: "union-departed"}); err != nil {
		t.Fatal(err)
	}
	event := identityprovider.FeishuEvent{Schema: "2.0"}
	event.Header.EventID = "offboarding-event"
	event.Header.EventType = "contact.user.deleted_v3"
	event.Header.Token = cfg.AuthFeishuEventVerificationToken
	event.Header.AppID = cfg.AuthFeishuOffboardingAppID
	event.Header.TenantKey = cfg.AuthFeishuOffboardingTenantKey
	event.Event.Object.UnionID = "union-departed"
	send := func(e identityprovider.FeishuEvent, forge bool) int {
		t.Helper()
		plain, _ := json.Marshal(e)
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
		key := sha256.Sum256([]byte(cfg.AuthFeishuEventEncryptKey))
		block, _ := aes.NewCipher(key[:])
		frame := make([]byte, aes.BlockSize+len(plain))
		copy(frame, []byte("fixture-iv-12345"))
		cipher.NewCBCEncrypter(block, frame[:aes.BlockSize]).CryptBlocks(frame[aes.BlockSize:], plain)
		body, _ := json.Marshal(map[string]string{"encrypt": base64.StdEncoding.EncodeToString(frame)})
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "nonce"
		signature := sha256.Sum256(append([]byte(ts+nonce+cfg.AuthFeishuEventEncryptKey), body...))
		request := httptest.NewRequest("POST", "/auth/providers/feishu/events", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Lark-Request-Timestamp", ts)
		request.Header.Set("X-Lark-Request-Nonce", nonce)
		request.Header.Set("X-Lark-Signature", hex.EncodeToString(signature[:]))
		if forge {
			request.Header.Set("X-Lark-Signature", "forged")
		}
		response := httptest.NewRecorder()
		server.Routes().ServeHTTP(response, request)
		return response.Code
	}
	if code := send(event, true); code != 403 {
		t.Fatalf("forged event status=%d", code)
	}
	wrongTenant := event
	wrongTenant.Header.TenantKey = "other-tenant"
	if code := send(wrongTenant, false); code != 403 {
		t.Fatalf("wrong tenant status=%d", code)
	}
	unknown := event
	unknown.Event.Object.UnionID = "unlinked-same-email"
	if code := send(unknown, false); code != 200 {
		t.Fatalf("unknown identity status=%d", code)
	}
	for _, id := range []string{"departed", "unlinked-same-email", "untouched"} {
		user, found, err := server.core.Identity.UserByID(ctx, id)
		if err != nil || !found || user.Status != identitymodel.IdentityStatusActive {
			t.Fatal("unverified or unknown subject changed an account")
		}
	}
	if code := send(event, false); code != 200 {
		t.Fatalf("verified event status=%d", code)
	}
	user, found, err := server.core.Identity.UserByID(ctx, "departed")
	if err != nil || !found || user.Status != identitymodel.IdentityStatusDeleted {
		t.Fatalf("offboarding did not archive linked identity: %+v %v", user, err)
	}
	version := user.Version
	if code := send(event, false); code != 200 {
		t.Fatalf("duplicate delivery status=%d", code)
	}
	user, _, _ = server.core.Identity.UserByID(ctx, "departed")
	if user.Version != version {
		t.Fatal("duplicate event mutated account again")
	}
	linked, found, err := server.core.Auth.LinkedExternalIdentityUser(ctx, "workspace-primary", "feishu", "union-departed")
	if err != nil || !found || linked != "departed" {
		t.Fatal("external identity tombstone lost")
	}
	if _, err := server.core.Auth.ExternalLogin(ctx, "workspace-primary", authmodel.AuthExternalIdentityAssertion{Provider: "feishu", Subject: "union-departed"}, true); err == nil {
		t.Fatal("deleted Feishu account was recreated or logged in")
	}
	for _, id := range []string{"unlinked-same-email", "untouched"} {
		other, _, _ := server.core.Identity.UserByID(ctx, id)
		if other.Status != identitymodel.IdentityStatusActive {
			t.Fatal("unrelated account affected")
		}
	}
}
