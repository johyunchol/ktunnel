package plugin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginRejectsOversizedOrControlMetadata(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	for name, content := range map[string]map[string]any{
		"hostname": {
			"hostname": strings.Repeat("h", maxHostnameBytes+1),
			"metas":    map[string]any{metaToken: "token"},
		},
		"control": {
			"hostname": "trusted\nforged log line",
			"metas":    map[string]any{metaToken: "token"},
		},
		"token": {
			"metas": map[string]any{metaToken: strings.Repeat("t", maxTokenBytes+1)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(content)
			if err != nil {
				t.Fatal(err)
			}
			resp := h.login(raw, req)
			if !resp.Reject || !strings.Contains(resp.RejectReason, "invalid") {
				t.Fatalf("response=%#v", resp)
			}
		})
	}
}

func TestProxyAndHeartbeatRejectOversizedMetadataBeforeStoreAccess(t *testing.T) {
	h := &Handler{}
	proxyRaw, err := json.Marshal(newProxyContent{
		User:      userInfo{RunID: strings.Repeat("r", maxRunIDBytes+1)},
		ProxyName: "proxy", ProxyType: "http", SubDomain: "valid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.newProxy(proxyRaw); !resp.Reject || resp.RejectReason != "invalid proxy request" {
		t.Fatalf("proxy response=%#v", resp)
	}

	pingRaw, err := json.Marshal(userOnlyContent{User: userInfo{
		Metas: map[string]string{"oversized": strings.Repeat("m", maxMetaValueBytes+1)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if resp := h.ping(pingRaw); !resp.Reject || resp.RejectReason != "malformed ping" {
		t.Fatalf("ping response=%#v", resp)
	}
}

func TestPluginRequestBodyIsBounded(t *testing.T) {
	h := &Handler{}
	body := io.MultiReader(
		strings.NewReader(`{"version":"1","op":"Ping","content":{"padding":"`),
		io.LimitReader(&infiniteA{}, (1<<20)+1),
		strings.NewReader(`"}}`),
	)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

type infiniteA struct{}

func (*infiniteA) Read(p []byte) (int, error) {
	return bytes.NewReader(bytes.Repeat([]byte{'a'}, len(p))).Read(p)
}
