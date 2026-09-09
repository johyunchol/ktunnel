package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseStableSemver(t *testing.T) {
	tests := []struct {
		value string
		want  semver
		ok    bool
	}{
		{"v1.2.3", semver{1, 2, 3}, true},
		{"1.2.3", semver{1, 2, 3}, true},
		{"v0.4.0", semver{0, 4, 0}, true},
		{"dev", semver{}, false},
		{"v1.2.3-rc.1", semver{}, false},
		{"1.2.3+build", semver{}, false},
		{"1.02.3", semver{}, false},
		{"1.2", semver{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, ok := parseStableSemver(tt.value)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseStableSemver(%q) = %v, %v; want %v, %v", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
	if newer, ok := newerVersion("v1.9.9", "v1.10.0"); !ok || !newer {
		t.Fatal("expected v1.10.0 to be newer")
	}
	if newer, ok := newerVersion("v2.0.0", "v1.99.99"); !ok || newer {
		t.Fatal("expected v1.99.99 not to be newer")
	}
}

func TestLatestUsesGitHubHeadersWithoutLeakingToken(t *testing.T) {
	const secret = "secret-token-value"
	var gotAuth, gotAccept, gotVersion, gotAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotAgent = r.Header.Get("User-Agent")
		io.WriteString(w, `{"tag_name":"v1.2.3","html_url":"https://example.test/release","assets":[]}`)
	}))
	defer srv.Close()

	u := testUpdater(t, srv.URL)
	rel, err := u.latest(context.Background(), secret)
	if err != nil || rel.TagName != "v1.2.3" {
		t.Fatalf("latest = %#v, %v", rel, err)
	}
	if gotAuth != "Bearer "+secret || gotAccept != "application/vnd.github+json" || gotVersion != githubAPIVersion || gotAgent != "ktunnel/v1.0.0" {
		t.Fatalf("unexpected headers: auth=%q accept=%q version=%q agent=%q", gotAuth, gotAccept, gotVersion, gotAgent)
	}
	if strings.Contains(u.stderr.(*strings.Builder).String(), secret) {
		t.Fatal("token leaked to output")
	}
	entries, err := os.ReadDir(filepath.Dir(mustCachePath(t, u)))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		b, _ := os.ReadFile(filepath.Join(filepath.Dir(mustCachePath(t, u)), entry.Name()))
		if strings.Contains(string(b), secret) {
			t.Fatal("token persisted to cache")
		}
	}
}

func TestLatestAndDownloadWorkWithoutAuthentication(t *testing.T) {
	var releaseAuth, assetAuth string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			releaseAuth = r.Header.Get("Authorization")
			fmt.Fprintf(w, `{"tag_name":"v1.2.3","html_url":"%s/release","assets":[{"name":"asset","url":"%s/asset","size":4}]}`, srv.URL, srv.URL)
		case "/asset":
			assetAuth = r.Header.Get("Authorization")
			io.WriteString(w, "data")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	rel, err := u.latest(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	asset, ok := findAsset(rel, "asset")
	if !ok {
		t.Fatal("release asset missing")
	}
	var out strings.Builder
	if err := u.download(context.Background(), asset, "", 10, &out); err != nil {
		t.Fatal(err)
	}
	if releaseAuth != "" || assetAuth != "" || out.String() != "data" {
		t.Fatalf("release auth=%q asset auth=%q data=%q", releaseAuth, assetAuth, out.String())
	}
}

func TestGitHubTokenEnvironmentPrecedence(t *testing.T) {
	t.Setenv("GH_TOKEN", " primary-token \n")
	t.Setenv("GITHUB_TOKEN", "secondary-token")
	got, err := githubToken(context.Background())
	if err != nil || got != "primary-token" {
		t.Fatalf("githubToken = %q, %v", got, err)
	}
}

func TestGitHubTokenIsOptional(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("PATH", t.TempDir())
	got, err := githubToken(context.Background())
	if err != nil || got != "" {
		t.Fatalf("githubToken without auth = %q, %v", got, err)
	}
}

func TestReplaceEnvRemovesDuplicateValues(t *testing.T) {
	got := replaceEnv([]string{"A=1", "KTUNNEL_UPDATE_PREFLIGHT=0", "KTUNNEL_UPDATE_PREFLIGHT=old"}, "KTUNNEL_UPDATE_PREFLIGHT", "1")
	want := []string{"A=1", "KTUNNEL_UPDATE_PREFLIGHT=1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("replaceEnv = %q, want %q", got, want)
	}
}

func TestAssetSelectionAndChecksums(t *testing.T) {
	rel := &githubRelease{Assets: []releaseAsset{{Name: "ktunnel-linux-amd64", Digest: "sha256:" + strings.Repeat("a", 64)}}}
	a, ok := findAsset(rel, "ktunnel-linux-amd64")
	if !ok || a.Name != "ktunnel-linux-amd64" {
		t.Fatal("exact asset was not selected")
	}
	if _, ok := findAsset(rel, "ktunnel-linux-arm64"); ok {
		t.Fatal("wrong architecture asset matched")
	}
	sums := []byte(strings.Repeat("b", 64) + "  ktunnel-linux-amd64\n" + strings.Repeat("c", 64) + " *other\n")
	if got, err := checksumFor(sums, "ktunnel-linux-amd64"); err != nil || got != strings.Repeat("b", 64) {
		t.Fatalf("checksumFor = %q, %v", got, err)
	}
	if _, err := checksumFor(sums, "missing"); err == nil || !strings.Contains(err.Error(), "없습니다") {
		t.Fatalf("missing checksum error = %v", err)
	}
	duplicate := append(append([]byte{}, sums...), []byte(strings.Repeat("d", 64)+"  ktunnel-linux-amd64\n")...)
	if _, err := checksumFor(duplicate, "ktunnel-linux-amd64"); err == nil || !strings.Contains(err.Error(), "중복") {
		t.Fatalf("duplicate checksum error = %v", err)
	}
}

func TestExpectedChecksumFallsBackToSHA256SUMS(t *testing.T) {
	binary := releaseAsset{Name: "ktunnel-linux-amd64"}
	want := strings.Repeat("d", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/octet-stream" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		io.WriteString(w, want+"  "+binary.Name+"\n")
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	rel := &githubRelease{Assets: []releaseAsset{{Name: "SHA256SUMS", URL: srv.URL, Size: 100}}}
	got, err := u.expectedChecksum(context.Background(), rel, binary, "token")
	if err != nil || got != want {
		t.Fatalf("expectedChecksum = %q, %v", got, err)
	}
}

func TestDownloadRejectsOversizeAndForeignAPIHost(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, "data")
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	err := u.download(context.Background(), releaseAsset{Name: "large", URL: srv.URL, Size: 11}, "token", 10, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "크기") {
		t.Fatalf("oversize error = %v", err)
	}
	err = u.download(context.Background(), releaseAsset{Name: "foreign", URL: "https://example.test/asset", Size: 4}, "token", 10, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "GitHub API 주소") {
		t.Fatalf("foreign-host error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid downloads made %d requests", requests.Load())
	}
}

func TestAssetRedirectDoesNotForwardAuthorizationToAnotherHost(t *testing.T) {
	var destinationAuth string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationAuth = r.Header.Get("Authorization")
		io.WriteString(w, "data")
	}))
	defer destination.Close()
	// A different hostname forces net/http's redirect policy to strip sensitive
	// headers even though both test servers resolve locally.
	destinationURL := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destinationURL, http.StatusFound)
	}))
	defer source.Close()
	u := testUpdater(t, source.URL)
	var out strings.Builder
	if err := u.download(context.Background(), releaseAsset{Name: "asset", URL: source.URL, Size: 4}, "very-secret", 10, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "data" {
		t.Fatalf("download = %q", out.String())
	}
	if destinationAuth != "" {
		t.Fatalf("Authorization leaked across redirect: %q", destinationAuth)
	}
}

func TestAssetRedirectNeverForwardsAuthorization(t *testing.T) {
	var firstAuth, redirectedAuth string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/asset":
			firstAuth = r.Header.Get("Authorization")
			http.Redirect(w, r, srv.URL+"/content", http.StatusFound)
		case "/content":
			redirectedAuth = r.Header.Get("Authorization")
			io.WriteString(w, "data")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	var out strings.Builder
	if err := u.download(context.Background(), releaseAsset{Name: "asset", URL: srv.URL + "/asset", Size: 4}, "very-secret", 10, &out); err != nil {
		t.Fatal(err)
	}
	if firstAuth != "Bearer very-secret" {
		t.Fatalf("initial Authorization = %q", firstAuth)
	}
	if redirectedAuth != "" {
		t.Fatalf("Authorization leaked on same-origin redirect: %q", redirectedAuth)
	}
}

func TestInstallAtomicSuccess(t *testing.T) {
	old := []byte("old executable")
	newBinary := []byte("#!/bin/sh\nprintf 'ktunnel v2.0.0\\n'\n")
	u, rel, target, closeServer := updateFixture(t, old, newBinary, false)
	defer closeServer()
	if err := u.install(context.Background(), rel, "token"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(newBinary) {
		t.Fatalf("target = %q, %v", got, err)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0751 {
		t.Fatalf("mode = %o, want 751", info.Mode().Perm())
	}
	assertTargetAndNoUpdateFiles(t, target, newBinary)
}

func TestPreflightFailureLeavesExecutableUntouched(t *testing.T) {
	old := []byte("old executable")
	bad := []byte("#!/bin/sh\nprintf 'not ktunnel\\n'\n")
	u, rel, target, closeServer := updateFixture(t, old, bad, false)
	defer closeServer()
	err := u.install(context.Background(), rel, "token")
	if err == nil || !strings.Contains(err.Error(), "사전 검사 실패") {
		t.Fatalf("expected preflight failure, got %v", err)
	}
	assertTargetAndNoUpdateFiles(t, target, old)
}

func TestPostReplaceFailureRollsBack(t *testing.T) {
	old := []byte("old executable")
	newBinary := []byte("#!/bin/sh\nprintf 'ktunnel v2.0.0\\n'\n")
	u, rel, target, closeServer := updateFixture(t, old, newBinary, false)
	defer closeServer()
	var calls atomic.Int32
	u.verify = func(context.Context, string, string) error {
		if calls.Add(1) == 1 {
			return nil
		}
		return fmt.Errorf("simulated post-replace failure")
	}
	err := u.install(context.Background(), rel, "token")
	if err == nil || !strings.Contains(err.Error(), "롤백") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	assertTargetAndNoUpdateFiles(t, target, old)
}

func TestConcurrentExplicitUpdateIsRejected(t *testing.T) {
	old := []byte("old executable")
	newBinary := []byte("#!/bin/sh\nprintf 'ktunnel v2.0.0\\n'\n")
	u, rel, target, closeServer := updateFixture(t, old, newBinary, false)
	defer closeServer()
	lockPath := filepath.Join(filepath.Dir(target), ".ktunnel-update.lock")
	if err := os.WriteFile(lockPath, []byte("active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := u.install(context.Background(), rel, "token")
	if err == nil || !strings.Contains(err.Error(), "진행 중") {
		t.Fatalf("expected concurrent update rejection, got %v", err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	assertTargetAndNoUpdateFiles(t, target, old)
}

func TestChecksumMismatchLeavesExecutableUntouched(t *testing.T) {
	old := []byte("old executable")
	u, rel, target, closeServer := updateFixture(t, old, []byte("tampered"), true)
	defer closeServer()
	err := u.install(context.Background(), rel, "token")
	if err == nil || !strings.Contains(err.Error(), "체크섬 불일치") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(old) {
		t.Fatalf("existing executable changed: %q", got)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".ktunnel-update-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func assertTargetAndNoUpdateFiles(t *testing.T, target string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(want) {
		t.Fatalf("target = %q, %v; want %q", got, err, want)
	}
	for _, pattern := range []string{".ktunnel-update-*", ".ktunnel-backup-*"} {
		matches, _ := filepath.Glob(filepath.Join(filepath.Dir(target), pattern))
		if len(matches) != 0 {
			t.Fatalf("files left behind: %v", matches)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), ".ktunnel-update.lock")); !os.IsNotExist(err) {
		t.Fatalf("update lock left behind: %v", err)
	}
}

func TestInstallErrorsDoNotModifyTarget(t *testing.T) {
	u := testUpdater(t, "http://unused")
	u.executable = func() (string, error) { return filepath.Join(t.TempDir(), "missing"), nil }
	err := u.install(context.Background(), &githubRelease{TagName: "v2.0.0"}, "token")
	if err == nil || !strings.Contains(err.Error(), "현재 실행 파일") {
		t.Fatalf("unexpected error: %v", err)
	}
	u.goos = "windows"
	err = u.install(context.Background(), &githubRelease{TagName: "v2.0.0", HTMLURL: "https://example.test/release"}, "token")
	if err == nil || !strings.Contains(err.Error(), "Windows") || !strings.Contains(err.Error(), "https://example.test/release") {
		t.Fatalf("unexpected Windows error: %v", err)
	}
	u.goos = "linux"
	uvPath := filepath.Join(t.TempDir(), "uv", "tools", "ktunnel", "bin", "ktunnel")
	if err := os.MkdirAll(filepath.Dir(uvPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uvPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	u.executable = func() (string, error) { return uvPath, nil }
	if err := u.install(context.Background(), &githubRelease{}, "token"); err == nil || !strings.Contains(err.Error(), "--uv") {
		t.Fatalf("unexpected uv error: %v", err)
	}
}

func TestPassiveCacheTTLAndCorruption(t *testing.T) {
	u := testUpdater(t, "http://unused")
	now := time.Unix(2_000_000_000, 0)
	u.now = func() time.Time { return now }
	if !u.claimPassiveCheck() {
		t.Fatal("first check was not claimed")
	}
	if u.claimPassiveCheck() {
		t.Fatal("second check inside TTL was claimed")
	}
	now = now.Add(24*time.Hour + time.Second)
	if !u.claimPassiveCheck() {
		t.Fatal("expired cache was not claimed")
	}
	path := mustCachePath(t, u)
	if err := os.WriteFile(path, []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !u.claimPassiveCheck() {
		t.Fatal("corrupt cache should trigger a fresh check")
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "token") {
		t.Fatal("cache unexpectedly contains credentials")
	}
}

func TestPassiveCheckIsNonfatalAndDoesNotRepeatNetwork(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	u.passive(context.Background())
	u.passive(context.Background())
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if got := u.stderr.(*strings.Builder).String(); got != "" {
		t.Fatalf("passive failure wrote output: %q", got)
	}
}

func TestPassiveCheckPrintsOnlyForNewerRelease(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, `{"tag_name":"v1.1.0","html_url":"https://example.test/release","assets":[]}`)
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	u.passive(context.Background())
	got := u.stderr.(*strings.Builder).String()
	if !strings.Contains(got, "v1.1.0") || !strings.Contains(got, "ktunnel update") {
		t.Fatalf("unexpected notification: %q", got)
	}
	u.passive(context.Background())
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestPassiveSkipsDevelopmentAndCanBeDisabled(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()
	u := testUpdater(t, srv.URL)
	u.currentVersion = "dev"
	u.passive(context.Background())
	if requests.Load() != 0 {
		t.Fatal("development build made a passive request")
	}
	u.currentVersion = "v1.0.0"
	t.Setenv("KTUNNEL_NO_UPDATE_CHECK", "1")
	u.passive(context.Background())
	if requests.Load() != 0 {
		t.Fatal("disabled passive check made a request")
	}
}

func TestUpdateCheckDoesNotDownloadAsset(t *testing.T) {
	var assetRequests atomic.Int32
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			fmt.Fprintf(w, `{"tag_name":"v1.1.0","html_url":"%s/release","assets":[{"name":"ktunnel-linux-amd64","url":"%s/asset","digest":"sha256:%s","size":6}]}`, serverURL, serverURL, strings.Repeat("a", 64))
			return
		}
		assetRequests.Add(1)
		io.WriteString(w, "binary")
	}))
	defer srv.Close()
	serverURL = srv.URL
	u := testUpdater(t, serverURL)
	if err := u.run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if assetRequests.Load() != 0 {
		t.Fatalf("--check downloaded %d assets", assetRequests.Load())
	}
	if got := u.stderr.(*strings.Builder).String(); !strings.Contains(got, "v1.1.0") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestUpdateCommandAliasAndArguments(t *testing.T) {
	for _, command := range []string{"update", "upgrade"} {
		err := run([]string{command, "unexpected"})
		if err == nil || err.Error() != "usage: ktunnel update [--check]" {
			t.Fatalf("%s returned %v", command, err)
		}
	}
}

func testUpdater(t *testing.T, base string) *updater {
	t.Helper()
	cache := t.TempDir()
	return &updater{
		client: &http.Client{Timeout: time.Second}, apiBase: base, repo: "owner/repo",
		currentVersion: "v1.0.0", goos: "linux", goarch: "amd64",
		executable: os.Executable,
		token:      func(context.Context) (string, error) { return "test-token", nil },
		now:        time.Now,
		cacheDir:   func() (string, error) { return cache, nil },
		stderr:     &strings.Builder{},
		verify:     verifyBinary,
	}
}

func mustCachePath(t *testing.T, u *updater) string {
	t.Helper()
	path, err := u.cachePath()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func updateFixture(t *testing.T, old, downloaded []byte, wrongDigest bool) (*updater, *githubRelease, string, func()) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "ktunnel")
	if err := os.WriteFile(target, old, 0751); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(downloaded)
	digest := hex.EncodeToString(sum[:])
	if wrongDigest {
		digest = strings.Repeat("0", 64)
	}
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/asset" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(downloaded)))
		_, _ = w.Write(downloaded)
	}))
	serverURL = srv.URL
	u := testUpdater(t, serverURL)
	u.executable = func() (string, error) { return target, nil }
	rel := &githubRelease{TagName: "v2.0.0", Assets: []releaseAsset{{
		Name: "ktunnel-linux-amd64", URL: serverURL + "/asset", Digest: "sha256:" + digest, Size: int64(len(downloaded)),
	}}}
	return u, rel, target, srv.Close
}
