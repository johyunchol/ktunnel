package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	githubRepo       = "johyunchol/ktunnel"
	githubAPIVersion = "2022-11-28"
	maxReleaseJSON   = 4 << 20
	maxChecksumFile  = 1 << 20
	maxBinarySize    = 256 << 20
	updateCacheTTL   = 24 * time.Hour
)

type releaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type githubRelease struct {
	TagName string         `json:"tag_name"`
	HTMLURL string         `json:"html_url"`
	Assets  []releaseAsset `json:"assets"`
}

type updater struct {
	client         *http.Client
	apiBase        string
	repo           string
	currentVersion string
	goos           string
	goarch         string
	executable     func() (string, error)
	token          func(context.Context) (string, error)
	now            func() time.Time
	cacheDir       func() (string, error)
	stderr         io.Writer
	verify         func(context.Context, string, string) error
}

func defaultUpdater() *updater {
	return &updater{
		// Short checks have their own tighter contexts; the client timeout also
		// bounds a full explicit binary download on slower connections.
		client:         &http.Client{Timeout: 2 * time.Minute},
		apiBase:        "https://api.github.com",
		repo:           githubRepo,
		currentVersion: version,
		goos:           runtime.GOOS,
		goarch:         runtime.GOARCH,
		executable:     os.Executable,
		token:          githubToken,
		now:            time.Now,
		cacheDir:       updateCacheDir,
		stderr:         os.Stderr,
		verify:         verifyBinary,
	}
}

func githubToken(ctx context.Context) (string, error) {
	for _, name := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, nil
		}
	}
	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("GitHub 인증이 필요합니다. `gh auth login`을 실행하거나 GH_TOKEN을 설정해 주세요")
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", errors.New("GitHub 인증 토큰이 비어 있습니다. `gh auth login`을 다시 실행해 주세요")
	}
	return token, nil
}

func updateCacheDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("KTUNNEL_UPDATE_CACHE_DIR")); dir != "" {
		return dir, nil
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ktunnel"), nil
}

func (u *updater) request(ctx context.Context, method, url, accept, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", "ktunnel/"+u.currentVersion)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return u.client.Do(req)
}

func readLimited(body io.Reader, limit int64) ([]byte, error) {
	r := io.LimitReader(body, limit+1)
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("응답이 허용 크기(%d바이트)를 초과했습니다", limit)
	}
	return b, nil
}

func (u *updater) latest(ctx context.Context, token string) (*githubRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(u.apiBase, "/"), u.repo)
	resp, err := u.request(ctx, http.MethodGet, url, "application/vnd.github+json", token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("GitHub 릴리스를 읽을 수 없습니다(HTTP %d). 비공개 저장소 접근 권한을 확인하고 `gh auth login`을 실행해 주세요", resp.StatusCode)
		}
		return nil, fmt.Errorf("GitHub 릴리스 조회 실패(HTTP %d)", resp.StatusCode)
	}
	b, err := readLimited(resp.Body, maxReleaseJSON)
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(b, &rel); err != nil {
		return nil, fmt.Errorf("GitHub 릴리스 응답 해석: %w", err)
	}
	if _, ok := parseStableSemver(rel.TagName); !ok {
		return nil, fmt.Errorf("최신 릴리스 버전 %q은 안정 버전 형식이 아닙니다", rel.TagName)
	}
	return &rel, nil
}

type semver [3]uint64

func parseStableSemver(s string) (semver, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "v"))
	if s == "" || strings.ContainsAny(s, "+-") {
		return semver{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var out semver
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return semver{}, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return semver{}, false
		}
		out[i] = n
	}
	return out, true
}

func newerVersion(current, latest string) (bool, bool) {
	c, ok := parseStableSemver(current)
	if !ok {
		return false, false
	}
	l, ok := parseStableSemver(latest)
	if !ok {
		return false, false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i], true
		}
	}
	return false, true
}

func (u *updater) assetName() string {
	ext := ""
	if u.goos == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("ktunnel-%s-%s%s", u.goos, u.goarch, ext)
}

func findAsset(rel *githubRelease, name string) (releaseAsset, bool) {
	for _, asset := range rel.Assets {
		if asset.Name == name {
			return asset, true
		}
	}
	return releaseAsset{}, false
}

func digestSHA256(s string) (string, bool) {
	alg, value, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || !strings.EqualFold(alg, "sha256") || len(value) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return strings.ToLower(value), true
}

func checksumFor(data []byte, assetName string) (string, error) {
	var found string
	s := bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 || len(fields[0]) != 64 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == assetName {
			if _, err := hex.DecodeString(fields[0]); err != nil {
				continue
			}
			if found != "" {
				return "", fmt.Errorf("SHA256SUMS에 %s 항목이 중복되어 있습니다", assetName)
			}
			found = strings.ToLower(fields[0])
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("SHA256SUMS에 %s 항목이 없습니다", assetName)
	}
	return found, nil
}

func (u *updater) download(ctx context.Context, asset releaseAsset, token string, limit int64, dst io.Writer) error {
	if asset.Size > limit {
		return fmt.Errorf("릴리스 자산 %s이 허용 크기를 초과했습니다", asset.Name)
	}
	assetURL, assetErr := url.Parse(asset.URL)
	baseURL, baseErr := url.Parse(u.apiBase)
	if assetErr != nil || baseErr != nil || assetURL.Scheme != baseURL.Scheme || assetURL.Host != baseURL.Host {
		return fmt.Errorf("릴리스 자산 %s의 다운로드 주소가 GitHub API 주소와 일치하지 않습니다", asset.Name)
	}
	resp, err := u.request(ctx, http.MethodGet, asset.URL, "application/octet-stream", token)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("%s 다운로드 실패(HTTP %d)", asset.Name, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("릴리스 자산 %s이 허용 크기를 초과했습니다", asset.Name)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("릴리스 자산 %s이 허용 크기를 초과했습니다", asset.Name)
	}
	return nil
}

func (u *updater) expectedChecksum(ctx context.Context, rel *githubRelease, binary releaseAsset, token string) (string, error) {
	if sum, ok := digestSHA256(binary.Digest); ok {
		return sum, nil
	}
	sums, ok := findAsset(rel, "SHA256SUMS")
	if !ok {
		return "", errors.New("릴리스에 SHA-256 검증 정보가 없습니다")
	}
	var b strings.Builder
	if err := u.download(ctx, sums, token, maxChecksumFile, &b); err != nil {
		return "", err
	}
	return checksumFor([]byte(b.String()), binary.Name)
}

func isUVInstall(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return strings.Contains(clean, "/uv/tools/") || strings.Contains(clean, "/uv/tool/")
}

func verifyBinary(ctx context.Context, path, releaseTag string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, path, "version")
	cmd.Env = replaceEnv(os.Environ(), "KTUNNEL_UPDATE_PREFLIGHT", "1")
	var stdout bytes.Buffer
	cmd.Stdout = &boundedWriter{writer: &stdout, remaining: 4096}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
			return errors.New("버전 확인 시간이 초과되었습니다")
		}
		return fmt.Errorf("버전 명령 실행: %w", err)
	}
	want := "ktunnel " + releaseTag + "\n"
	if stdout.String() != want {
		return fmt.Errorf("버전 출력이 일치하지 않습니다(예상 %q, 실제 %q)", strings.TrimSpace(want), strings.TrimSpace(stdout.String()))
	}
	return nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	originalLen := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	if len(p) > 0 {
		n, err := w.writer.Write(p)
		w.remaining -= n
		if err != nil {
			return n, err
		}
	}
	// Report the original length so an overly chatty child gets a mismatch
	// instead of failing with io.ErrShortWrite and cannot grow memory forever.
	return originalLen, nil
}

func replaceEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func syncDirectory(path string) {
	if d, err := os.Open(path); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func backupExecutable(path string, info os.FileInfo) (string, error) {
	dir := filepath.Dir(path)
	backup, err := os.CreateTemp(dir, ".ktunnel-backup-*")
	if err != nil {
		return "", err
	}
	name := backup.Name()
	ok := false
	defer func() {
		_ = backup.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	source, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer source.Close()
	if _, err := io.Copy(backup, io.LimitReader(source, maxBinarySize+1)); err != nil {
		return "", err
	}
	if pos, err := backup.Seek(0, io.SeekCurrent); err != nil || pos > maxBinarySize {
		return "", errors.New("기존 실행 파일이 백업 허용 크기를 초과했습니다")
	}
	if err := backup.Chmod(info.Mode().Perm()); err != nil {
		return "", err
	}
	if err := backup.Sync(); err != nil {
		return "", err
	}
	if err := backup.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func (u *updater) install(ctx context.Context, rel *githubRelease, token string) error {
	if u.goos == "windows" {
		return fmt.Errorf("Windows에서는 실행 중인 파일을 안전하게 교체할 수 없습니다. %s 에서 %s를 내려받아 기존 ktunnel.exe를 교체해 주세요", rel.HTMLURL, u.assetName())
	}
	path, err := u.executable()
	if err != nil {
		return fmt.Errorf("현재 실행 파일 위치 확인: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("현재 실행 파일 경로 확인: %w", err)
	}
	if isUVInstall(path) {
		return errors.New("uv로 설치된 ktunnel은 바이너리만 교체할 수 없습니다. 저장소의 `./install.sh --uv`를 실행해 주세요")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("현재 실행 파일 확인: %w", err)
	}
	asset, ok := findAsset(rel, u.assetName())
	if !ok {
		return fmt.Errorf("릴리스 %s에 이 플랫폼용 자산 %s가 없습니다", rel.TagName, u.assetName())
	}
	expected, err := u.expectedChecksum(ctx, rel, asset, token)
	if err != nil {
		return fmt.Errorf("무결성 정보 확인: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ktunnel-update-*")
	if err != nil {
		return fmt.Errorf("설치 디렉터리에 쓸 수 없습니다(%s). ktunnel을 쓰기 가능한 사용자 경로에 설치해 주세요; sudo는 자동 실행하지 않습니다: %w", dir, err)
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	h := sha256.New()
	if err := u.download(ctx, asset, token, maxBinarySize, io.MultiWriter(tmp, h)); err != nil {
		_ = tmp.Close()
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		_ = tmp.Close()
		return fmt.Errorf("체크섬 불일치: 다운로드를 중단했습니다(예상 %s, 실제 %s)", expected, actual)
	}
	mode := info.Mode().Perm()
	if mode&0111 == 0 {
		mode |= 0755
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("실행 권한 설정: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("업데이트 파일 동기화: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("업데이트 파일 닫기: %w", err)
	}
	if err := u.verify(ctx, tmpName, rel.TagName); err != nil {
		return fmt.Errorf("새 실행 파일 사전 검사 실패: %w", err)
	}
	backup, err := backupExecutable(path, info)
	if err != nil {
		return fmt.Errorf("기존 실행 파일 백업 실패: %w", err)
	}
	syncDirectory(dir)
	cleanupBackup := true
	defer func() {
		if cleanupBackup {
			_ = os.Remove(backup)
		}
	}()
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("실행 파일 교체 실패(기존 파일은 유지됨): %w", err)
	}
	keep = true
	syncDirectory(dir)
	if err := u.verify(ctx, path, rel.TagName); err != nil {
		if rollbackErr := os.Rename(backup, path); rollbackErr != nil {
			cleanupBackup = false
			return fmt.Errorf("교체 후 검사 실패(%v), 롤백도 실패했습니다: %w", err, rollbackErr)
		}
		cleanupBackup = false
		syncDirectory(dir)
		return fmt.Errorf("교체 후 검사 실패하여 기존 버전으로 롤백했습니다: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("업데이트는 완료됐지만 백업 파일 %s 삭제에 실패했습니다: %w", backup, err)
	}
	cleanupBackup = false
	syncDirectory(dir)
	return nil
}

func (u *updater) check(ctx context.Context) (*githubRelease, bool, error) {
	if _, ok := parseStableSemver(u.currentVersion); !ok {
		return nil, false, fmt.Errorf("현재 버전 %q은 정식 릴리스 버전이 아닙니다", u.currentVersion)
	}
	token, err := u.token(ctx)
	if err != nil {
		return nil, false, err
	}
	rel, err := u.latest(ctx, token)
	if err != nil {
		return nil, false, err
	}
	newer, _ := newerVersion(u.currentVersion, rel.TagName)
	return rel, newer, nil
}

func (u *updater) run(ctx context.Context, checkOnly bool) error {
	if _, ok := parseStableSemver(u.currentVersion); !ok {
		return fmt.Errorf("현재 버전 %q은 정식 릴리스 버전이 아닙니다", u.currentVersion)
	}
	token, err := u.token(ctx)
	if err != nil {
		return err
	}
	rel, err := u.latest(ctx, token)
	if err != nil {
		return err
	}
	newer, _ := newerVersion(u.currentVersion, rel.TagName)
	if !newer {
		fmt.Fprintf(u.stderr, "ktunnel %s은 최신 버전입니다.\n", u.currentVersion)
		return nil
	}
	if checkOnly {
		fmt.Fprintf(u.stderr, "새 버전 %s을 사용할 수 있습니다: ktunnel update\n", rel.TagName)
		return nil
	}
	if err := u.install(ctx, rel, token); err != nil {
		return err
	}
	fmt.Fprintf(u.stderr, "ktunnel을 %s에서 %s(으)로 업데이트했습니다.\n", u.currentVersion, rel.TagName)
	return nil
}

func (u *updater) cachePath() (string, error) {
	dir, err := u.cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "last-update-check"), nil
}

func (u *updater) claimPassiveCheck() bool {
	path, err := u.cachePath()
	if err != nil {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false
	}
	// Serialize the read/claim across concurrent ktunnel processes. The lock is
	// short-lived: it protects only the timestamp, never the network request.
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if info, statErr := os.Stat(lockPath); statErr != nil || u.now().Sub(info.ModTime()) <= time.Minute {
			return false
		}
		// Recover a lock orphaned by a process that died during the very short
		// cache update. Only locks older than a minute are eligible.
		if os.Remove(lockPath) != nil {
			return false
		}
		lock, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return false
		}
	}
	_ = lock.Close()
	defer os.Remove(lockPath)
	if b, err := os.ReadFile(path); err == nil {
		stamp, parseErr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if parseErr == nil {
			checked := time.Unix(stamp, 0)
			if !checked.After(u.now()) && u.now().Sub(checked) < updateCacheTTL {
				return false
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".last-update-check-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(0600)
	_, writeErr := fmt.Fprintf(tmp, "%d\n", u.now().Unix())
	closeErr := tmp.Close()
	if writeErr != nil || closeErr != nil || os.Rename(name, path) != nil {
		return false
	}
	return true
}

func (u *updater) passive(ctx context.Context) {
	if os.Getenv("KTUNNEL_NO_UPDATE_CHECK") == "1" || os.Getenv("CI") != "" {
		return
	}
	if _, ok := parseStableSemver(u.currentVersion); !ok || !u.claimPassiveCheck() {
		return
	}
	rel, newer, err := u.check(ctx)
	if err == nil && newer {
		fmt.Fprintf(u.stderr, "\n새 ktunnel 버전 %s이 있습니다. `ktunnel update`로 업데이트하세요.\n", rel.TagName)
	}
}

func passiveUpdateCheck() {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	defaultUpdater().passive(ctx)
}

func cmdUpdate(args []string) error {
	checkOnly := false
	if len(args) == 1 && args[0] == "--check" {
		checkOnly = true
	} else if len(args) != 0 {
		return errors.New("usage: ktunnel update [--check]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return defaultUpdater().run(ctx, checkOnly)
}

func cmdVersion() error {
	fmt.Printf("ktunnel %s\n", version)
	if os.Getenv("KTUNNEL_UPDATE_PREFLIGHT") == "1" {
		return nil
	}
	if _, ok := parseStableSemver(version); !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	rel, newer, err := defaultUpdater().check(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "업데이트 확인 불가: %v\n", err)
		return nil
	}
	if newer {
		fmt.Fprintf(os.Stderr, "새 버전 %s이 있습니다. `ktunnel update`로 업데이트하세요.\n", rel.TagName)
	} else {
		fmt.Fprintln(os.Stderr, "최신 버전입니다.")
	}
	return nil
}
