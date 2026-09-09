# ktunnel

[한국어](README.md) | [English](README.en.md)

내 장비에서 실행 중인 로컬 포트를 `https://<name>.your-domain.com`으로
외부에 공개합니다. 호스팅형 터널 서비스처럼 사용자별 토큰, 서브도메인
소유권, 대시보드를 제공하지만 중계 서버까지 직접 소유하고 운영합니다.

```console
$ ktunnel login              # 숨김 프롬프트에서 발급받은 토큰 입력
$ ktunnel http 3000

  https://happy-zephyr-0faf.kkensu.com
  -> 127.0.0.1:3000   (http)

live - Ctrl-C to stop.
```

두 개의 바이너리로 구성됩니다.

| 바이너리 | 실행 위치 | 역할 |
|---|---|---|
| `ktunnel` | 각 노트북, Pi, CI 장비 | 터널을 엽니다 |
| `ktunneld` | frps 옆의 중계 서버 | 토큰을 발급·검증하고 서브도메인 소유권을 적용하며 대시보드를 제공합니다 |

실제 터널링은 [frp](https://github.com/fatedier/frp)가 담당하며 라이브러리로
내장되어 있습니다. 클라이언트와 서버 어느 쪽에도 Docker, `frpc`, 별도
런타임을 설치할 필요가 없습니다.

## 사용자 안내

중계 서버 운영자에게 토큰을 발급받아야 합니다. 토큰에 중계 서버 주소와
도메인과 검증할 TLS 서버 이름이 들어 있으므로 토큰 하나만 입력하면 됩니다.

```bash
ktunnel login                          # 토큰을 화면에 표시하지 않고 입력
ktunnel http 3000                      # 무작위 서브도메인
ktunnel http 3000 --name myapp         # https://myapp.example.com
ktunnel http 8080 --host 192.168.1.50  # LAN의 다른 장비로 전달
ktunnel tcp 22 --remote 20022          # 원시 TCP(SSH, 데이터베이스 등)
ktunnel status                         # 현재 로그인된 중계 서버 확인
ktunnel logout
ktunnel update                         # 최신 릴리스 설치(upgrade도 동일하게 동작)
ktunnel update --check                 # 설치하지 않고 업데이트 확인
```

`ktunnel login`은 터미널에서 토큰 입력을 숨기며 이것이 권장 방식입니다. 파이프가
필요한 자동화에서는 `printf '%s\n' "$KTUNNEL_TOKEN" | ktunnel login`처럼 표준
입력을 사용할 수 있습니다. `ktunnel login <token>`도 호환성을 위해 지원하지만
토큰이 셸 기록이나 프로세스 목록에 노출될 수 있으므로 대화형 사용에는 권장하지
않습니다. 설정은 `~/.config/ktunnel/config`에 저장되며 POSIX 시스템에서는
디렉터리와 파일 권한이 각각 `0700`, `0600`으로 제한됩니다.

일반 CLI 명령을 사용할 때 하루에 한 번 새로운 안정 버전이 있는지
확인하고, 새 버전이 있으면 짧게 알려줍니다. 짧은 명령에서는 최대 750ms만
기다리며, 터널 명령에서는 터널이 열린 뒤 백그라운드에서 확인합니다. 확인에
실패해도 오류를 표시하지 않고 다음 날 다시 시도합니다. 비활성화하려면
`KTUNNEL_NO_UPDATE_CHECK=1`을 설정하세요.

`update`는 릴리스의 SHA-256을 검증한 뒤 현재 바이너리를 원자적으로
교체합니다. 공개 저장소의 릴리스는 로그인 없이 업데이트할 수 있습니다.
`GH_TOKEN`, `GITHUB_TOKEN` 또는 `gh auth login`으로 인증되어 있으면 해당
자격 증명을 자동으로 사용해 API 제한을 완화합니다. 바이너리에 내장된
`ktunnel update`는 공식 `johyunchol/ktunnel` 저장소만 확인하며 임의의 포크로
전환하지 않습니다. 업데이트 도구는 토큰을 저장하지 않고 `sudo`를 실행하지도
않습니다. 바이너리가 보호된 디렉터리에 있다면 `~/.local/bin`처럼 사용자가
쓸 수 있는 경로에 다시 설치하세요.
`./install.sh --uv`로 설치했다면 wheel 메타데이터와 바이너리가 일치하도록
같은 설치 명령을 다시 실행해야 합니다. Windows에서는 실행 중인 `.exe`가
자기 자신을 안전하게 교체할 수 없으므로 정확한 릴리스 자산을 안내하고
수동 교체하도록 합니다.

옵션은 포트 앞이나 뒤에 둘 수 있습니다. `tcp` 터널은 관리자가 허용한
범위의 원격 포트를 명시해야 합니다. HTTP의 `Host` 헤더가 없으므로 별도의
라우팅 기준이 필요하기 때문입니다.

중계 서버가 터널을 거부하면 이유를 보여주고 프롬프트로 돌아옵니다.

```
error: subdomain "api" belongs to alice
error: tunnel limit reached (5)
error: token has been revoked
```

### 설치

macOS, Linux, Windows용 바이너리는 각 [릴리스](../../releases)에 첨부됩니다.
`install.sh`는 현재 플랫폼에 맞는 파일을 선택하며 `uv` 설치도 지원합니다.

```bash
./install.sh          # 바이너리를 ~/.local/bin에 복사
./install.sh --uv     # 플랫폼별 wheel을 사용해 uv tool로 설치
```

공개 릴리스는 `curl`로 내려받으므로 GitHub 계정이나 `gh`가 필요하지 않습니다.
인증된 GitHub CLI가 있으면 설치 스크립트가 이를 자동으로 사용합니다. 비공개
포크를 설치하려면 `KTUNNEL_REPO=owner/repo`를 지정하고 `gh auth login`으로
읽기 권한이 있는 계정에 로그인해야 합니다. 내려받은 파일은 `SHA256SUMS`로
검증한 뒤에만 설치됩니다. Windows에서는
`ktunnel-windows-amd64.exe`를 내려받아 `PATH`에 포함된 경로에 두세요. 바이너리
방식으로 설치한 이후부터는 `ktunnel update` 또는 같은 기능의
`ktunnel upgrade`로 새 릴리스를 설치할 수 있습니다.

## 관리자 안내

`ktunneld`는 정적 바이너리 하나와 SQLite 파일 하나로 이루어진 작은 제어
서버입니다. frps의 [서버 플러그인](https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md)
훅에 연결되므로, frps는 로그인·터널 생성·하트비트마다 `ktunneld`에 확인합니다.

```
ktunnel ──login, metas.token──▶ frps ──Login/NewProxy/Ping/CloseProxy──▶ ktunneld
                                                                         │
                                                                     SQLite: users,
                                                                     tokens, reservations,
                                                                     sessions, audit
```

이제 **공유 frps 비밀키는 사용하지 않습니다.** 토큰은 사용자별로 발급되고
저장 시 sha256으로 해시되며, 최초 발급 때 한 번만 표시되고 개별적으로
폐기할 수 있습니다.

`kt2` 토큰에는 중계 서버 인증서의 이름도 포함됩니다. v0.6 클라이언트는
내장된 Let's Encrypt ISRG Root X1/X2만 신뢰하고 frps 제어 연결의 인증서와
호스트 이름을 모두 검증합니다. 기존 `kt1` 토큰은 서버에서 마이그레이션
기간 동안 유지되지만 v0.6 클라이언트로 새 터널을 열 수 없습니다. 웹 포털에서
새 `kt2` 토큰을 발급받으세요.

```bash
ktunneld user add alice --max 5              # 동시 터널 수 제한
ktunneld token issue alice --label laptop    # 토큰을 한 번만 출력
ktunneld token ls
ktunneld token revoke 6KkHiYxu               # 접두사로 폐기, 활성 세션은 30초 이내 종료

ktunneld reserve api alice                   # api.example.com은 alice만 사용
ktunneld release api

ktunneld ls                                  # 접속자와 공개된 서비스 확인
ktunneld kill <session-id | subdomain>       # 연결 종료, 해당 토큰은 5분간 거부
```

**웹 포털**은 `127.0.0.1:7600`에서 수신합니다. 관리자는 아이디 `admin`과
`ktunneld admin set-password`로 설정한 비밀번호로 로그인합니다. 사용자를
생성하거나 비밀번호를 초기화하면 일회용 임시 비밀번호가 표시되며, 관리자는
이를 사용자에게 전달합니다. 공개 회원가입은 없습니다. 사용자는 처음
로그인할 때 임시 비밀번호를 반드시 변경해야 하며, 이후 본인의 터널 토큰만
발급·폐기하고 본인의 연결과 예약 주소만 볼 수 있습니다. 새 토큰은 한 번만
표시되며 사용자는 `ktunnel login`의 숨김 프롬프트로 저장합니다.

운영 포털 주소는 `https://ktunnel.kkensu.com`입니다. 기존
`tunnel-admin.kkensu.com` 주소는 영구 리다이렉트로 유지합니다. 설정은
[`server/nginx-dashboard.conf`](server/nginx-dashboard.conf)를 참고하세요.

각 터널에는 다음 규칙이 적용됩니다.

- 토큰이 활성 상태이고 계정이 활성화되어 있으며 세션이 강제 종료되지 않아야 합니다.
- `http` 터널은 단일 서브도메인만 사용합니다. 사용자 지정 도메인이나 다단계 이름은 허용하지 않습니다.
- 예약된 서브도메인은 소유자만 열 수 있습니다. 예약되지 않은 이름은 먼저 연 사용자가 사용하며 두 세션이 동시에 사용할 수 없습니다.
- `tcp` 터널은 설정된 원격 포트 범위 안에 있어야 합니다.
- 사용자별 동시 터널 수 제한을 지켜야 합니다.

토큰 폐기, 계정 비활성화, 세션 강제 종료는 클라이언트의 다음 하트비트 시점인
30초 이내에 적용됩니다. 일반적인 frpc는 즉시 재연결하지만 `ktunnel`은 대신
메시지를 표시하고 종료합니다. 강제 종료한 토큰은 5분 동안 추가로 거부됩니다.

구축 방법은 [server/README.md](server/README.md)에 정리되어 있습니다.
DNS-01 방식의 와일드카드 인증서, frps, nginx 와일드카드 가상 호스트와
Synology DSM 우회 설정, `ktunneld` 구성을 다룹니다.

## 동작 원리

클라이언트가 외부 중계 서버로 연결하고, 중계 서버가 그 연결을 역방향으로
재사용합니다. 클라이언트에서는 어떤 포트도 수신하지 않으므로 인바운드 규칙,
포트 포워딩, 공인 IP가 필요 없습니다. 카페 Wi-Fi, 회사 NAT, CGNAT,
테더링 환경에서도 동작합니다.

공개 웹 트래픽의 TLS는 nginx에서 와일드카드 인증서로 종료됩니다. 따라서
서브도메인을 정하는 즉시 유효한 HTTPS 주소가 됩니다. 이와 별도로 클라이언트와
frps 사이의 제어 채널도 TLS를 강제하고 인증서를 검증합니다. 터널마다 인증서를
별도로 발급하지 않으므로 터널이 즉시 생성되고 Let's Encrypt 발급 제한도
피할 수 있습니다.

## 빌드

Go 1.25 이상이 필요합니다. Go를 직접 설치하지 않으려면 Docker를 사용할 수
있습니다.

```bash
./build.sh v0.6.0                    # 두 바이너리를 dist/에 교차 컴파일
python3 packaging/build_wheels.py 0.6.0
```

정확한 안정 버전 태그(예: `v0.6.0`)를 만들면 GitHub Actions가 같은 빌드를
실행하고 모든 결과물을 릴리스에 첨부합니다. 릴리스 워크플로는 바이너리와
wheel을 모두 만든 다음 하나의 `SHA256SUMS`를 생성합니다. wheel 항목이 없는
이전 또는 로컬 체크섬 파일을 새 릴리스에 재사용해서는 안 됩니다.

## 라이선스

MIT
