# CFA L1 페이스메이커

CFA Level I 3회독 진도표와 과목별 일일 공부시간·메모 달력입니다.

- 사이트: https://cfa.serendipity-awaits.workers.dev
- 아이디·비밀번호 또는 구글 계정으로 로그인하면 기록이 서버에 저장되어 PC와 휴대폰에서 같이 보입니다.
- 첫 화면은 대시보드, 옆으로 넘기면 "오늘 공부" 현황판(5분 시작 버튼, 집중 타이머, 강의 단계 체크)입니다.
- 로그인하지 않으면 그 기기 브라우저에만 저장됩니다.

## 구성
- `index.html`: 페이지 전체 (빌드 과정 없음). 서버가 이 파일을 읽어서 보여주므로, 이 파일을 main에 올리면 5분 안에 사이트에 반영됩니다.
- `server/worker.js`: Cloudflare Worker. 페이지 제공 + 로그인·기록 저장 API (`/api/signup`, `/api/login`, `/api/data`, `/api/password`, `/api/logout`, `/api/reset`, `/api/recovery-code`, `/api/google`, `/api/config`, `/api/me`).
- `server/schema.sql`: Cloudflare D1 데이터베이스 `cfa-pacer-db`의 테이블.

비밀번호는 PBKDF2-SHA256(10만 회)으로 해시해 저장하고, 5번 틀리면 15분 동안 잠깁니다. 가입은 최대 5개 계정까지 가능합니다.

구글 로그인은 Worker 환경 변수 `GOOGLE_CLIENT_ID`(구글 OAuth 웹 클라이언트 ID)를 넣으면 켜집니다. 없으면 버튼이 보이지 않습니다.

이메일 인증번호(아이디·비밀번호 찾기)는 Worker 비밀값 `RESEND_API_KEY`(Resend API 키)가 있으면 켜집니다. 도메인 없이 쓰므로 Resend에 가입한 이메일 주소로만 보낼 수 있습니다.
