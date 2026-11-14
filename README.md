# CFA L1 페이스메이커

CFA Level I 3회독 진도표와 과목별 일일 공부시간·메모 달력입니다.

- 사이트: https://app.cfa-study-pacer.workers.dev
- 아이디·비밀번호로 로그인하면 기록이 서버에 저장되어 PC와 휴대폰에서 같이 보입니다.
- 로그인하지 않으면 그 기기 브라우저에만 저장됩니다.

## 구성
- `index.html`: 페이지 전체 (빌드 과정 없음). 서버가 이 파일을 읽어서 보여주므로, 이 파일을 main에 올리면 5분 안에 사이트에 반영됩니다.
- `server/worker.js`: Cloudflare Worker. 페이지 제공 + 로그인·기록 저장 API (`/api/signup`, `/api/login`, `/api/data`, `/api/password`, `/api/logout`).
- `server/schema.sql`: Cloudflare D1 데이터베이스 `cfa-pacer-db`의 테이블.

비밀번호는 PBKDF2-SHA256(10만 회)으로 해시해 저장하고, 5번 틀리면 15분 동안 잠깁니다. 가입은 최대 5개 계정까지 가능합니다.
