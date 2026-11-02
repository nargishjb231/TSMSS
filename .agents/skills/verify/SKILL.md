---
name: verify
description: Verification-first offensive security auditing skill. Replaces probabilistic guesses with strict ground-truth proofs across all vulnerability classes. Enforces the Five-Gate doctrine (Candidate, Context, Confirm, Repro, Artifact) and captures verifiable proof artifacts.
tools:
  - run_command
  - read_file
---

# TSMSS Verification Skill (/verify)

A verification-first pipeline for bug bounty and security auditing.
**Doctrine:** "Nothing ships at 'probably'. A finding with no proof artifact does not exist."

## The Five-Gate Standard
Every candidate finding must pass all five gates to be reported as `CONFIRMED`:
1. **G1 CANDIDATE**: Payload sent, response differs from calibrated baseline.
2. **G2 CONTEXT**: Named injection context classified (`MARKUP`, `ATTR_Q`, `ATTR_UQ`, `JS_STRING`, `JSON`, `COMMENT`, `TEXT`, `SQL`, `TEMPLATE`, `HEADER`).
3. **G3 CONFIRM**: Class-specific ground-truth oracle fires.
4. **G4 REPRO**: 3 consecutive reproducible runs on a clean session.
5. **G5 ARTIFACT**: Raw request dump, 1KB response oracle slice, full response SHA-256, and timestamp stored in `$TMPDIR/art/<scanid>/<findingid>/`.

## Standalone Class Playbook Scripts
Each vulnerability class can be invoked directly:

- **XSS**: `python .agents/skills/verify/scripts/verify_xss.py --url <URL> --param <PARAM>`
- **SQLi**: `python .agents/skills/verify/scripts/verify_sqli.py --url <URL> --param <PARAM>`
- **SSTI**: `python .agents/skills/verify/scripts/verify_ssti.py --url <URL> --param <PARAM>`
- **SSRF**: `python .agents/skills/verify/scripts/verify_ssrf.py --url <URL> --param <PARAM> [--interactsh <HOST>]`
- **Open Redirect**: `python .agents/skills/verify/scripts/verify_redirect.py --url <URL> --param <PARAM>`
- **CORS**: `python .agents/skills/verify/scripts/verify_cors.py --url <URL>`
- **CRLF**: `python .agents/skills/verify/scripts/verify_crlf.py --url <URL> --param <PARAM>`
- **Host Header**: `python .agents/skills/verify/scripts/verify_headers.py --url <URL>`
- **Path Traversal**: `python .agents/skills/verify/scripts/verify_traversal.py --url <URL> --param <PARAM>`
- **Prototype Pollution**: `python .agents/skills/verify/scripts/verify_prototype.py --url <URL> --param <PARAM>`
- **JWT**: `python .agents/skills/verify/scripts/verify_jwt.py --token <TOKEN> --url <URL>`
- **GraphQL**: `python .agents/skills/verify/scripts/verify_graphql.py --url <URL>`
- **Cache Deception**: `python .agents/skills/verify/scripts/verify_cache.py --url <URL> --path <PATH>`
- **IDOR**: `python .agents/skills/verify/scripts/verify_idor.py --url <URL> --param <PARAM>`

## Kill Rules
Drop immediately:
- Byte-identical response
- Reflection only in JS string or JSON with no actionable sink
- Soft-404 match against calibrated baseline
- Edge challenge page (unless browser subagent bypassed)
- Flaky oracles (fewer than 3/3 reproducible executions)
- 0-byte body on HTTP 200 without `Content-Length: 0`
- Double-encoded HTML entities without execution
