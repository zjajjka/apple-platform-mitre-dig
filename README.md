# apple-platform-mitre-dig

Free **GitHub Actions `macos-15`** digs for third-party Apple-platform apps → MITRE (not Apple CNA).

**Credit:** Zhang Jinshan `<2831737873a@gmail.com>`

## Jobs

| Workflow job | What it proves |
|--------------|----------------|
| `path-escape-swift` | iTransfer-style `contentURL` path traversal (Foundation = iOS) |
| `itransfer-static-audit` | HTTP/FTP servers ignore accounts / whitelist (dead config) |
| `iina-allowlist-audit` | IINA 1.4.4 no longer allowlists `log-file` / `input-commands`; notes residual (`tls-verify`, …) |

## Run

- Push to `main`, or **Actions → macos-dig → Run workflow**
- Public repo → standard macOS runners are **free**

## Local (on a Mac)

```bash
cd PathEscapeDemo && swift test
```
