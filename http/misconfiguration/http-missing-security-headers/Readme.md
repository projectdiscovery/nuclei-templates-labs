# HTTP Missing Security Headers

## Description:
Web servers and applications often fail to implement essential security headers, leaving them vulnerable to attacks such as clickjacking, MIME sniffing, cross-site scripting (XSS), and data leakage. This template scans for missing HTTP security headers that help mitigate these risks.

## Reference:
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers 

## Vulnerable Setup

- Deploy a vulnerable Nginx server with missing security headers.

```bash
docker-compose up -d
```

- Once started, the server will be available on http://localhost:8080 without security headers.

## Exploitation Steps

- Run curl to check headers:

```bash
curl -I http://localhost:8080
```

- If headers such as Strict-Transport-Security, Content-Security-Policy, or X-Frame-Options are absent, the server is misconfigured.


## Steps to Write Nuclei Template

**Template Logic**

HTTP Request & Response Handling.

- Request Type: GET

- Target: Base URL ({{BaseURL}})

- Redirection Handling: Follows up to 3 redirects

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    host-redirects: true
    max-redirects: 3
```

**Matchers for Missing Security Headers**

Each security header is checked using a negative regex match, ensuring it is absent in the response.

```yaml
matchers:
  - type: dsl
    name: strict-transport-security
    dsl:
      - "!regex('(?i)strict-transport-security', header)"
      - "status_code != 301 && status_code != 302"
    condition: and
```

**This process is repeated for other headers such as:**

- content-security-policy

- permissions-policy

- x-frame-options

- clear-site-data

- x-permitted-cross-domain-policies

- x-content-type-options

- referrer-policy

- cross-origin-embedder-policy

- cross-origin-opener-policy

- cross-origin-resource-policy


## Nuclei Template URL : [http-missing-security-headers](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/http-missing-security-headers.yaml)

## Nuclei Command:

```bash
nuclei -id http-missing-security-headers -u localhost:8080 -vv
```

This command scans the specified URL and reports missing security headers.

![image](https://github.com/user-attachments/assets/444410ea-99c2-4fdc-b034-3b261d692cf7)

