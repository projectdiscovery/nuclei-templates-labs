# PHP Info Exposure Lab

## Description:
This lab demonstrates a common web server misconfiguration where PHP info pages are publicly accessible. The `phpinfo()` output reveals sensitive server information including PHP environment details, system paths, and configuration settings that could aid attackers in crafting targeted exploits.

## Reference:
- [PHP: phpinfo() Manual](https://www.php.net/manual/en/function.phpinfo.php)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)

## Vulnerable Setup

- Deploy a vulnerable Apache/PHP server with multiple exposed phpinfo pages:

```bash
docker-compose up -d
```

Once started, the server will be available at:

- http://localhost:8080/phpinfo.php

- http://localhost:8080/test.php

- http://localhost:8080/info.php

- http://localhost:8080/php_info.php

- http://localhost:8080/p.php

## Exploitation Steps

- Check exposure using curl

```bash
curl -I http://localhost:8080/phpinfo.php
```

- View complete information disclosure:

```bash
curl http://localhost:8080/phpinfo.php | grep "PHP Version"
```


## Steps to Write Nuclei Template

**HTTP Request Definition**

- The template uses an HTTP `GET` request to check if the target has exposed `phpinfo()` pages.

- The `path` parameter allows dynamic URL formation using predefined paths.

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}{{paths}}"
```

**Defining Payloads (Target Paths)**

- This section specifies common file names where `phpinfo()` pages are likely to be exposed.

- The template will test multiple URLs at the target site to detect misconfigurations.

```yaml
    payloads:
      paths:
        - "/phpinfo.php"
        - "/test.php"
        - "/info.php"
```

**Matchers for Detection**

- `matchers-condition: and` ensures that both conditions must be met for detection.

- The template looks for two specific keywords in the response body: `"PHP Extension"` and `"PHP Version"`, The HTTP response must return `200 OK`.

```yaml
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "PHP Extension"
          - "PHP Version"
        condition: and

      - type: status
        status:
          - 200
```

**Extracting PHP Version Information**

- The extractor section uses a regular expression (regex) to retrieve the PHP version from the page content.

- This helps in identifying outdated or vulnerable PHP versions that might be exploited.

```yaml
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - '>PHP Version <\/td><td class="v">([0-9.]+)'
```

## Nuclei Template URL : [phpinfo-files](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/configs/phpinfo-files.yaml)

## Nuclei Command:

```bash
nuclei -id phpinfo-files -u localhost:8080 -vv
```

This command scans the specified URL and reports missing security headers.

![image](https://github.com/user-attachments/assets/e9153c77-3db4-41df-9213-354c3418a841)

