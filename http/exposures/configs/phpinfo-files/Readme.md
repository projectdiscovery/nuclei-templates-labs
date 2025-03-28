# PHP Info Exposure Lab

## Description:
This lab demonstrates a common web server misconfiguration where PHP info pages are publicly accessible. The `phpinfo()` output reveals sensitive server information including PHP environment details, system paths, and configuration settings that could aid attackers in crafting targeted exploits.

## Reference:
- [PHP: phpinfo() Manual](https://www.php.net/manual/en/function.phpinfo.php)
- [OWASP Information Exposure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure_Cheat_Sheet.html)

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

**Template Logic**

The detection uses:

- Multiple common phpinfo file paths

- Content matching for "PHP Version" and "PHP Extension"

- Version number extraction via regex

```yaml
http:
  - method: GET
    path:
      - "/phpinfo.php"
      - "/test.php"
      - "/info.php"
    matchers:
      - type: word
        words:
          - "PHP Version"
          - "PHP Extension"
        condition: and
      - type: status
        status:
          - 200
```


## Nuclei Template URL : [phpinfo-files](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/configs/phpinfo-files.yaml)

## Nuclei Command:

```bash
nuclei -id phpinfo-files -u localhost:8080 -vv
```

This command scans the specified URL and reports missing security headers.

![image](https://github.com/user-attachments/assets/93512f34-9695-409f-9286-c72135e54820)
