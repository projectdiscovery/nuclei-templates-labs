# phpMyAdmin Server Import

## Description

The phpMyAdmin Server Import page allows users to upload and execute SQL files. If exposed publicly or left unprotected, this functionality can be exploited by attackers to upload malicious SQL files, potentially leading to unauthorized database manipulation.

## Lab Setup

- Run the following command to build and start the container:

  ```bash
  docker-compose up -d
  ```
Once running, phpMyAdmin will be accessible at: `http://localhost:8080/phpMyAdmin`

## Exploitation Steps
- Open a browser and navigate to: `http://your-ip:8080/phpMyAdmin/server_import.php`
![phpmyadmin-server-import-1](https://github.com/user-attachments/assets/c76919f7-7b52-44e8-a841-d1139e53a16f)

This page, if accessible without authentication, exposes the SQL import functionality.
## Steps to Write Nuclei Template


**HTTP Requests**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}{{paths}}"
    payloads:
      paths:
        - "/pma/server_import.php"
        - "/phpmyadmin/server_import.php"
        - "/db/server_import.php"
        - "/server_import.php"
        - "/PMA/server_import.php"
        - "/admin/server_import.php"
        - "/admin/pma/server_import.php"
        - "/phpMyAdmin/server_import.php"
        - "/admin/phpMyAdmin/server_import.php"

    stop-at-first-match: true
```
- These GET requests check for accessible import page via `phpMyAdmin`.

**Matchers: Detecting Access**
```yaml
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "File to import"

      - type: word
        part: body
        words:
          - "Location of the text file"
          - "Browse your computer"
        condition: or

      - type: status
        status:
          - 200
```

- These matchers help verify:
    - The page content includes typical import UI text.
    - HTTP status is 200, confirming successful access.

## Nuclei Template URL : [phpmyadmin-server-import](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/phpmyadmin/phpmyadmin-server-import.yaml)

## Nuclei Command  

```bash
nuclei -id pma-server-import -u localhost:8080 -vv
```
![phpmyadmin-server-import-2](https://github.com/user-attachments/assets/2f8bb644-1a94-489c-92df-d5257688dd69)
