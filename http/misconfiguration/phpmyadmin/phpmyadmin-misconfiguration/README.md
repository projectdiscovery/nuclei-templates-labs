# phpMyAdmin Misconfiguration

## Description  

An unauthenticated instance of phpMyAdmin was discovered, exposing sensitive internal data. This misconfiguration could allow attackers to browse system databases like information_schema without credentials.
## References  

- [Exploit DB – GHDB](https://www.exploit-db.com/ghdb/6997)  

## Lab Setup  

- Run the following command to build and start the container:

  ```bash
  docker-compose up -d
  ```
Once running, phpMyAdmin will be accessible at: `http://localhost:8080`

## Exploitation Steps  
- Open a browser and navigate to: `http://your-ip:8080/phpMyAdmin/index.php?db=information_schema`
![phpmyadmin-misconfiguration-1](https://github.com/user-attachments/assets/3a569916-aecc-452c-bee4-746f71d4d043)

- If successful, you’ll gain access to the internal database schema without authentication.


## Steps to Write Nuclei Template  


**HTTP Requests**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/phpmyadmin/index.php?db=information_schema"
      - "{{BaseURL}}/phpMyAdmin/index.php?db=information_schema"

    stop-at-first-match: true
```
- These GET requests check for accessible database views via `phpMyAdmin` (case-sensitive variations included).

**Matchers: Detecting Access**
```yaml
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "var db    = 'information_schema';"
          - "var opendb_url = 'db_structure.php';"
        condition: and

      - type: word
        words:
          - "db:\"information_schema\""
          - "opendb_url:\"db_structure.php\""
        condition: and
```

- These matchers confirm:
    - The presence of internal database (information_schema)
    - Page elements indicating successful access to phpMyAdmin UI components

## Nuclei Template URL : [phpmyadmin-misconfiguration](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/phpmyadmin/phpmyadmin-misconfiguration.yaml)

## Nuclei Command  

```bash
nuclei -id phpmyadmin-misconfiguration -u localhost:8080 -vv
```
![phpmyadmin-misconfiguration-2](https://github.com/user-attachments/assets/889f9dda-9b8e-430b-9019-75e0a37e0b11)
