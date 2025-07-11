# phpMyAdmin Setup Page Exposure

## Description  

An unauthenticated phpMyAdmin setup page is accessible, potentially exposing sensitive configuration details.

## References

- [Security StackExchange – phpMyAdmin Setup Page Risk](https://security.stackexchange.com/questions/137876/does-phpmyadmin-setup-index-php-present-a-security-risk)

## Lab Setup

- Run the following command to build and start the container:

  ```bash
  docker-compose up -d
  ```
Once running, phpMyAdmin will be accessible at: `http://localhost:8080`

## Exploitation Steps
- Open a browser and navigate to: `http://your-ip:8080/setup/index.php`
![phpmyadmin-setup-1](https://github.com/user-attachments/assets/b1b0d075-5253-48b4-bbc6-c7e59667f8c7)


## Steps to Write Nuclei Template  


**HTTP Requests**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}{{paths}}"
    payloads:
      paths:
        - "/phpmyadmin/scripts/setup.php"
        - "/phpMyAdmin/scripts/setup.php"
        - "/_phpmyadmin/scripts/setup.php"
        - "/forum/phpmyadmin/scripts/setup.php"
        - "/php/phpmyadmin/scripts/setup.php"
        - "/typo3/phpmyadmin/scripts/setup.php"
        - "/web/phpmyadmin/scripts/setup.php"
        - "/xampp/phpmyadmin/scripts/setup.php"
        - "/sysadmin/phpMyAdmin/scripts/setup.php"
        - "/phpmyadmin/setup/index.php"
        - "/pma/setup/index.php"
        - "/admin/pma/setup/index.php"
        - "/phpmyadmin/setup/"
        - "/setup/index.php"
        - "/admin/"
        - "/phpMyAdminOLD/setup/index.php"
    
    stop-at-first-match: true
```
- These GET requests attempt to identify publicly accessible setup pages under various common paths.

**Matchers: Detecting Access**
```yaml
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "You want to configure phpMyAdmin using web interface"
          - "<title>phpMyAdmin setup</title>"
        condition: or

      - type: status
        status:
          - 200
```

- These matchers confirm:
  * **`matchers-condition: and`** – Both matcher rules must pass:

  * **Word Matcher**: Checks the response body for one of the following:

    * `"You want to configure phpMyAdmin using web interface"` (text on setup page)
    * `"<title>phpMyAdmin setup</title>"` (HTML title)
  * **Status Matcher**: Ensures the HTTP response status is `200 OK`, confirming the page loaded successfully.

## Nuclei Template URL : [phpmyadmin-setup](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/phpmyadmin/phpmyadmin-setup.yaml)

## Nuclei Command

```bash
nuclei -id phpmyadmin-setup -u localhost:8080 -vv
```
![phpmyadmin-setup-2](https://github.com/user-attachments/assets/47659582-80e9-430b-9710-dc565fa21ada)
