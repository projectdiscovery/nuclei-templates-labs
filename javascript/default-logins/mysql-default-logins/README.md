# MySQL Default Login - Detect

## Description
- This detection focuses on identifying MySQL servers that are accessible using **default or weak credentials** such as `root:root`, `admin:admin`, or even blank passwords.
- MySQL is a widely used open-source relational database management system. If it's exposed with default logins, attackers can gain unauthorized access, potentially leading to data breaches or remote code execution via SQL.

## References
- [Exploit Database](https://www.exploit-db.com/)
- [NVD](https://nvd.nist.gov/)
- [MySQL Documentation](https://dev.mysql.com/doc/)

## Vulnerable Setupß

Execute the following commands to start a vulnerable MySQL container using Docker:

```bash
# Step 1: Build the image
docker build -t my-mysql .

# Step 2: Run the container
docker run -d -p 3306:3306 --name mysql-container my-mysql
```

## Exploitation Steps

### 1. Identify Open Ports
Use tools like nmap or naabu to confirm MySQL (port 3306) is open:

```bash
nmap -p 3306 localhost
```

### 2. Attempt Login Using Common Credentials
You can use the mysql CLI or tools like hydra or ncrack:

```bash
mysql -h 127.0.0.1 -P 3306 -u root -p
```

Try common passwords like:
- root
- admin
- mysql
- (empty)

## Steps to Write Nuclei Template

### Template Metadata
```yaml
id: mysql-default-login

info:
  name: MySQL - Default Login
  author: DhiyaneshDk, pussycat0x, ritikchaddha
  severity: high
  description: |
    A MySQL service was accessed with easily guessed credentials.
  metadata:
    verified: true
    max-request: 21
    shodan-query: "port:3306"
  tags: js, mysql, default-login, network, fuzz, enum
```

### TCP Service Check + Pre-Condition
```yaml
javascript:
  - pre-condition: |
      isPortOpen(Host,Port);
```

### Credential Brute-force Logic
```yaml
code: |
  var m = require("nuclei/mysql");
  var c = m.MySQLClient();
  c.Connect(Host,Port,User,Pass)
```

### Payloads for Login Attempts
```yaml
args:
  Host: "{{Host}}"
  Port: "3306"
  User: "{{usernames}}"
  Pass: "{{passwords}}"

payloads:
  usernames:
    - root
    - admin
    - mysql
    - test
  passwords:
    - root
    - admin
    - mysql
    - test
    -
```

### Attack Type
```yaml
attack: clusterbomb
```

### Matchers to Confirm Login Success
```yaml
matchers:
  - type: dsl
    dsl:
      - "response == true"
      - "success == true"
    condition: and
```

## Usage

### Nuclei Command
```bash
nuclei -t mysql-default-login.yaml -u <target-ip> -vv
```

### Example
```bash
nuclei -t mysql-default-login.yaml -u 127.0.0.1 -p 3306 -vv
```

## JavaScript Execution Block

### Pre-condition
```yaml
pre-condition: |
  isPortOpen(Host,Port);
```

### Code Logic
```yaml
code: |
  var m = require("nuclei/mysql");
  var c = m.MySQLClient();
  c.Connect(Host,Port,User,Pass)
```

### Arguments and Payloads
```yaml
args:
  Host: "{{Host}}"
  Port: "3306"
  User: "{{usernames}}"
  Pass: "{{passwords}}"

payloads:
  usernames:
    - root
    - admin
    - mysql
    - test
  passwords:
    - root
    - admin
    - mysql
    - test
    -
```

### Attack Strategy
```yaml
attack: clusterbomb
```

### Matchers (Login Success Check)
```yaml
matchers:
  - type: dsl
    dsl:
      - "response == true"
      - "success == true"
    condition: and
```