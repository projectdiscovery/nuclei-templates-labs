# EMQX Default Login

## Description:
EMQX is an open-source MQTT broker that provides a web-based Dashboard for management and monitoring.  
By default, EMQX includes predefined administrative credentials, which, if not changed, can pose security risks.  
An attacker could leverage these default credentials to gain unauthorized access, potentially leading to exposure of sensitive information, data modification, or execution of unauthorized operations.

## Reference:
- https://docs.emqx.com/en/emqx/latest/dashboard/introduction.html

## Vulnerable Setup

- Execute the following commands to start a Laravel Voyager 1.8.0 server:

```bash
docker compose up -d
```

- After the server is started, browse to http://your-ip:8000 to see the Laravel Voyager admin panel. This server requires authentication.

## Default Login   

Username: admin

Password: public

## Exploitation Steps
Navigate to the EMQX Dashboard at http://your-ip:18083.

Enter the default credentials (admin / public).

Upon successful login, you will have administrative access to the EMQX Dashboard.


## Steps to Write Nuclei Template
### Variables Section
Define the login credentials as variables for reuse in requests:

```
variables:
  username: "admin"
  password: "public"
  ```
### Request: Perform Login
Send a POST request to the EMQX authentication endpoint with the defined credentials:
```
- raw:
    - |
      POST /api/v4/auth HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"{{username}}","password":"{{password}}"}

  matchers:
    - type: dsl
      dsl:
        - 'contains(body, "{\"code\":0}")'
        - 'status_code == 200'
      condition: and
```
This template attempts to authenticate using the default credentials and checks for a successful login response.

## Nuclei Template URL
[EMQX Default Admin Login](https://github.com/projectdiscovery/nuclei-templates/blob/64c51343a069c230e693d275d9911a72c9f9928e/http/default-logins/emqx/emqx-default-login.yaml)

## Nuclei Command :

```bash
nuclei -id emqx-default-login -u http://<IP>:18083 -vv
```