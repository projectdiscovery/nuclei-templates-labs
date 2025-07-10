# Exposed MCP SSE Server

## Description:
Detects exposed Model Context Protocol (MCP) servers through the SSE API. MCP servers often provide administrative access to AI tools, LLM systems, or other automation infrastructure. Exposed MCP interfaces can lead to unauthorized access, information disclosure, and potential system compromise. This template detects a SSE server event stream and returns the messages endpoint which can be used to POST JSON-RPC 2.0 requests.

## Reference:
- https://modelcontextprotocol.io/specification/2024-11-05/basic/transports#http-with-sse

## Vulnerable Setup

- Execute the following commands to start the MCP SSE server:

```bash
docker compose up --build -d
```

- After the server is started, you can send a GET request to the `/sse` endpoint this will start a Server-Side Event stream. And the first event will be a `/messages` endpoint and sessionid where the MCP JSON can be sent to.

## Exploitation Steps

- Send a HTTP GET request to the `/sse` endpoint:

```bash
curl http://localhost:8081/sse
```

- The response will send a messages event, such as:

```bash
event: endpoint
data: /messages/?session_id=512b026054d04af78c834cb9a5af4e97
```

- As it is an event stream you will receive the JSON-RPC responses here from any messages POST'ed to the `/messages/?session_id=512b026054d04af78c834cb9a5af4e97` endpoint.

## Steps to Write Nuclei Template

**HTTP Request Section**

```yaml
- method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/sse"
```

- The MCP specification does not define what the endpoint will be but it may be under the root or `/sse`

```yaml
    max-size: 100
```

- `max-size` is required as the response is streamed, otherwise nuclei will timeout

**Matchers Section**

```yaml
    stop-at-first-match: true

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(content_type, 'text/event-stream')"
          - "status_code == 406 && contains(content_type, 'application/json')"
        condition: or

      - type: dsl
        dsl:
          - "contains(body, 'event: endpoint')"
          - "contains(body, 'Not Acceptable: Client must accept text/event-stream')"
        condition: or
```

- `stop-at-first-match: true` is used to stop making aditional request if the matchers find a hit.

- `type: dsl` matches a 200 status code and a `text/event-stream` *or* a 406 status code and a `application/json` response

- `type: dsl` matches the first event as defined in the spec as an endpoint event *or* Not Acceptable

**Extractors Section**

```yaml
    extractors:
      - type: regex
        name: message_endpoint
        regex:
          - 'data: ([/?_=a-zA-Z0-9-]+)'
```

- `type: regex` to match the data of the event which will be the messages endpoint with a session_id.

## Nuclei Template URL : [exposed-mcp-sse-server](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/apis/exposed-mcp-sse-server.yaml)

## Nuclei Command :

```bash
nuclei -id exposed-mcp-sse-server -u http://localhost:8080 -vv
```

![image](https://github.com/user-attachments/assets/b66cc8da-a42a-41e9-b568-7520dbff5631)
