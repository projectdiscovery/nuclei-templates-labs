# Exposed MCP Server

## Description:
Detects exposed Machine Control Protocol (MCP) servers through JSON-RPC 2.0 API endpoints.MCP servers often provide administrative access to AI tools, LLM systems, or other automation infrastructure.Exposed MCP interfaces can lead to unauthorized access, information disclosure, and potential system compromise.This template tests multiple detection methods including tools/list, rpc.discover, resources/list, and prompts/list.

## Reference:
- https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http

## Vulnerable Setup

- Execute the following commands to start the MCP server:

```bash
docker compose up --build -d
```

- After the server is started, navigate to http://localhost:8080/mcp, the expected response is

```json
{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}
```

## Exploitation Steps

- Send a HTTP POST request to the `/mcp` endpoint, containing a valid method:

```bash
curl -X POST http://localhost:8080/mcp/ -H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" --data '{"jsonrpc": "2.0","method": "tools/list","params": {},"id": 1}'
```

- The response will list the tools that are avaliable to the LLM:

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"start-notification-stream","description":"Sends a stream of notifications with configurable count and interval","inputSchema":{"type":"object","required":["interval","count","caller"],"properties":{"interval":{"type":"number","description":"Interval between notifications in seconds"},"count":{"type":"number","description":"Number of notifications to send"},"caller":{"type":"string","description":"Identifier of the caller to include in notifications"}}}}]}}
```

## Steps to Write Nuclei Template

**HTTP Request Section**

```yaml
- method: POST
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/mcp/"
```

- The MCP specification does not define what the endpoint will be but it may be under the root or `/mcp/`

```yaml
    headers:
      Accept: application/json, text/event-stream
      Content-Type: application/json
```

- `headers` is required as the specification states that the mcp endpoint MUST include an accept header, listing both application/json and text/event-stream as supported content types.

**Attack Mode**
```yml
attack: pitchfork
```
- This mode places a the payload into each position.  

**Payloads**

```yaml
    payloads:
      method:
        - rpc.discover
        - rpc.describe
        - rpc.listTools
        - tools/list
        - resources/list
        - prompts/list
        - tool.status
        - tool.help
        - tool.version
        - tool.list
```

- These are a list of all the avaliable methods in the protocol. The pitchfork attack will send 1 request per avaliable method

**Matchers Section**

```yaml
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "jsonrpc"
          - "result"
        condition: and

      - type: regex
        part: body
        regex:
          - "\"available_tools\"\\s*:\\s*\\["
          - "\"name\"\\s*:\\s*\"get_tools\""
          - "\"server_status\"\\s*:\\s*\\{"
          - "\"observatories_by_type\""
          - "\"parameters\"\\s*:\\s*\\{"
          - "\"tools\"\\s*:\\s*\\[.*?\\]"
          - "\"resources\"\\s*:\\s*\\[.*?\\]"
          - "\"prompts\"\\s*:\\s*\\[.*?\\]"
```

- `matchers-condition: and` match both the words `jsonrpc` and `result` in the response aswell as `regex` for the json-rpc responses to those methods.

**Extractors Section**

```yaml
    extractors:
      - type: regex
        part: body
        regex:
          - "\"name\"\\s*:\\s*\"([^\"]+)\""
```

- `type: regex` to extract the name of the important resource.

## Nuclei Template URL : [exposed-mcp-server](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/apis/exposed-mcp-server.yaml)

## Nuclei Command :

```bash
nuclei -id exposed-mcp-server -u http://localhost:8080 -vv
```

![image](https://github.com/user-attachments/assets/980ff913-41c7-4668-a4da-1b0a4742c8e2)
