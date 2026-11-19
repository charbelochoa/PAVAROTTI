from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener
import json
import os
import ssl
import subprocess
import time


origin = os.environ["PAVAROTTI_HTTPS_ORIGIN"]
password = os.environ["PAVAROTTI_TEST_ACCOUNT_PASSWORD"]
case = os.environ["PAVAROTTI_EXPEDIENTE"]
tls = ssl.create_default_context(cafile=os.environ["PAVAROTTI_TLS_CERT_FILE"])
compose = ["docker", "compose", "-f", "compose.https.yaml"]


def client():
    return build_opener(HTTPSHandler(context=tls), HTTPCookieProcessor(CookieJar()))


def request(opener, path, status=200, body=None, source=origin):
    headers = {}
    if body is not None:
        headers = {"Content-Type": "application/json", "Origin": source}
        body = json.dumps(body).encode()
    req = Request(origin + path, data=body, headers=headers)
    try:
        response = opener.open(req, timeout=4)
    except HTTPError as error:
        response = error
    with response:
        assert response.code == status, (path, status, response.code)
        return response.geturl(), response.headers, response.read()


anonymous = client()
address, _, page = request(anonymous, "/")
assert address.endswith("/ingresar") and b"PAVAROTTI" in page
request(anonymous, "/api/app", status=401)
container = subprocess.check_output(compose + ["ps", "-q", "postgres"], text=True).strip()
ports = subprocess.check_output(["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", container], text=True)
assert not json.loads(ports)

accounts = {}
for role in ("lector", "analista"):
    subprocess.run(compose + ["exec", "-T", "app", "pavarotti", "-expediente", case, "usuarios", "guardar",
                               "--nombre", role, "--rol", role, "--clave-archivo", "-"],
                   input=password + "\n", text=True, stdout=subprocess.DEVNULL, check=True, timeout=20)
    opener = client()
    _, headers, _ = request(opener, "/api/acceso/ingresar", status=204, body={"name": role, "password": password})
    cookie = headers["Set-Cookie"].lower()
    assert cookie.startswith("__host-pavarotti-") and all(attr in cookie for attr in ("; secure", "; httponly", "samesite=strict"))
    settings = json.loads(request(opener, "/api/app")[2])
    assert settings["case"] == case and settings["shared"] and settings["account"]["role"] == role
    accounts[role] = opener

note = {"title": "Evidencia HTTPS", "details": "Persistencia de Compose"}
request(accounts["lector"], "/api/nota", status=403, body=note)
request(accounts["analista"], "/api/nota", status=403, body=note, source="https://otro.invalid")
request(accounts["analista"], "/api/nota", body=note)

subprocess.run(compose + ["restart", "app"], check=True, timeout=30)
deadline = time.monotonic() + 30
while True:
    try:
        _, _, evidence = request(accounts["lector"], "/api/registro")
        break
    except (URLError, TimeoutError, ConnectionError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.5)
assert any(item["title"] == note["title"] for item in json.loads(evidence))
events = json.loads(request(accounts["lector"], "/api/actividad")[2])["events"]
assert any(event["action"] == "nota.creada" and event["actor"] == "analista" for event in events)
