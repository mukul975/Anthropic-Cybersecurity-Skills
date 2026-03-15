# API Reference: Rsyslog Centralization with TLS

## Rsyslog Server Configuration Directives

### TLS Module Loading
```
module(load="imtcp"
    StreamDriver.Name="gtls"
    StreamDriver.Mode="1"
    StreamDriver.Authmode="x509/name"
    PermittedPeer=["client1.local","client2.local"])
```

### Global TLS Settings
```
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/path/to/ca.pem"
    DefaultNetstreamDriverCertFile="/path/to/cert.pem"
    DefaultNetstreamDriverKeyFile="/path/to/key.pem")
```

### Template Syntax
```
template(name="PerHostDir" type="string"
    string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
template(name="JSONFormat" type="string"
    string='{"host":"%HOSTNAME%","msg":"%msg:::json%"}\n')
```

## Rsyslog Client Forwarding
```
action(type="omfwd" target="<server>" port="6514" protocol="tcp"
    StreamDriver="gtls" StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    queue.type="LinkedList" queue.filename="fwdRule1"
    queue.maxdiskspace="1g" queue.saveonshutdown="on"
    action.resumeRetryCount="-1")
```

## Jinja2 Template Engine
```python
from jinja2 import Template
tmpl = Template("target={{ server_ip }} port={{ port }}")
output = tmpl.render(server_ip="10.0.0.1", port=6514)
```

## Paramiko SSH Deployment
```python
import paramiko
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(hostname=host, username=user, key_filename=key)
sftp = client.open_sftp()
sftp.file(remote_path, "w").write(content)
client.exec_command("systemctl restart rsyslog")
client.close()
```

## OpenSSL Certificate Generation
```bash
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca.pem -days 3650 -nodes
openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr -nodes
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem
```
