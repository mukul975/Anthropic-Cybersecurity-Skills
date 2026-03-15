# Fluentd / Fluent Bit Log Forwarding API Reference

## Fluent Bit CLI

```bash
# Run Fluent Bit with config file
fluent-bit -c /etc/fluent-bit/fluent-bit.conf

# Validate configuration syntax
fluent-bit -c /etc/fluent-bit/fluent-bit.conf --dry-run

# Run with specific input and output (no config file)
fluent-bit -i cpu -o stdout -f 1

# Tail a log file and forward to Fluentd
fluent-bit -i tail -p path=/var/log/syslog -o forward -p host=fluentd.local -p port=24224
```

## Fluentd CLI

```bash
# Start Fluentd with config
fluentd -c /etc/fluentd/fluent.conf

# Validate config file
fluentd --dry-run -c /etc/fluentd/fluent.conf

# Install output plugin
fluent-gem install fluent-plugin-elasticsearch
fluent-gem install fluent-plugin-s3
fluent-gem install fluent-plugin-splunk-hec
```

## Fluent Bit Configuration Sections

```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info

[INPUT]
    Name         tail
    Tag          app.logs
    Path         /var/log/app/*.log
    Parser       json
    DB           /var/log/flb_app.db

[FILTER]
    Name         record_modifier
    Match        *
    Record       hostname ${HOSTNAME}

[OUTPUT]
    Name         forward
    Match        *
    Host         aggregator.local
    Port         24224
```

## Fluentd Configuration Directives

```xml
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<filter **>
  @type record_transformer
  <record>
    hostname "#{Socket.gethostname}"
  </record>
</filter>

<match **>
  @type elasticsearch
  host es.local
  port 9200
  logstash_format true
</match>
```

## Python fluent-logger

```python
from fluent import sender
from fluent import event

# Create sender (default: localhost:24224)
sender.setup('app', host='fluentd.local', port=24224)
event.Event('access', {'user': 'admin', 'action': 'login'})

# Direct sender usage
logger = sender.FluentSender('myapp', host='fluentd.local', port=24224)
logger.emit('follow', {'from': 'userA', 'to': 'userB'})
logger.close()
```

## Forward Protocol (TCP Port 24224)

Messages use MessagePack encoding: `[tag, timestamp, record]`

```bash
# Test connectivity
nc -zv fluentd.local 24224

# Monitor Fluentd buffer status
curl http://localhost:24220/api/plugins.json
```
