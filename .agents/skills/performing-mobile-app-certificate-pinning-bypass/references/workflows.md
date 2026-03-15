# Workflows: Certificate Pinning Bypass

## Workflow 1: Escalating Bypass Approach
```
[Configure Burp proxy] --> [App connection fails?] --> [Yes: Pinning active]
                                                              |
                                          [Try Objection generic bypass]
                                                              |
                                                    [Traffic visible?]
                                                    /              \
                                              [Yes: Done]    [No: Advanced]
                                                              |
                                          [Identify pinning library]
                                          [frida-trace *Trust* *Pin*]
                                                              |
                                          [Write custom Frida script]
                                          [Target specific implementation]
                                                              |
                                          [Verify traffic capture]
```

## Decision Matrix
| Pinning Method | Bypass Tool | Difficulty |
|---------------|-------------|-----------|
| OkHttp CertificatePinner | Objection | Easy |
| Network Security Config | Manifest modification | Easy |
| Custom TrustManager | Frida hook | Medium |
| TrustKit | Objection or Frida | Medium |
| Native C/C++ validation | Frida Interceptor.attach | Hard |
| Certificate Transparency | Custom Frida script | Hard |
