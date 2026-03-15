# Container Image Hardening Templates

## Hardened Python Dockerfile

```dockerfile
FROM python:3.12-slim-bookworm AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim-bookworm AS production
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin appuser && \
    find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true
COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser src/ /app/src/
USER appuser
WORKDIR /app
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1
EXPOSE 8080
ENTRYPOINT ["python", "-m", "src.main"]
```

## Hardened Go Dockerfile (Distroless)

```dockerfile
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

## Hadolint Configuration

```yaml
# .hadolint.yaml
ignored:
  - DL3008  # Pin versions in apt-get (use --no-install-recommends instead)
trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
```
