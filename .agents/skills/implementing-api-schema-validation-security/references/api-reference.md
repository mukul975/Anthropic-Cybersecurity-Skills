# API Reference: Implementing API Schema Validation Security

## jsonschema (Python)

```python
import jsonschema
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "maxLength": 100},
        "email": {"type": "string", "format": "email"},
    },
    "required": ["name", "email"],
    "additionalProperties": False,  # Prevent mass assignment
}
jsonschema.validate(instance=payload, schema=schema)
```

## OpenAPI Security Checks

| Check | Risk | Severity |
|-------|------|----------|
| No request body schema | Injection | HIGH |
| additionalProperties: true | Mass assignment | MEDIUM |
| String without maxLength | Buffer overflow | MEDIUM |
| No response schema | Data exposure | MEDIUM |
| No security scheme | Broken auth | CRITICAL |
| Security explicitly disabled | Unauthenticated access | CRITICAL |

## OpenAPI Schema Best Practices

```yaml
components:
  schemas:
    User:
      type: object
      additionalProperties: false
      properties:
        name:
          type: string
          maxLength: 100
          pattern: "^[a-zA-Z ]+$"
        email:
          type: string
          format: email
          maxLength: 255
      required: [name, email]
```

## Spectral (OpenAPI Linter)

```bash
spectral lint openapi.yaml --ruleset .spectral.yaml
# Custom security rules in .spectral.yaml
```

### References

- jsonschema: https://python-jsonschema.readthedocs.io/
- OpenAPI 3.0: https://spec.openapis.org/oas/v3.0.3
- Spectral: https://stoplight.io/open-source/spectral
