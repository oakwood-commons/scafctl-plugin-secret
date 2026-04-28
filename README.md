# scafctl-plugin-secret

Retrieves and lists encrypted secrets from the scafctl secrets store
via HostService RPC calls without accessing the keychain directly.

## Installation

```bash
# Build from source
task build

# Or install from the scafctl catalog
scafctl plugins install secret
```

## Usage

Register this plugin in your scafctl solution, then reference
the **secret** provider in your resolvers:

~~~yaml
resolvers:
  # Get a secret by exact name
  api-token:
    resolve:
      with:
        - provider: secret
          inputs:
            operation: get
            name: api-token
            required: true

  # Get a secret with a fallback value
  optional-token:
    resolve:
      with:
        - provider: secret
          inputs:
            operation: get
            name: optional-token
            required: false
            fallback: default-token

  # Get the first secret matching a regex pattern
  prod-secret:
    resolve:
      with:
        - provider: secret
          inputs:
            operation: get
            pattern: "^prod-.+$"
            required: true

  # List all available secret names
  all-secrets:
    resolve:
      with:
        - provider: secret
          inputs:
            operation: list
~~~

### Operations

| Operation | Description |
|-----------|-------------|
| `get` | Retrieve a single secret by name or regex pattern |
| `list` | List all available secret names |

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `operation` | Yes | One of: `get`, `list` |
| `name` | No | Exact secret name (for `get`; required if `pattern` not set) |
| `pattern` | No | Regex pattern to match secret names (for `get`; returns first match) |
| `required` | No | If true (default), error when secret not found; if false, return fallback |
| `fallback` | No | Value to return when secret not found and `required=false` |

## Development

```bash
# Run tests
task test

# Run linter
task lint

# Run benchmarks
task bench

# Build
task build

# Full CI pipeline
task ci
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
