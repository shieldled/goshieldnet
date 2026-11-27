<!-- This page shows examples/README.md and the example sources; edit those. -->
{% include-markdown "../../examples/README.md" %}

## The sources

### `server/main.go` {#server-main-go}

```go
{% include "../../examples/server/main.go" %}
```

### `client/main.go` {#client-main-go}

```go
{% include "../../examples/client/main.go" %}
```

### `internal/secret/secret.go` {#internal-secret-secret-go}

How both examples read a key from a mode-0600 file or the environment.

```go
{% include "../../examples/internal/secret/secret.go" %}
```
