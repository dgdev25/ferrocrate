# Registry transport and authentication

Ferrocrate uses OCI Distribution over HTTPS for remote registries. Disposable
local registries retain the historical HTTP default; production qualification
must set `FERROCRATE_REGISTRY_TLS=1` for a local host/port reference.

For a private TLS registry signed by an internal CA, point the registry client
at a bounded, regular PEM file:

```bash
export FERROCRATE_REGISTRY_TLS=1
export FERROCRATE_REGISTRY_CA_CERT=/etc/ferrocrate/registry-ca.pem
export DOCKER_CONFIG=/etc/ferrocrate/docker-config
export FERROCRATE_SIGNATURE_VERIFY=1
export FERROCRATE_SIGNATURE_KEY=/etc/ferrocrate/cosign.pub
ferrocrate pull registry.example:5443/team/app@sha256:<digest>
ferrocrate run registry.example:5443/team/app@sha256:<digest>
```

Registry credentials are resolved through the existing Ferrocrate/Docker
credential configuration. The CA path must be a regular file no larger than
1 MiB; invalid, empty, oversized, or substituted paths fail before a request is
sent. Remote registry references remain HTTPS regardless of the local override.
