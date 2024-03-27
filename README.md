# docker-path-proxy

Package: https://github.com/orgs/jc-lab/packages/container/package/docker-path-proxy-go

- Only support docker v2

# Use-case

All docker registries can be cached through one nexus docker repository.

# Usage

### containerd

```bash
$ ctr image pull --plain-http docker-path-proxy.domain/docker.io/library/alpine:3.16
```

# Environment Variables

## CONFIG_FILE

**config yaml file path**

## PORT

**port**

- default port : 80

# License

[Apache-2.0 License](./LICENSE)
