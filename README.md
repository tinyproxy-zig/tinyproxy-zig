# Rewrite Tinyproxy in zig

Tinyproxy is a lightweight http(s) proxy daemon.
See https://github.com/tinyproxy/tinyproxy .

### Design

- single thread model: start a coroutine for each connection
- use ziro coroutine engine, libxev based async io

### Features

- [ ] forward proxy
- [ ] upstream
- [ ] transparent proxy
- [ ] reverse proxy
- [ ] filter
- [ ] custom headers
- [ ] acl
- [ ] basic auth
- [ ] stats
- [ ] logging
- [ ] config

### Run and Test

After `zig build run`, tinyproxy will listen on 127.0.0.1:9999, see `config.zig`.

If you want to test single http request:

```shell
curl http://127.0.0.1:9999/
```

or if you want to run benchmark:

```shell
wrk http://127.0.0.1:9999
```

If you want to monitor your request in http layer, use `mitmproxy` or other similar tools.

If you want to monitor your request in tcp layer, use `wireshark`.

### Contribution

All contributions are welcome.

### License

Copyright Dacheng Gao and licensed under MIT.
