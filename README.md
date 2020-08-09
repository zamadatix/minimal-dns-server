# Minimal DNS Server
## What
A bare-bones non recursive DNS server capable of hosting `A` or `AAAA` records. Intentionally not standards compliant - this server only responds with packets to clients that made a request the server is able to fully fulfil locally. Any other request will be silently dropped. Only queries over UDP are supported to achieve this. Does not support multiple queries in one request but will always respond with the corresponding `A` or `AAAA` record as an additional record if a domain has both defined. There are probably a few bits that should be treated more leniently and a few that should probably be sent in the response but it does work. If you're looking for more feature coverage it's probably easier to start from scratch than try to adapt this code, it takes many shortcuts via lots of assumptions about the use case.

Listens on all IPv4 and IPv6 interfaces by default. If you want v4 only modify the socket creation to `udp4`. If you want v6 only modify the socket creation to have the `ipv6Only` option which disables IPv4 mapped IPv6 addresses.

Basic logging of errors and query logging (for valid queries) to `dns.log`.

There is also a rudimentary service definition file for Open-RC you can drop in `/etc/init.d/`. To add to boot `rc-update add dns`

## Why

Fun weekend project to remove another external dependency (BIND) from my self hosted infrastructure.

## Future plans
I'd like to convert the code to Zig to remove the Node dependency and be a step closer to removing MUSL libc. Once that's done there are a few features I'd still like to add while keeping it minimal:

- Automatic generation of the record `a` and `aaaa` buffers from IP strings
- Move the records file and logging configuration out of the source code and into a config file
- Add support for TXT records (to work towards Let's Encrypt integration)
- Create a more featureful service definition

## License

MIT
