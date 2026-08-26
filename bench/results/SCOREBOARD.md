# Real-app bench scoreboard

Generated 2026-08-26 22:05Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-26T21:23Z | 16/52 | 52/52 | 36 | 0 | 0 | 0 |
| battleships | 2026-08-26T21:27Z | 46/57 | 57/57 | 11 | 0 | 0 | 0 |
| docker-flask | 2026-08-26T21:31Z | 12/52 | 19/52 | 7 | 0 | 33 | 0 |
| docker-todo | 2026-08-26T21:35Z | 16/52 | 52/52 | 36 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-26T21:38Z | 12/47 | 14/47 | 2 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-26T21:38Z | 42/57 | 57/57 | 15 | 0 | 0 | 0 |
| gin-basic | 2026-08-26T21:43Z | 16/52 | 52/52 | 36 | 0 | 0 | 0 |
| kutt | 2026-08-26T21:47Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| mdn-static | 2026-08-26T21:49Z | 23/52 | 52/52 | 29 | 0 | 0 | 0 |
| microblog | 2026-08-26T21:52Z | 12/47 | 16/47 | 2 | 1 | 32 | 0 |
| node-getting-started | 2026-08-26T21:53Z | 16/52 | 52/52 | 36 | 0 | 0 | 0 |
| scratch | 2026-08-26T21:56Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-26T21:56Z | 16/52 | 51/52 | 35 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-26T22:00Z | 14/57 | 19/57 | 5 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 41 | 0 | 0 | 1 |
| image | 51 | 35 | 0 | 40 |
| lifecycle | 38 | 146 | 0 | 138 |
| data | 10 | 0 | 0 | 5 |
| network | 14 | 34 | 1 | 7 |
| compose | 20 | 34 | 0 | 1 |
| errors | 30 | 6 | 0 | 6 |
| extras | 67 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | build | 1 | `8525: registry (verified)
[2m2026-08-26T21:24:31.735192Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m invalid Dockerfile: RUN /bin/sh -c cargo buil` |
| actix-basics | image-inspect | 1 | `[2m2026-08-26T21:24:32.050105Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/actix-basics:latest` |
| actix-basics | history | 1 | `[2m2026-08-26T21:24:32.202941Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/actix-basics:latest
error` |
| actix-basics | tag | 1 | `[2m2026-08-26T21:24:32.334004Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/actix-basics:latest
` |
| actix-basics | save | 1 | `[2m2026-08-26T21:24:32.468587Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/actix-basics:latest
error: docker: unknown ` |
| actix-basics | rmi-tag | 1 | `rmi: bench/actix-basics:bench-tag: rmi: not found registry-1.docker.io/bench/actix-basics:bench-tag
[2m2026-08-26T21:24:32.591841Z[0m [31mERROR[0m [2mferro` |
| actix-basics | load | 1 | `[2m2026-08-26T21:24:32.723587Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| actix-basics | run-detached | 1 | `istry returned HTTP 401: {"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/actix-bas` |
| actix-basics | health | 1 | `` |
| actix-basics | logs | 1 | `[2m2026-08-26T21:25:04.117501Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | inspect | 1 | `[2m2026-08-26T21:25:04.249995Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | top | 1 | `[2m2026-08-26T21:25:04.383565Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | stats | 1 | `[2m2026-08-26T21:25:04.519613Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | exec | 1 | `[2m2026-08-26T21:25:04.655352Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | cp-out | 1 | `[2m2026-08-26T21:25:04.783113Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | cp-in | 1 | `[2m2026-08-26T21:25:04.916911Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | diff | 1 | `[2m2026-08-26T21:25:05.056418Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | pause | 1 | `pause: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-26T21:25:05.186361Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m paus` |
| actix-basics | unpause | 1 | `unpause: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-26T21:25:05.316119Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m un` |
| actix-basics | restart | 1 | `restart: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-26T21:25:05.449129Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m re` |
| actix-basics | stop | 1 | `stop: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-26T21:25:05.577513Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop:` |
| actix-basics | start | 1 | `start: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-26T21:25:05.708022Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m star` |
| actix-basics | rename | 1 | `[2m2026-08-26T21:25:05.838705Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | commit | 1 | `[2m2026-08-26T21:25:05.961013Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-actix-basics-r
error: commit: contai` |
| actix-basics | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| actix-basics | kill | 1 | `kill: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-26T21:25:06.226456Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m k` |
| actix-basics | wait | 1 | `wait: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-26T21:25:06.364368Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m w` |
| actix-basics | rm | 1 | `rm: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-26T21:25:06.594128Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm:` |
| actix-basics | rmi-committed | 1 | `rmi: bench/actix-basics:committed: rmi: not found registry-1.docker.io/bench/actix-basics:committed
[2m2026-08-26T21:25:06.718523Z[0m [31mERROR[0m [2mferro` |
| actix-basics | network-create | 1 | `[2m2026-08-26T21:25:06.986143Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| actix-basics | network-run | 1 | `[2m2026-08-26T21:25:07.118523Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-actix-basics-net
error: network: not found ben` |
| actix-basics | network-rm | 1 | `[2m2026-08-26T21:25:07.241811Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-actix-basics-net
error: network: not found ben` |
| actix-basics | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| actix-basics | compose-health | 1 | `` |
| actix-basics | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| actix-basics | err-port-in-use | 1 | ` required","detail":[{"Type":"repository","Class":"","Name":"bench/actix-basics","Action":"pull"}]}]}

error: registry error: registry returned HTTP 401: {"erro` |
| battleships | cp-in | 1 | `[2m2026-08-26T21:28:21.687736Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: put archive: invalid command: archive target unavailable: No su` |
| battleships | start | 1 | `` |
| battleships | commit | 1 | `[2m2026-08-26T21:28:53.138660Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: bind and tmpfs mounts must be removed before committing the roo` |
| battleships | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
[2m2026-08-26T21:28:53.955947Z[0m [31mERROR[0m [2mferro_c` |
| battleships | network-create | 1 | `[2m2026-08-26T21:28:59.477048Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| battleships | network-run | 1 | `[2m2026-08-26T21:28:59.611180Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-battleships-net
error: network: not found benc` |
| battleships | network-rm | 1 | `[2m2026-08-26T21:28:59.742242Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-battleships-net
error: network: not found benc` |
| battleships | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| battleships | compose-health | 1 | `` |
| battleships | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| docker-flask | network-create | 1 | `[2m2026-08-26T21:33:08.006713Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| docker-flask | network-rm | 1 | `[2m2026-08-26T21:33:08.139187Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-docker-flask-net
error: network: not found ben` |
| docker-flask | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `[2m2026-08-26T21:35:10.301861Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-flask | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| docker-flask | compose-down | 1 | `[2m2026-08-26T21:35:10.515587Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-todo | build | 1 | ` (verified)
layer sha256:7d81ded9d9d91300a049431a3130956a89c86eb93b66adc2a0e0d4da6944b576: registry (verified)
layer sha256:736dd3f75c3cb794a01a2a33a1fb9cac98e4` |
| docker-todo | image-inspect | 1 | `[2m2026-08-26T21:35:58.878137Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/docker-todo:latest
` |
| docker-todo | history | 1 | `[2m2026-08-26T21:35:59.006806Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/docker-todo:latest
error:` |
| docker-todo | tag | 1 | `[2m2026-08-26T21:35:59.132731Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/docker-todo:latest
e` |
| docker-todo | save | 1 | `[2m2026-08-26T21:35:59.260480Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/docker-todo:latest
error: docker: unknown i` |
| docker-todo | rmi-tag | 1 | `rmi: bench/docker-todo:bench-tag: rmi: not found registry-1.docker.io/bench/docker-todo:bench-tag
[2m2026-08-26T21:35:59.395686Z[0m [31mERROR[0m [2mferro_c` |
| docker-todo | load | 1 | `[2m2026-08-26T21:35:59.530410Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| docker-todo | run-detached | 1 | `egistry returned HTTP 401: {"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-` |
| docker-todo | health | 1 | `` |
| docker-todo | logs | 1 | `[2m2026-08-26T21:36:31.016251Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | inspect | 1 | `[2m2026-08-26T21:36:31.152933Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | top | 1 | `[2m2026-08-26T21:36:31.282517Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | stats | 1 | `[2m2026-08-26T21:36:31.419879Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | exec | 1 | `[2m2026-08-26T21:36:31.563604Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | cp-out | 1 | `[2m2026-08-26T21:36:31.716662Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | cp-in | 1 | `[2m2026-08-26T21:36:31.851273Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | diff | 1 | `[2m2026-08-26T21:36:31.975574Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-26T21:36:32.107911Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause:` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-26T21:36:32.240882Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpa` |
| docker-todo | restart | 1 | `restart: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-26T21:36:32.374925Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rest` |
| docker-todo | stop | 1 | `stop: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-26T21:36:32.506505Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1` |
| docker-todo | start | 1 | `start: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-26T21:36:32.635364Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start:` |
| docker-todo | rename | 1 | `[2m2026-08-26T21:36:32.766442Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | commit | 1 | `[2m2026-08-26T21:36:32.898010Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-docker-todo-r
error: commit: contain` |
| docker-todo | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-26T21:36:33.166389Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kil` |
| docker-todo | wait | 1 | `wait: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-26T21:36:33.301905Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wai` |
| docker-todo | rm | 1 | `rm: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-26T21:36:33.534955Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1` |
| docker-todo | rmi-committed | 1 | `rmi: bench/docker-todo:committed: rmi: not found registry-1.docker.io/bench/docker-todo:committed
[2m2026-08-26T21:36:33.675163Z[0m [31mERROR[0m [2mferro_c` |
| docker-todo | network-create | 1 | `[2m2026-08-26T21:36:33.927426Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| docker-todo | network-run | 1 | `[2m2026-08-26T21:36:34.064063Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-docker-todo-net
error: network: not found benc` |
| docker-todo | network-rm | 1 | `[2m2026-08-26T21:36:34.192412Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-docker-todo-net
error: network: not found benc` |
| docker-todo | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| docker-todo | compose-health | 1 | `` |
| docker-todo | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| docker-todo | err-port-in-use | 1 | `ion required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: registry error: registry returned HTTP 401: {"er` |
| fastapi-fullstack | network-create | 1 | `[2m2026-08-26T21:38:47.634625Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| fastapi-fullstack | network-rm | 1 | `[2m2026-08-26T21:38:47.761340Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-fastapi-fullstack-net
error: network: not foun` |
| flask-tutorial | health | 1 | `` |
| flask-tutorial | cp-in | 1 | `[2m2026-08-26T21:39:54.772671Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: put archive: invalid command: archive target unavailable: No su` |
| flask-tutorial | pause | 1 | `pause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
[2m2026-08-26T21:39:56.137321Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0` |
| flask-tutorial | unpause | 1 | `unpause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
[2m2026-08-26T21:39:56.265865Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| flask-tutorial | restart | 1 | `` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `[2m2026-08-26T21:40:57.756977Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: bind and tmpfs mounts must be removed before committing the roo` |
| flask-tutorial | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
[2m2026-08-26T21:40:58.617447Z[0m [31mERROR[0m [2mf` |
| flask-tutorial | network-create | 1 | `[2m2026-08-26T21:41:03.625579Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| flask-tutorial | network-run | 1 | `[2m2026-08-26T21:41:03.758165Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-flask-tutorial-net
error: network: not found b` |
| flask-tutorial | network-rm | 1 | `[2m2026-08-26T21:41:03.886669Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-flask-tutorial-net
error: network: not found b` |
| flask-tutorial | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| flask-tutorial | compose-health | 1 | `` |
| flask-tutorial | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| gin-basic | build | 1 | `[0m [2mferro_cli::linux_cli[0m[2m:[0m invalid Dockerfile: RUN /bin/sh -c go mod download && CGO_ENABLED=0 go build -buildvcs=false -o /out/app ./basic fail` |
| gin-basic | image-inspect | 1 | `[2m2026-08-26T21:44:33.539130Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/gin-basic:latest
er` |
| gin-basic | history | 1 | `[2m2026-08-26T21:44:33.812616Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/gin-basic:latest
error: h` |
| gin-basic | tag | 1 | `[2m2026-08-26T21:44:33.962101Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/gin-basic:latest
err` |
| gin-basic | save | 1 | `[2m2026-08-26T21:44:34.128934Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/gin-basic:latest
error: docker: unknown ima` |
| gin-basic | rmi-tag | 1 | `rmi: bench/gin-basic:bench-tag: rmi: not found registry-1.docker.io/bench/gin-basic:bench-tag
[2m2026-08-26T21:44:34.288157Z[0m [31mERROR[0m [2mferro_cli::` |
| gin-basic | load | 1 | `[2m2026-08-26T21:44:34.433106Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| gin-basic | run-detached | 1 | `r: registry returned HTTP 401: {"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gin` |
| gin-basic | health | 1 | `` |
| gin-basic | logs | 1 | `[2m2026-08-26T21:45:06.219350Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | inspect | 1 | `[2m2026-08-26T21:45:06.382962Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | top | 1 | `[2m2026-08-26T21:45:06.548649Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | stats | 1 | `[2m2026-08-26T21:45:06.685039Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | exec | 1 | `[2m2026-08-26T21:45:06.838656Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | cp-out | 1 | `[2m2026-08-26T21:45:06.992408Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | cp-in | 1 | `[2m2026-08-26T21:45:07.213573Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | diff | 1 | `[2m2026-08-26T21:45:07.358840Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | pause | 1 | `pause: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-26T21:45:07.510816Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause: 1 c` |
| gin-basic | unpause | 1 | `unpause: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-26T21:45:07.666183Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpause:` |
| gin-basic | restart | 1 | `restart: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-26T21:45:07.811293Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m restart:` |
| gin-basic | stop | 1 | `stop: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-26T21:45:07.934733Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1 con` |
| gin-basic | start | 1 | `start: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-26T21:45:08.070069Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start: 1 c` |
| gin-basic | rename | 1 | `[2m2026-08-26T21:45:08.194941Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | commit | 1 | `[2m2026-08-26T21:45:08.330463Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-gin-basic-r
error: commit: container` |
| gin-basic | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| gin-basic | kill | 1 | `kill: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-26T21:45:08.607132Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kill: 1` |
| gin-basic | wait | 1 | `wait: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-26T21:45:08.754568Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wait: 1` |
| gin-basic | rm | 1 | `rm: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-26T21:45:08.975944Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1 con` |
| gin-basic | rmi-committed | 1 | `rmi: bench/gin-basic:committed: rmi: not found registry-1.docker.io/bench/gin-basic:committed
[2m2026-08-26T21:45:09.105787Z[0m [31mERROR[0m [2mferro_cli::` |
| gin-basic | network-create | 1 | `[2m2026-08-26T21:45:09.375441Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| gin-basic | network-run | 1 | `[2m2026-08-26T21:45:09.510637Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-gin-basic-net
error: network: not found bench-` |
| gin-basic | network-rm | 1 | `[2m2026-08-26T21:45:09.647364Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-gin-basic-net
error: network: not found bench-` |
| gin-basic | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| gin-basic | compose-health | 1 | `` |
| gin-basic | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| gin-basic | err-port-in-use | 1 | `ntication required","detail":[{"Type":"repository","Class":"","Name":"bench/gin-basic","Action":"pull"}]}]}

error: registry error: registry returned HTTP 401: ` |
| kutt | network-create | 1 | `[2m2026-08-26T21:47:18.818500Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| kutt | network-rm | 1 | `[2m2026-08-26T21:47:18.958653Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-kutt-net
error: network: not found bench-kutt-` |
| kutt | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| kutt | compose-health | 1 | `` |
| kutt | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| mdn-static | run-detached | 1 | `[2m2026-08-26T21:50:16.893360Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m command is required to run container
error: command is required to run ` |
| mdn-static | health | 1 | `` |
| mdn-static | logs | 1 | `[2m2026-08-26T21:50:47.576761Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | inspect | 1 | `[2m2026-08-26T21:50:47.702745Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | top | 1 | `[2m2026-08-26T21:50:47.860027Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | stats | 1 | `[2m2026-08-26T21:50:48.000300Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | exec | 1 | `[2m2026-08-26T21:50:48.131042Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | cp-out | 1 | `[2m2026-08-26T21:50:48.262369Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | cp-in | 1 | `[2m2026-08-26T21:50:48.397628Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | diff | 1 | `[2m2026-08-26T21:50:48.537113Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-26T21:50:48.676234Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause: 1` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-26T21:50:48.828672Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpaus` |
| mdn-static | restart | 1 | `restart: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-26T21:50:48.977564Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m restar` |
| mdn-static | stop | 1 | `stop: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-26T21:50:49.095433Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1 c` |
| mdn-static | start | 1 | `start: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-26T21:50:49.227370Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start: 1` |
| mdn-static | rename | 1 | `[2m2026-08-26T21:50:49.357903Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | commit | 1 | `[2m2026-08-26T21:50:49.494061Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-mdn-static-r
error: commit: containe` |
| mdn-static | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-26T21:50:49.757812Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kill:` |
| mdn-static | wait | 1 | `wait: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-26T21:50:49.904005Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wait:` |
| mdn-static | rm | 1 | `rm: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-26T21:50:50.130776Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1 c` |
| mdn-static | rmi-committed | 1 | `rmi: bench/mdn-static:committed: rmi: not found registry-1.docker.io/bench/mdn-static:committed
[2m2026-08-26T21:50:50.255692Z[0m [31mERROR[0m [2mferro_cli` |
| mdn-static | network-create | 1 | `[2m2026-08-26T21:50:50.524236Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| mdn-static | network-run | 1 | `[2m2026-08-26T21:50:50.668521Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-mdn-static-net
error: network: not found bench` |
| mdn-static | network-rm | 1 | `[2m2026-08-26T21:50:50.793842Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-mdn-static-net
error: network: not found bench` |
| mdn-static | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| mdn-static | compose-health | 1 | `` |
| mdn-static | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| mdn-static | err-port-in-use | 1 | `[2m2026-08-26T21:52:54.154709Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m command is required to run container
error: command is required to run ` |
| microblog | network-create | 1 | `[2m2026-08-26T21:53:01.309208Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| microblog | network-rm | 1 | `[2m2026-08-26T21:53:01.724313Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-microblog-net
error: network: not found bench-` |
| node-getting-started | build | 1 | `[2m2026-08-26T21:53:18.680987Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m invalid Dockerfile: COPY source /data/dev/bench-apps/node-getting-start` |
| node-getting-started | image-inspect | 1 | `[2m2026-08-26T21:53:18.889065Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/node-getting-starte` |
| node-getting-started | history | 1 | `[2m2026-08-26T21:53:19.020730Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/node-getting-started:late` |
| node-getting-started | tag | 1 | `[2m2026-08-26T21:53:19.149265Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/node-getting-started` |
| node-getting-started | save | 1 | `[2m2026-08-26T21:53:19.281597Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/node-getting-started:latest
error: docker: ` |
| node-getting-started | rmi-tag | 1 | `rmi: bench/node-getting-started:bench-tag: rmi: not found registry-1.docker.io/bench/node-getting-started:bench-tag
[2m2026-08-26T21:53:19.419802Z[0m [31mERR` |
| node-getting-started | load | 1 | `[2m2026-08-26T21:53:19.556742Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| node-getting-started | run-detached | 1 | `TTP 401: {"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/node-getting-started","Ac` |
| node-getting-started | health | 1 | `` |
| node-getting-started | logs | 1 | `[2m2026-08-26T21:53:50.999206Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | inspect | 1 | `[2m2026-08-26T21:53:51.128092Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | top | 1 | `[2m2026-08-26T21:53:51.260264Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | stats | 1 | `[2m2026-08-26T21:53:51.395028Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | exec | 1 | `[2m2026-08-26T21:53:51.527194Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | cp-out | 1 | `[2m2026-08-26T21:53:51.661379Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | cp-in | 1 | `[2m2026-08-26T21:53:51.796267Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | diff | 1 | `[2m2026-08-26T21:53:51.923640Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | pause | 1 | `pause: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-26T21:53:52.067874Z[0m [31mERROR[0m [2mferro_cli::linux_cli[` |
| node-getting-started | unpause | 1 | `unpause: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-26T21:53:52.195320Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | restart | 1 | `restart: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-26T21:53:52.330655Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | stop | 1 | `stop: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-26T21:53:52.458747Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0` |
| node-getting-started | start | 1 | `start: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-26T21:53:52.595245Z[0m [31mERROR[0m [2mferro_cli::linux_cli[` |
| node-getting-started | rename | 1 | `[2m2026-08-26T21:53:52.728115Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | commit | 1 | `[2m2026-08-26T21:53:52.863011Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-node-getting-started-r
error: commit` |
| node-getting-started | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-26T21:53:53.135525Z[0m [31mERROR[0m [2mferro_cli::linux_cl` |
| node-getting-started | wait | 1 | `wait: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-26T21:53:53.272036Z[0m [31mERROR[0m [2mferro_cli::linux_cl` |
| node-getting-started | rm | 1 | `rm: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-26T21:53:53.503146Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | rmi-committed | 1 | `rmi: bench/node-getting-started:committed: rmi: not found registry-1.docker.io/bench/node-getting-started:committed
[2m2026-08-26T21:53:53.639246Z[0m [31mERR` |
| node-getting-started | network-create | 1 | `[2m2026-08-26T21:53:53.903561Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| node-getting-started | network-run | 1 | `[2m2026-08-26T21:53:54.041337Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-node-getting-started-net
error: network: not f` |
| node-getting-started | network-rm | 1 | `[2m2026-08-26T21:53:54.170606Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-node-getting-started-net
error: network: not f` |
| node-getting-started | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| node-getting-started | compose-health | 1 | `` |
| node-getting-started | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| node-getting-started | err-port-in-use | 1 | `ype":"repository","Class":"","Name":"bench/node-getting-started","Action":"pull"}]}]}

error: registry error: registry returned HTTP 401: {"errors":[{"code":"UN` |
| spring-petclinic | build | 1 | `eb539654ddd7d70efe53: registry (verified)
[2m2026-08-26T21:59:05.285822Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m invalid Dockerfile: RUN /bin/` |
| spring-petclinic | image-inspect | 1 | `[2m2026-08-26T21:59:06.794244Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/spring-petclinic:la` |
| spring-petclinic | history | 1 | `[2m2026-08-26T21:59:06.918974Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/spring-petclinic:latest
e` |
| spring-petclinic | tag | 1 | `[2m2026-08-26T21:59:07.048887Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/spring-petclinic:lat` |
| spring-petclinic | save | 1 | `[2m2026-08-26T21:59:07.173243Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/spring-petclinic:latest
error: docker: unkn` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
[2m2026-08-26T21:59:07.317969Z[0m [31mERROR[0m ` |
| spring-petclinic | load | 1 | `[2m2026-08-26T21:59:07.448663Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| spring-petclinic | run-detached | 1 | `turned HTTP 401: {"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic"` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `[2m2026-08-26T21:59:51.658999Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | inspect | 1 | `[2m2026-08-26T21:59:51.788492Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | top | 1 | `[2m2026-08-26T21:59:51.915734Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | stats | 1 | `[2m2026-08-26T21:59:52.049104Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | exec | 1 | `[2m2026-08-26T21:59:52.181562Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | cp-out | 1 | `[2m2026-08-26T21:59:52.315780Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | cp-in | 1 | `[2m2026-08-26T21:59:52.445911Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | diff | 1 | `[2m2026-08-26T21:59:52.573844Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-26T21:59:52.698441Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-26T21:59:52.838994Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-26T21:59:52.979875Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-26T21:59:53.106622Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-26T21:59:53.243060Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | rename | 1 | `[2m2026-08-26T21:59:53.370997Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | commit | 1 | `[2m2026-08-26T21:59:53.506787Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-spring-petclinic-r
error: commit: co` |
| spring-petclinic | export | 2 | `error: the following required arguments were not provided:
  --output <OUTPUT>

Usage: ferro-cli export --output <OUTPUT> <CONTAINER>

For more information, try` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-26T21:59:53.770583Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-26T21:59:53.907738Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-26T21:59:54.139234Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
[2m2026-08-26T21:59:54.268184Z[0m [31mERROR[0m ` |
| spring-petclinic | network-create | 1 | `[2m2026-08-26T21:59:54.531839Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| spring-petclinic | network-run | 1 | `[2m2026-08-26T21:59:54.663210Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-spring-petclinic-net
error: network: not found` |
| spring-petclinic | network-rm | 1 | `[2m2026-08-26T21:59:54.800250Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-spring-petclinic-net
error: network: not found` |
| spring-petclinic | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| spring-petclinic | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
| spring-petclinic | err-port-in-use | 1 | `detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | network-create | 1 | `[2m2026-08-26T22:00:05.856784Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m custom networks need rootful mode
error: custom networks need rootful m` |
| uptime-kuma | network-rm | 1 | `[2m2026-08-26T22:00:05.976941Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m network: not found bench-uptime-kuma-net
error: network: not found benc` |
| uptime-kuma | compose-up | 2 | `error: unexpected argument '--build' found

  tip: to pass '--build' as a value, use '-- --build'

Usage: ferro-cli compose up --detach [SERVICES]...

For more ` |
| uptime-kuma | compose-health | 1 | `` |
| uptime-kuma | compose-logs | 2 | `error: unexpected argument '--tail' found

Usage: ferro-cli compose logs

For more information, try '--help'.
` |
