# Real-app bench scoreboard

Generated 2026-08-27 19:00Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-27T08:00Z | 49/52 | 52/52 | 3 | 0 | 0 | 0 |
| battleships | 2026-08-26T23:54Z | 52/57 | 57/57 | 5 | 0 | 0 | 0 |
| docker-flask | 2026-08-26T23:58Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-27T08:10Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-27T00:06Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-27T00:06Z | 48/57 | 57/57 | 9 | 0 | 0 | 0 |
| gin-basic | 2026-08-27T08:04Z | 49/52 | 52/52 | 3 | 0 | 0 | 0 |
| kutt | 2026-08-27T00:14Z | 17/52 | 19/52 | 2 | 0 | 33 | 0 |
| mdn-static | 2026-08-27T00:16Z | 26/52 | 52/52 | 26 | 0 | 0 | 0 |
| microblog | 2026-08-27T00:19Z | 14/47 | 16/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-27T08:07Z | 28/52 | 52/52 | 24 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-27T08:13Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-27T00:24Z | 17/57 | 19/57 | 2 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 41 | 0 | 0 | 1 |
| image | 72 | 14 | 0 | 40 |
| lifecycle | 84 | 100 | 0 | 138 |
| data | 10 | 0 | 0 | 5 |
| network | 45 | 3 | 1 | 7 |
| compose | 30 | 24 | 0 | 1 |
| errors | 33 | 3 | 0 | 6 |
| extras | 67 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | start | 1 | `` |
| actix-basics | compose-up | 1 | `2026-08-27T08:02:17.868780Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: runtime mutation mediation failed: compose execution request dig` |
| actix-basics | compose-health | 1 | `` |
| battleships | start | 1 | `` |
| battleships | commit | 1 | `[2m2026-08-26T23:55:41.139332Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: bind and tmpfs mounts must be removed before committing the roo` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
[2m2026-08-26T23:55:42.135372Z[0m [31mERROR[0m [2mferro_c` |
| battleships | compose-up | 1 | `[2m2026-08-26T23:55:54.199706Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: battleships run failed: runtime mutation mediat` |
| battleships | compose-health | 1 | `` |
| docker-flask | compose-up | 1 | `[2m2026-08-26T23:58:09.337604Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `[2m2026-08-27T00:00:10.469060Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-flask | compose-logs | 1 | `[2m2026-08-27T00:00:10.586525Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-flask | compose-down | 1 | `[2m2026-08-27T00:00:10.706481Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose parse error: services.web.healthcheck.test: invalid type: strin` |
| docker-todo | build | 1 | `2026-08-27T08:10:28.930643Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| docker-todo | image-inspect | 1 | `2026-08-27T08:10:29.167084Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/docker-todo:latest
error: image inspect: not found r` |
| docker-todo | history | 1 | `2026-08-27T08:10:29.294771Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/docker-todo:latest
error: history: not found registry-1.do` |
| docker-todo | tag | 1 | `2026-08-27T08:10:29.410677Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/docker-todo:latest
error: source image not found: reg` |
| docker-todo | save | 1 | `2026-08-27T08:10:29.540788Z ERROR ferro_cli::linux_cli: docker: unknown image bench/docker-todo:latest
error: docker: unknown image bench/docker-todo:latest
` |
| docker-todo | rmi-tag | 1 | `rmi: bench/docker-todo:bench-tag: rmi: not found registry-1.docker.io/bench/docker-todo:bench-tag
2026-08-27T08:10:29.665332Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | load | 1 | `2026-08-27T08:10:29.785220Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| docker-todo | run-detached | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | health | 1 | `` |
| docker-todo | logs | 1 | `2026-08-27T08:11:01.112580Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | inspect | 1 | `2026-08-27T08:11:01.229418Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | top | 1 | `2026-08-27T08:11:01.356819Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | stats | 1 | `2026-08-27T08:11:01.490223Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | exec | 1 | `2026-08-27T08:11:01.615855Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-out | 1 | `2026-08-27T08:11:01.735619Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-in | 1 | `2026-08-27T08:11:01.871106Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | diff | 1 | `2026-08-27T08:11:01.989308Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T08:11:02.111651Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T08:11:02.236265Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) fai` |
| docker-todo | restart | 1 | `restart: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T08:11:02.362801Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) fai` |
| docker-todo | stop | 1 | `stop: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T08:11:02.494277Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
er` |
| docker-todo | start | 1 | `start: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T08:11:02.617322Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
` |
| docker-todo | rename | 1 | `2026-08-27T08:11:02.736045Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | commit | 1 | `2026-08-27T08:11:02.860029Z ERROR ferro_cli::linux_cli: commit: container not found: bench-docker-todo-r
error: commit: container not found: bench-docker-todo-r` |
| docker-todo | export | 1 | `2026-08-27T08:11:02.999588Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo-r
error: container not found: bench-docker-todo-r
` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T08:11:03.129138Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) faile` |
| docker-todo | wait | 1 | `wait: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T08:11:03.251185Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) faile` |
| docker-todo | rm | 1 | `rm: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T08:11:03.472148Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
er` |
| docker-todo | rmi-committed | 1 | `rmi: bench/docker-todo:committed: rmi: not found registry-1.docker.io/bench/docker-todo:committed
2026-08-27T08:11:03.602185Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | network-run | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | compose-up | 1 | `t does not match authorized child; mysql run failed: runtime mutation mediation failed: compose execution request digest does not match authorized child; client` |
| docker-todo | compose-health | 1 | `` |
| docker-todo | err-port-in-use | 1 | `docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/docker-todo:latest failed: registry error: registry returned HTTP 401: {"er` |
| flask-tutorial | health | 1 | `` |
| flask-tutorial | pause | 1 | `pause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
[2m2026-08-27T00:07:44.556486Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0` |
| flask-tutorial | unpause | 1 | `unpause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
[2m2026-08-27T00:07:44.660069Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| flask-tutorial | restart | 1 | `` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `[2m2026-08-27T00:08:46.553149Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: bind and tmpfs mounts must be removed before committing the roo` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
[2m2026-08-27T00:08:47.907814Z[0m [31mERROR[0m [2mf` |
| flask-tutorial | compose-up | 1 | `[2m2026-08-27T00:08:58.865343Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: app run failed: runtime mutation mediation fail` |
| flask-tutorial | compose-health | 1 | `` |
| gin-basic | start | 1 | `` |
| gin-basic | compose-up | 1 | `2026-08-27T08:05:12.716329Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: runtime mutation mediation failed: compose execution request dig` |
| gin-basic | compose-health | 1 | `` |
| kutt | compose-up | 1 | `[2m2026-08-27T00:14:33.552439Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m invalid Dockerfile: cache mount target must be an absolute non-parent p` |
| kutt | compose-health | 1 | `` |
| mdn-static | run-detached | 1 | `[2m2026-08-27T00:16:41.778812Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m command is required to run container
error: command is required to run ` |
| mdn-static | health | 1 | `` |
| mdn-static | logs | 1 | `[2m2026-08-27T00:17:12.254841Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | inspect | 1 | `[2m2026-08-27T00:17:12.371325Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | top | 1 | `[2m2026-08-27T00:17:12.493491Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | stats | 1 | `[2m2026-08-27T00:17:12.610252Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | exec | 1 | `[2m2026-08-27T00:17:12.731493Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | cp-out | 1 | `[2m2026-08-27T00:17:12.848277Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | cp-in | 1 | `[2m2026-08-27T00:17:12.968856Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | diff | 1 | `[2m2026-08-27T00:17:13.086907Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-27T00:17:13.225402Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause: 1` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-27T00:17:13.339149Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpaus` |
| mdn-static | restart | 1 | `restart: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-27T00:17:13.458345Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m restar` |
| mdn-static | stop | 1 | `stop: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-27T00:17:13.575444Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1 c` |
| mdn-static | start | 1 | `start: bench-mdn-static: container not found: bench-mdn-static
[2m2026-08-27T00:17:13.695532Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start: 1` |
| mdn-static | rename | 1 | `[2m2026-08-27T00:17:13.813039Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static
error: container not found: bench` |
| mdn-static | commit | 1 | `[2m2026-08-27T00:17:13.934976Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-mdn-static-r
error: commit: containe` |
| mdn-static | export | 1 | `[2m2026-08-27T00:17:14.056775Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-mdn-static-r
error: container not found: ben` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-27T00:17:14.174513Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kill:` |
| mdn-static | wait | 1 | `wait: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-27T00:17:14.294233Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wait:` |
| mdn-static | rm | 1 | `rm: bench-mdn-static-r: container not found: bench-mdn-static-r
[2m2026-08-27T00:17:14.512384Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1 c` |
| mdn-static | rmi-committed | 1 | `rmi: bench/mdn-static:committed: rmi: not found registry-1.docker.io/bench/mdn-static:committed
[2m2026-08-27T00:17:14.629533Z[0m [31mERROR[0m [2mferro_cli` |
| mdn-static | network-run | 1 | `[2m2026-08-27T00:17:14.997696Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m command is required to run container
error: command is required to run ` |
| mdn-static | compose-up | 1 | `[2m2026-08-27T00:17:15.332378Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: app run failed: command is required to run cont` |
| mdn-static | compose-health | 1 | `` |
| mdn-static | err-port-in-use | 1 | `[2m2026-08-27T00:19:17.566432Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m command is required to run container
error: command is required to run ` |
| node-getting-started | run-detached | 1 | `2026-08-27T08:07:28.227371Z ERROR ferro_cli::linux_cli: run: env must be KEY=VALUE
error: run: env must be KEY=VALUE
` |
| node-getting-started | health | 1 | `` |
| node-getting-started | logs | 1 | `2026-08-27T08:07:58.707590Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | inspect | 1 | `2026-08-27T08:07:58.831302Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | top | 1 | `2026-08-27T08:07:58.969963Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | stats | 1 | `2026-08-27T08:07:59.096505Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | exec | 1 | `2026-08-27T08:07:59.216154Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | cp-out | 1 | `2026-08-27T08:07:59.336781Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | cp-in | 1 | `2026-08-27T08:07:59.458541Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | diff | 1 | `2026-08-27T08:07:59.575974Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | pause | 1 | `pause: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T08:07:59.696763Z ERROR ferro_cli::linux_cli: pause: 1 container op` |
| node-getting-started | unpause | 1 | `unpause: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T08:07:59.816610Z ERROR ferro_cli::linux_cli: unpause: 1 containe` |
| node-getting-started | restart | 1 | `restart: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T08:07:59.940019Z ERROR ferro_cli::linux_cli: restart: 1 containe` |
| node-getting-started | stop | 1 | `stop: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T08:08:00.063348Z ERROR ferro_cli::linux_cli: stop: 1 container oper` |
| node-getting-started | start | 1 | `start: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T08:08:00.183497Z ERROR ferro_cli::linux_cli: start: 1 container op` |
| node-getting-started | rename | 1 | `2026-08-27T08:08:00.310523Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | commit | 1 | `2026-08-27T08:08:00.433432Z ERROR ferro_cli::linux_cli: commit: container not found: bench-node-getting-started-r
error: commit: container not found: bench-node` |
| node-getting-started | export | 1 | `2026-08-27T08:08:00.559343Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started-r
error: container not found: bench-node-getting-started` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T08:08:00.679976Z ERROR ferro_cli::linux_cli: kill: 1 container ` |
| node-getting-started | wait | 1 | `wait: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T08:08:00.801278Z ERROR ferro_cli::linux_cli: wait: 1 container ` |
| node-getting-started | rm | 1 | `rm: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T08:08:01.032012Z ERROR ferro_cli::linux_cli: rm: 1 container oper` |
| node-getting-started | rmi-committed | 1 | `rmi: bench/node-getting-started:committed: rmi: not found registry-1.docker.io/bench/node-getting-started:committed
2026-08-27T08:08:01.154775Z ERROR ferro_cli:` |
| node-getting-started | compose-up | 1 | `2026-08-27T08:08:06.297604Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: runtime mutation mediation failed: compose execution request dig` |
| node-getting-started | compose-health | 1 | `` |
| spring-petclinic | build | 1 | `2026-08-27T08:14:55.936170Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| spring-petclinic | image-inspect | 1 | `2026-08-27T08:14:56.155133Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-27T08:14:56.280218Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-27T08:14:56.406699Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-27T08:14:56.529239Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-27T08:14:56.653678Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-27T08:14:56.775774Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-27T08:15:28.091977Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-27T08:15:28.217169Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-27T08:15:28.336488Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-27T08:15:28.458144Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-27T08:15:28.578799Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-27T08:15:28.702026Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-27T08:15:28.821333Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-27T08:15:28.939572Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T08:15:29.082752Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T08:15:29.201962Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T08:15:29.318634Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T08:15:29.435752Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T08:15:29.556286Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-27T08:15:29.675340Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-27T08:15:29.800477Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-27T08:15:29.917593Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T08:15:30.037598Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T08:15:30.163414Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T08:15:30.381325Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-27T08:15:30.501759Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `2026-08-27T08:15:36.273691Z ERROR ferro_cli::linux_cli: compose partial result: postgres run failed: surface authorization binding is invalid; mysql run failed:` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-up | 1 | `rified)
[2m2026-08-27T00:25:33.488187Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: uptime-kuma run failed: runtime mutatio` |
| uptime-kuma | compose-health | 1 | `` |
