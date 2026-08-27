# Real-app bench scoreboard

Generated 2026-08-27 00:45Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-27T00:29Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| battleships | 2026-08-26T23:54Z | 52/57 | 57/57 | 5 | 0 | 0 | 0 |
| docker-flask | 2026-08-26T23:58Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-27T00:34Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-27T00:06Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-27T00:06Z | 48/57 | 57/57 | 9 | 0 | 0 | 0 |
| gin-basic | 2026-08-27T00:37Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| kutt | 2026-08-27T00:14Z | 17/52 | 19/52 | 2 | 0 | 33 | 0 |
| mdn-static | 2026-08-27T00:16Z | 26/52 | 52/52 | 26 | 0 | 0 | 0 |
| microblog | 2026-08-27T00:19Z | 14/47 | 16/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-27T00:42Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-27T00:22Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-27T00:24Z | 17/57 | 19/57 | 2 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 41 | 0 | 0 | 1 |
| image | 51 | 35 | 0 | 40 |
| lifecycle | 42 | 142 | 0 | 138 |
| data | 10 | 0 | 0 | 5 |
| network | 42 | 6 | 1 | 7 |
| compose | 30 | 24 | 0 | 1 |
| errors | 30 | 6 | 0 | 6 |
| extras | 67 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | build | 1 | `[2m2026-08-27T00:30:45.764504Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m layer size exceeds maximum (4444777984 bytes)
error: layer size exceeds` |
| actix-basics | image-inspect | 1 | `[2m2026-08-27T00:30:45.976665Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/actix-basics:latest` |
| actix-basics | history | 1 | `[2m2026-08-27T00:30:46.096476Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/actix-basics:latest
error` |
| actix-basics | tag | 1 | `[2m2026-08-27T00:30:46.214783Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/actix-basics:latest
` |
| actix-basics | save | 1 | `[2m2026-08-27T00:30:46.336850Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/actix-basics:latest
error: docker: unknown ` |
| actix-basics | rmi-tag | 1 | `rmi: bench/actix-basics:bench-tag: rmi: not found registry-1.docker.io/bench/actix-basics:bench-tag
[2m2026-08-27T00:30:46.455304Z[0m [31mERROR[0m [2mferro` |
| actix-basics | load | 1 | `[2m2026-08-27T00:30:46.576926Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| actix-basics | run-detached | 1 | `uthentication required","detail":[{"Type":"repository","Class":"","Name":"bench/actix-basics","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/` |
| actix-basics | health | 1 | `` |
| actix-basics | logs | 1 | `[2m2026-08-27T00:31:19.202108Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | inspect | 1 | `[2m2026-08-27T00:31:19.329125Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | top | 1 | `[2m2026-08-27T00:31:19.464512Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | stats | 1 | `[2m2026-08-27T00:31:19.585102Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | exec | 1 | `[2m2026-08-27T00:31:19.705908Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | cp-out | 1 | `[2m2026-08-27T00:31:19.842748Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | cp-in | 1 | `[2m2026-08-27T00:31:19.977942Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | diff | 1 | `[2m2026-08-27T00:31:20.110795Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | pause | 1 | `pause: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-27T00:31:20.233630Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m paus` |
| actix-basics | unpause | 1 | `unpause: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-27T00:31:20.357012Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m un` |
| actix-basics | restart | 1 | `restart: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-27T00:31:20.486247Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m re` |
| actix-basics | stop | 1 | `stop: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-27T00:31:20.606916Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop:` |
| actix-basics | start | 1 | `start: bench-actix-basics: container not found: bench-actix-basics
[2m2026-08-27T00:31:20.733277Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m star` |
| actix-basics | rename | 1 | `[2m2026-08-27T00:31:20.858052Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics
error: container not found: ben` |
| actix-basics | commit | 1 | `[2m2026-08-27T00:31:20.978885Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-actix-basics-r
error: commit: contai` |
| actix-basics | export | 1 | `[2m2026-08-27T00:31:21.103366Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-actix-basics-r
error: container not found: b` |
| actix-basics | kill | 1 | `kill: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-27T00:31:21.223855Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m k` |
| actix-basics | wait | 1 | `wait: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-27T00:31:21.347033Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m w` |
| actix-basics | rm | 1 | `rm: bench-actix-basics-r: container not found: bench-actix-basics-r
[2m2026-08-27T00:31:21.580122Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm:` |
| actix-basics | rmi-committed | 1 | `rmi: bench/actix-basics:committed: rmi: not found registry-1.docker.io/bench/actix-basics:committed
[2m2026-08-27T00:31:21.704893Z[0m [31mERROR[0m [2mferro` |
| actix-basics | network-run | 1 | `uthentication required","detail":[{"Type":"repository","Class":"","Name":"bench/actix-basics","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/` |
| actix-basics | compose-up | 1 | `[2m2026-08-27T00:32:11.732115Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: app prerequisite failed: layer size exceeds max` |
| actix-basics | compose-health | 1 | `` |
| actix-basics | err-port-in-use | 1 | `x-basics","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/actix-basics:latest failed: registry error: registry returned HTTP 401: {"erro` |
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
| docker-todo | build | 1 | `[2m2026-08-27T00:34:28.780467Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m io error: Permission denied (os error 13)
error: io error: Permission d` |
| docker-todo | image-inspect | 1 | `[2m2026-08-27T00:34:29.069046Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/docker-todo:latest
` |
| docker-todo | history | 1 | `[2m2026-08-27T00:34:29.213452Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/docker-todo:latest
error:` |
| docker-todo | tag | 1 | `[2m2026-08-27T00:34:29.363896Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/docker-todo:latest
e` |
| docker-todo | save | 1 | `[2m2026-08-27T00:34:29.509550Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/docker-todo:latest
error: docker: unknown i` |
| docker-todo | rmi-tag | 1 | `rmi: bench/docker-todo:bench-tag: rmi: not found registry-1.docker.io/bench/docker-todo:bench-tag
[2m2026-08-27T00:34:29.698456Z[0m [31mERROR[0m [2mferro_c` |
| docker-todo | load | 1 | `[2m2026-08-27T00:34:29.916593Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| docker-todo | run-detached | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | health | 1 | `` |
| docker-todo | logs | 1 | `[2m2026-08-27T00:35:01.341385Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | inspect | 1 | `[2m2026-08-27T00:35:01.468180Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | top | 1 | `[2m2026-08-27T00:35:01.612158Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | stats | 1 | `[2m2026-08-27T00:35:01.732351Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | exec | 1 | `[2m2026-08-27T00:35:01.864252Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | cp-out | 1 | `[2m2026-08-27T00:35:01.997964Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | cp-in | 1 | `[2m2026-08-27T00:35:02.130882Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | diff | 1 | `[2m2026-08-27T00:35:02.264623Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-27T00:35:02.397020Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause:` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-27T00:35:02.518073Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpa` |
| docker-todo | restart | 1 | `restart: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-27T00:35:02.656090Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rest` |
| docker-todo | stop | 1 | `stop: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-27T00:35:02.773016Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1` |
| docker-todo | start | 1 | `start: bench-docker-todo: container not found: bench-docker-todo
[2m2026-08-27T00:35:02.894535Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start:` |
| docker-todo | rename | 1 | `[2m2026-08-27T00:35:03.019381Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo
error: container not found: benc` |
| docker-todo | commit | 1 | `[2m2026-08-27T00:35:03.155183Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-docker-todo-r
error: commit: contain` |
| docker-todo | export | 1 | `[2m2026-08-27T00:35:03.276072Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-docker-todo-r
error: container not found: be` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-27T00:35:03.404071Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kil` |
| docker-todo | wait | 1 | `wait: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-27T00:35:03.524324Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wai` |
| docker-todo | rm | 1 | `rm: bench-docker-todo-r: container not found: bench-docker-todo-r
[2m2026-08-27T00:35:03.765625Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1` |
| docker-todo | rmi-committed | 1 | `rmi: bench/docker-todo:committed: rmi: not found registry-1.docker.io/bench/docker-todo:committed
[2m2026-08-27T00:35:03.886684Z[0m [31mERROR[0m [2mferro_c` |
| docker-todo | network-run | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | compose-up | 1 | `tation mediation failed: compose execution request digest does not match authorized child; proxy run failed: runtime mutation mediation failed: compose executio` |
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
| gin-basic | build | 1 | `[2m2026-08-27T00:38:25.561081Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m layer size exceeds maximum (4446864896 bytes)
error: layer size exceeds` |
| gin-basic | image-inspect | 1 | `[2m2026-08-27T00:38:25.822479Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/gin-basic:latest
er` |
| gin-basic | history | 1 | `[2m2026-08-27T00:38:25.953789Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/gin-basic:latest
error: h` |
| gin-basic | tag | 1 | `[2m2026-08-27T00:38:26.090167Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/gin-basic:latest
err` |
| gin-basic | save | 1 | `[2m2026-08-27T00:38:26.223566Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/gin-basic:latest
error: docker: unknown ima` |
| gin-basic | rmi-tag | 1 | `rmi: bench/gin-basic:bench-tag: rmi: not found registry-1.docker.io/bench/gin-basic:bench-tag
[2m2026-08-27T00:38:26.355624Z[0m [31mERROR[0m [2mferro_cli::` |
| gin-basic | load | 1 | `[2m2026-08-27T00:38:26.488173Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| gin-basic | run-detached | 1 | `ssage":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gin-basic","Action":"pull"}]}]}

error: run: pull image registry-1.dock` |
| gin-basic | health | 1 | `` |
| gin-basic | logs | 1 | `[2m2026-08-27T00:38:58.507349Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | inspect | 1 | `[2m2026-08-27T00:38:58.649451Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | top | 1 | `[2m2026-08-27T00:38:58.774874Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | stats | 1 | `[2m2026-08-27T00:38:58.912876Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | exec | 1 | `[2m2026-08-27T00:38:59.041148Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | cp-out | 1 | `[2m2026-08-27T00:38:59.179883Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | cp-in | 1 | `[2m2026-08-27T00:38:59.322931Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | diff | 1 | `[2m2026-08-27T00:38:59.451734Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | pause | 1 | `pause: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-27T00:38:59.582812Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m pause: 1 c` |
| gin-basic | unpause | 1 | `unpause: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-27T00:38:59.724559Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m unpause:` |
| gin-basic | restart | 1 | `restart: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-27T00:38:59.857963Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m restart:` |
| gin-basic | stop | 1 | `stop: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-27T00:38:59.989279Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m stop: 1 con` |
| gin-basic | start | 1 | `start: bench-gin-basic: container not found: bench-gin-basic
[2m2026-08-27T00:39:00.128384Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m start: 1 c` |
| gin-basic | rename | 1 | `[2m2026-08-27T00:39:00.266837Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic
error: container not found: bench-` |
| gin-basic | commit | 1 | `[2m2026-08-27T00:39:00.391547Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-gin-basic-r
error: commit: container` |
| gin-basic | export | 1 | `[2m2026-08-27T00:39:00.545272Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-gin-basic-r
error: container not found: benc` |
| gin-basic | kill | 1 | `kill: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-27T00:39:00.687317Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m kill: 1` |
| gin-basic | wait | 1 | `wait: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-27T00:39:00.827488Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m wait: 1` |
| gin-basic | rm | 1 | `rm: bench-gin-basic-r: container not found: bench-gin-basic-r
[2m2026-08-27T00:39:01.070779Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m rm: 1 con` |
| gin-basic | rmi-committed | 1 | `rmi: bench/gin-basic:committed: rmi: not found registry-1.docker.io/bench/gin-basic:committed
[2m2026-08-27T00:39:01.197419Z[0m [31mERROR[0m [2mferro_cli::` |
| gin-basic | network-run | 1 | `ssage":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gin-basic","Action":"pull"}]}]}

error: run: pull image registry-1.dock` |
| gin-basic | compose-up | 1 | `[2m2026-08-27T00:39:56.258929Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: app prerequisite failed: layer size exceeds max` |
| gin-basic | compose-health | 1 | `` |
| gin-basic | err-port-in-use | 1 | `:"bench/gin-basic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/gin-basic:latest failed: registry error: registry returned HTTP 401: ` |
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
| node-getting-started | build | 1 | `[2m2026-08-27T00:43:07.207925Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m layer size exceeds maximum (4444575232 bytes)
error: layer size exceeds` |
| node-getting-started | image-inspect | 1 | `[2m2026-08-27T00:43:07.437725Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/node-getting-starte` |
| node-getting-started | history | 1 | `[2m2026-08-27T00:43:07.555210Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/node-getting-started:late` |
| node-getting-started | tag | 1 | `[2m2026-08-27T00:43:07.677386Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/node-getting-started` |
| node-getting-started | save | 1 | `[2m2026-08-27T00:43:07.804134Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/node-getting-started:latest
error: docker: ` |
| node-getting-started | rmi-tag | 1 | `rmi: bench/node-getting-started:bench-tag: rmi: not found registry-1.docker.io/bench/node-getting-started:bench-tag
[2m2026-08-27T00:43:07.924561Z[0m [31mERR` |
| node-getting-started | load | 1 | `[2m2026-08-27T00:43:08.037956Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| node-getting-started | run-detached | 1 | `"detail":[{"Type":"repository","Class":"","Name":"bench/node-getting-started","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/node-getti` |
| node-getting-started | health | 1 | `` |
| node-getting-started | logs | 1 | `[2m2026-08-27T00:43:39.348917Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | inspect | 1 | `[2m2026-08-27T00:43:39.469852Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | top | 1 | `[2m2026-08-27T00:43:39.587619Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | stats | 1 | `[2m2026-08-27T00:43:39.709489Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | exec | 1 | `[2m2026-08-27T00:43:39.846890Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | cp-out | 1 | `[2m2026-08-27T00:43:39.974084Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | cp-in | 1 | `[2m2026-08-27T00:43:40.092565Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | diff | 1 | `[2m2026-08-27T00:43:40.208998Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | pause | 1 | `pause: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-27T00:43:40.329753Z[0m [31mERROR[0m [2mferro_cli::linux_cli[` |
| node-getting-started | unpause | 1 | `unpause: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-27T00:43:40.447139Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | restart | 1 | `restart: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-27T00:43:40.568904Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | stop | 1 | `stop: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-27T00:43:40.685979Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0` |
| node-getting-started | start | 1 | `start: bench-node-getting-started: container not found: bench-node-getting-started
[2m2026-08-27T00:43:40.804806Z[0m [31mERROR[0m [2mferro_cli::linux_cli[` |
| node-getting-started | rename | 1 | `[2m2026-08-27T00:43:40.926042Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started
error: container not fo` |
| node-getting-started | commit | 1 | `[2m2026-08-27T00:43:41.042455Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-node-getting-started-r
error: commit` |
| node-getting-started | export | 1 | `[2m2026-08-27T00:43:41.161522Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-node-getting-started-r
error: container not ` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-27T00:43:41.280472Z[0m [31mERROR[0m [2mferro_cli::linux_cl` |
| node-getting-started | wait | 1 | `wait: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-27T00:43:41.400648Z[0m [31mERROR[0m [2mferro_cli::linux_cl` |
| node-getting-started | rm | 1 | `rm: bench-node-getting-started-r: container not found: bench-node-getting-started-r
[2m2026-08-27T00:43:41.619377Z[0m [31mERROR[0m [2mferro_cli::linux_cli` |
| node-getting-started | rmi-committed | 1 | `rmi: bench/node-getting-started:committed: rmi: not found registry-1.docker.io/bench/node-getting-started:committed
[2m2026-08-27T00:43:41.741884Z[0m [31mERR` |
| node-getting-started | network-run | 1 | `"detail":[{"Type":"repository","Class":"","Name":"bench/node-getting-started","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/node-getti` |
| node-getting-started | compose-up | 1 | `[2m2026-08-27T00:43:47.468843Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: app prerequisite failed: layer size exceeds max` |
| node-getting-started | compose-health | 1 | `` |
| node-getting-started | err-port-in-use | 1 | `"}]}]}

error: run: pull image registry-1.docker.io/bench/node-getting-started:latest failed: registry error: registry returned HTTP 401: {"errors":[{"code":"UN` |
| spring-petclinic | build | 1 | `heckstyle violations. -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X` |
| spring-petclinic | image-inspect | 1 | `[2m2026-08-27T00:23:05.414631Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m image inspect: not found registry-1.docker.io/bench/spring-petclinic:la` |
| spring-petclinic | history | 1 | `[2m2026-08-27T00:23:05.534737Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m history: not found registry-1.docker.io/bench/spring-petclinic:latest
e` |
| spring-petclinic | tag | 1 | `[2m2026-08-27T00:23:05.654337Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m source image not found: registry-1.docker.io/bench/spring-petclinic:lat` |
| spring-petclinic | save | 1 | `[2m2026-08-27T00:23:05.773339Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: unknown image bench/spring-petclinic:latest
error: docker: unkn` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
[2m2026-08-27T00:23:05.898354Z[0m [31mERROR[0m ` |
| spring-petclinic | load | 1 | `[2m2026-08-27T00:23:06.018985Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m docker: load read failed: No such file or directory (os error 2)
error:` |
| spring-petclinic | run-detached | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `[2m2026-08-27T00:23:37.235534Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | inspect | 1 | `[2m2026-08-27T00:23:37.356005Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | top | 1 | `[2m2026-08-27T00:23:37.471871Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | stats | 1 | `[2m2026-08-27T00:23:37.594531Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | exec | 1 | `[2m2026-08-27T00:23:37.715047Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | cp-out | 1 | `[2m2026-08-27T00:23:37.832878Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | cp-in | 1 | `[2m2026-08-27T00:23:37.952712Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | diff | 1 | `[2m2026-08-27T00:23:38.072151Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-27T00:23:38.187550Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-27T00:23:38.309707Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-27T00:23:38.432984Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-27T00:23:38.553224Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
[2m2026-08-27T00:23:38.673849Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | rename | 1 | `[2m2026-08-27T00:23:38.791028Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic
error: container not found:` |
| spring-petclinic | commit | 1 | `[2m2026-08-27T00:23:38.916991Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m commit: container not found: bench-spring-petclinic-r
error: commit: co` |
| spring-petclinic | export | 1 | `[2m2026-08-27T00:23:39.032881Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m container not found: bench-spring-petclinic-r
error: container not foun` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-27T00:23:39.153098Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-27T00:23:39.295058Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
[2m2026-08-27T00:23:39.512041Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
[2m2026-08-27T00:23:39.633234Z[0m [31mERROR[0m ` |
| spring-petclinic | network-run | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | ` (verified)
[2m2026-08-27T00:24:29.028419Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: postgres run failed: surface author` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-up | 1 | `rified)
[2m2026-08-27T00:25:33.488187Z[0m [31mERROR[0m [2mferro_cli::linux_cli[0m[2m:[0m compose partial result: uptime-kuma run failed: runtime mutatio` |
| uptime-kuma | compose-health | 1 | `` |
