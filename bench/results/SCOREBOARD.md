# Real-app bench scoreboard

Generated 2026-08-28 02:56Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-28T02:21Z | 51/52 | 52/52 | 1 | 0 | 0 | 0 |
| battleships | 2026-08-28T02:24Z | 54/57 | 57/57 | 3 | 0 | 0 | 0 |
| docker-flask | 2026-08-28T02:26Z | 14/52 | 18/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-28T02:29Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-28T02:34Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-28T02:35Z | 54/57 | 57/57 | 3 | 0 | 0 | 0 |
| gin-basic | 2026-08-28T02:37Z | 51/52 | 52/52 | 1 | 0 | 0 | 0 |
| gitea | 2026-08-28T02:38Z | 21/52 | 52/52 | 31 | 0 | 0 | 0 |
| kutt | 2026-08-28T02:40Z | 17/52 | 19/52 | 2 | 0 | 33 | 0 |
| mdn-static | 2026-08-28T02:43Z | 46/52 | 52/52 | 6 | 0 | 0 | 0 |
| microblog | 2026-08-28T02:47Z | 14/47 | 14/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-28T02:47Z | 51/52 | 52/52 | 1 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-28T02:50Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-28T02:53Z | 18/57 | 19/57 | 1 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 44 | 0 | 0 | 1 |
| image | 74 | 21 | 0 | 40 |
| lifecycle | 127 | 80 | 0 | 138 |
| data | 15 | 0 | 0 | 5 |
| network | 49 | 3 | 1 | 7 |
| compose | 42 | 12 | 0 | 1 |
| errors | 36 | 3 | 0 | 6 |
| extras | 72 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | start | 1 | `` |
| battleships | start | 1 | `` |
| battleships | commit | 1 | `2026-08-28T02:26:30.800187Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
2026-08-28T02:26:33.042485Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-flask | compose-up | 1 | `2026-08-28T02:27:23.324672Z ERROR ferro_cli::linux_cli: compose parse error: services.worker.entrypoint: invalid type: sequence, expected a string at line 94 co` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `2026-08-28T02:29:24.549353Z ERROR ferro_cli::linux_cli: compose parse error: services.worker.entrypoint: invalid type: sequence, expected a string at line 94 co` |
| docker-flask | compose-logs | 1 | `2026-08-28T02:29:24.672688Z ERROR ferro_cli::linux_cli: compose parse error: services.worker.entrypoint: invalid type: sequence, expected a string at line 94 co` |
| docker-flask | compose-down | 1 | `2026-08-28T02:29:24.805776Z ERROR ferro_cli::linux_cli: compose parse error: services.worker.entrypoint: invalid type: sequence, expected a string at line 94 co` |
| docker-todo | build | 1 | `2026-08-28T02:31:31.343927Z ERROR ferro_cli::linux_cli: invalid Dockerfile: RUN /bin/sh -c npm run test failed with status exit status: 1
--- stdout ---

--- st` |
| docker-todo | image-inspect | 1 | `2026-08-28T02:31:31.528359Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/docker-todo:latest
error: image inspect: not found r` |
| docker-todo | history | 1 | `2026-08-28T02:31:31.648860Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/docker-todo:latest
error: history: not found registry-1.do` |
| docker-todo | tag | 1 | `2026-08-28T02:31:31.778630Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/docker-todo:latest
error: source image not found: reg` |
| docker-todo | save | 1 | `2026-08-28T02:31:31.912727Z ERROR ferro_cli::linux_cli: docker: unknown image bench/docker-todo:latest
error: docker: unknown image bench/docker-todo:latest
` |
| docker-todo | rmi-tag | 1 | `rmi: bench/docker-todo:bench-tag: rmi: not found registry-1.docker.io/bench/docker-todo:bench-tag
2026-08-28T02:31:32.024615Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | load | 1 | `2026-08-28T02:31:32.145125Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| docker-todo | run-detached | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | health | 1 | `` |
| docker-todo | logs | 1 | `2026-08-28T02:32:03.500791Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | inspect | 1 | `2026-08-28T02:32:03.613696Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | top | 1 | `2026-08-28T02:32:03.739091Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | stats | 1 | `2026-08-28T02:32:03.853607Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | exec | 1 | `2026-08-28T02:32:03.978586Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-out | 1 | `2026-08-28T02:32:04.120633Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-in | 1 | `2026-08-28T02:32:04.246495Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | diff | 1 | `2026-08-28T02:32:04.370345Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: container not found: bench-docker-todo
2026-08-28T02:32:04.489934Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: container not found: bench-docker-todo
2026-08-28T02:32:04.638792Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) fai` |
| docker-todo | restart | 1 | `restart: bench-docker-todo: container not found: bench-docker-todo
2026-08-28T02:32:04.778986Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) fai` |
| docker-todo | stop | 1 | `stop: bench-docker-todo: container not found: bench-docker-todo
2026-08-28T02:32:04.887897Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
er` |
| docker-todo | start | 1 | `start: bench-docker-todo: container not found: bench-docker-todo
2026-08-28T02:32:05.015151Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
` |
| docker-todo | rename | 1 | `2026-08-28T02:32:05.133473Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | commit | 1 | `2026-08-28T02:32:05.280469Z ERROR ferro_cli::linux_cli: commit: container not found: bench-docker-todo-r
error: commit: container not found: bench-docker-todo-r` |
| docker-todo | export | 1 | `2026-08-28T02:32:05.406447Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo-r
error: container not found: bench-docker-todo-r
` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-28T02:32:05.519680Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) faile` |
| docker-todo | wait | 1 | `wait: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-28T02:32:05.651464Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) faile` |
| docker-todo | rm | 1 | `rm: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-28T02:32:05.891038Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
er` |
| docker-todo | rmi-committed | 1 | `rmi: bench/docker-todo:committed: rmi: not found registry-1.docker.io/bench/docker-todo:committed
2026-08-28T02:32:06.002619Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | network-run | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | compose-up | 1 | `ks (os error 40); client prerequisite failed: invalid Dockerfile: RUN /bin/sh -c npm run test failed with status exit status: 1
--- stdout ---

--- stderr ---
b` |
| docker-todo | compose-health | 1 | `` |
| docker-todo | err-port-in-use | 1 | `docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/docker-todo:latest failed: registry error: registry returned HTTP 401: {"er` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `2026-08-28T02:36:59.451397Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
2026-08-28T02:37:00.286165Z ERROR ferro_cli::linux_cli: ` |
| gin-basic | start | 1 | `` |
| gitea | build | 1 | `2026-08-28T02:39:51.398049Z ERROR ferro_cli::linux_cli: unsupported Dockerfile instruction: Dockerfile syntax directive is not supported: docker/dockerfile:1
er` |
| gitea | image-inspect | 1 | `2026-08-28T02:39:51.665132Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/gitea:latest
error: image inspect: not found registr` |
| gitea | history | 1 | `2026-08-28T02:39:51.795239Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/gitea:latest
error: history: not found registry-1.docker.i` |
| gitea | tag | 1 | `2026-08-28T02:39:51.934334Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/gitea:latest
error: source image not found: registry-` |
| gitea | save | 1 | `2026-08-28T02:39:52.061289Z ERROR ferro_cli::linux_cli: docker: unknown image bench/gitea:latest
error: docker: unknown image bench/gitea:latest
` |
| gitea | rmi-tag | 1 | `rmi: bench/gitea:bench-tag: rmi: not found registry-1.docker.io/bench/gitea:bench-tag
2026-08-28T02:39:52.177315Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | load | 1 | `2026-08-28T02:39:52.305429Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| gitea | run-detached | 1 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | health | 1 | `` |
| gitea | logs | 1 | `2026-08-28T02:40:23.641322Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | inspect | 1 | `2026-08-28T02:40:23.759884Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | top | 1 | `2026-08-28T02:40:23.885656Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | stats | 1 | `2026-08-28T02:40:24.027337Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | exec | 1 | `2026-08-28T02:40:24.156065Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-out | 1 | `2026-08-28T02:40:24.279191Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-in | 1 | `2026-08-28T02:40:24.397991Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | diff | 1 | `2026-08-28T02:40:24.537719Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | pause | 1 | `pause: bench-gitea: container not found: bench-gitea
2026-08-28T02:40:24.667414Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
error: pause` |
| gitea | unpause | 1 | `unpause: bench-gitea: container not found: bench-gitea
2026-08-28T02:40:24.775765Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) failed
error: u` |
| gitea | restart | 1 | `restart: bench-gitea: container not found: bench-gitea
2026-08-28T02:40:24.900820Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) failed
error: r` |
| gitea | stop | 1 | `stop: bench-gitea: container not found: bench-gitea
2026-08-28T02:40:25.017938Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
error: stop: 1` |
| gitea | start | 1 | `start: bench-gitea: container not found: bench-gitea
2026-08-28T02:40:25.138754Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
error: start` |
| gitea | rename | 1 | `2026-08-28T02:40:25.261744Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | commit | 1 | `2026-08-28T02:40:25.382418Z ERROR ferro_cli::linux_cli: commit: container not found: bench-gitea-r
error: commit: container not found: bench-gitea-r
` |
| gitea | export | 1 | `2026-08-28T02:40:25.519301Z ERROR ferro_cli::linux_cli: container not found: bench-gitea-r
error: container not found: bench-gitea-r
` |
| gitea | kill | 1 | `kill: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T02:40:25.644037Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) failed
error: kil` |
| gitea | wait | 1 | `wait: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T02:40:25.776620Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) failed
error: wai` |
| gitea | rm | 1 | `rm: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T02:40:25.989486Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
error: rm: 1 c` |
| gitea | rmi-committed | 1 | `rmi: bench/gitea:committed: rmi: not found registry-1.docker.io/bench/gitea:committed
2026-08-28T02:40:26.116531Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | network-run | 1 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | err-port-in-use | 1 | `Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/gitea:latest failed: registry error: registry returned HT` |
| kutt | compose-up | 1 | `2026-08-28T02:41:05.285410Z ERROR ferro_cli::linux_cli: invalid Dockerfile: base image not found: node:22-alpine
error: invalid Dockerfile: base image not found` |
| kutt | compose-health | 1 | `` |
| mdn-static | health | 1 | `` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T02:44:21.446997Z ERROR ferro_cli::linux_cli: pause: 1 container operati` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T02:44:21.566113Z ERROR ferro_cli::linux_cli: unpause: 1 container ope` |
| mdn-static | restart | 1 | `` |
| mdn-static | start | 1 | `` |
| mdn-static | compose-health | 1 | `` |
| node-getting-started | start | 1 | `` |
| spring-petclinic | build | 1 | `2026-08-28T02:52:44.736320Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| spring-petclinic | image-inspect | 1 | `2026-08-28T02:52:44.953516Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-28T02:52:45.072973Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-28T02:52:45.189018Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-28T02:52:45.311721Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-28T02:52:45.431580Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-28T02:52:45.548938Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-28T02:53:16.853667Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-28T02:53:16.972131Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-28T02:53:17.091010Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-28T02:53:17.210000Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-28T02:53:17.331435Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-28T02:53:17.452529Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-28T02:53:17.572871Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-28T02:53:17.692792Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T02:53:17.828105Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T02:53:17.961164Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T02:53:18.074397Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T02:53:18.191337Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T02:53:18.315285Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-28T02:53:18.429790Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-28T02:53:18.549586Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-28T02:53:18.670511Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T02:53:18.791713Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T02:53:18.912204Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T02:53:19.130328Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-28T02:53:19.254029Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `_id=53ab09e4b07e6541ff87492822a5cc34c8a6e7976059e83d24f2468e30a385bf pid=705487 network_backend=ebpf
2026-08-28T02:53:32.204688Z ERROR ferro_cli::linux_cli: com` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-health | 1 | `` |
