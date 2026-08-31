# Real-app bench scoreboard

Generated 2026-08-31 06:09Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-28T12:05Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| battleships | 2026-08-31T06:06Z | 57/57 | 57/57 | 0 | 0 | 0 | 0 |
| docker-flask | 2026-08-28T12:10Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-28T12:12Z | 40/52 | 52/52 | 12 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-28T12:18Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-28T12:18Z | 54/57 | 57/57 | 3 | 0 | 0 | 0 |
| gin-basic | 2026-08-28T12:20Z | 27/27 | 52/52 | 0 | 0 | 0 | 0 |
| gitea | 2026-08-28T11:35Z | 21/52 | 52/52 | 31 | 0 | 0 | 0 |
| kutt | 2026-08-28T11:54Z | 18/52 | 19/52 | 1 | 0 | 33 | 0 |
| mdn-static | 2026-08-28T11:40Z | 42/52 | 52/52 | 10 | 0 | 0 | 0 |
| microblog | 2026-08-28T11:44Z | 14/47 | 14/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-28T11:44Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-28T11:47Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-28T11:49Z | 17/57 | 17/57 | 0 | 2 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 44 | 0 | 0 | 1 |
| image | 81 | 14 | 0 | 40 |
| lifecycle | 129 | 70 | 0 | 138 |
| data | 15 | 0 | 0 | 5 |
| network | 46 | 2 | 1 | 7 |
| compose | 37 | 10 | 2 | 1 |
| errors | 34 | 2 | 0 | 6 |
| extras | 67 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | start | 1 | `` |
| actix-basics | kill | 1 | `kill: bench-actix-basics-r: cannot kill container: 0783750864e74fb9a1749929d6799c12231394e0a867395802f456242a866b01: container 0783750864e74fb9a1749929d6799c122` |
| docker-flask | compose-up | 1 | `2026-08-28T12:10:41.617070Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `2026-08-28T12:12:42.656110Z ERROR ferro_cli::linux_cli: compose validation error: service 'js' must specify image or build
error: compose validation error: serv` |
| docker-flask | compose-logs | 1 | `2026-08-28T12:12:42.778902Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-down | 1 | `2026-08-28T12:12:42.897822Z ERROR ferro_cli::linux_cli: compose validation error: service 'web' must specify image or build
error: compose validation error: ser` |
| docker-todo | health | 1 | `` |
| docker-todo | top | 1 | `2026-08-28T12:14:56.950472Z ERROR ferro_cli::linux_cli: container aea230157f140ad5192f727ff7fbca1c2663974dc7c1deb36a4cbd0efd7428f5 is not running
error: contain` |
| docker-todo | exec | 1 | `2026-08-28T12:14:57.187549Z ERROR ferro_cli::linux_cli: container aea230157f140ad5192f727ff7fbca1c2663974dc7c1deb36a4cbd0efd7428f5 is not running
error: contain` |
| docker-todo | cp-out | 1 | `2026-08-28T12:14:57.305453Z ERROR ferro_cli::linux_cli: docker: archive path is unavailable: No such file or directory (os error 2)
error: docker: archive path ` |
| docker-todo | cp-in | 1 | `2026-08-28T12:14:57.457369Z ERROR ferro_cli::linux_cli: container aea230157f140ad5192f727ff7fbca1c2663974dc7c1deb36a4cbd0efd7428f5 is not running
error: contain` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T12:14:57.669132Z ERROR ferro_cli::linux_cli: pause: 1 container operat` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T12:14:57.788905Z ERROR ferro_cli::linux_cli: unpause: 1 container op` |
| docker-todo | restart | 1 | `` |
| docker-todo | start | 1 | `` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: cannot kill container: aea230157f140ad5192f727ff7fbca1c2663974dc7c1deb36a4cbd0efd7428f5: container aea230157f140ad5192f727ff7fbca1c26` |
| docker-todo | compose-up | 1 | `cfc1e2264840c10 creation failed, cleaning up resources
2026-08-28T12:16:12.564702Z  WARN ferro_core::runtime: [rollback] container 1b501fb7735db3a9912bc88300623` |
| docker-todo | compose-health | 1 | `` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `2026-08-28T12:20:27.185951Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
2026-08-28T12:20:28.190452Z ERROR ferro_cli::linux_cli: ` |
| gitea | build | 1 | `2026-08-28T11:36:56.276772Z ERROR ferro_cli::linux_cli: invalid Dockerfile: FROM --platform must use OS/architecture form
error: invalid Dockerfile: FROM --plat` |
| gitea | image-inspect | 1 | `2026-08-28T11:36:56.515768Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/gitea:latest
error: image inspect: not found registr` |
| gitea | history | 1 | `2026-08-28T11:36:56.644028Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/gitea:latest
error: history: not found registry-1.docker.i` |
| gitea | tag | 1 | `2026-08-28T11:36:56.769632Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/gitea:latest
error: source image not found: registry-` |
| gitea | save | 1 | `2026-08-28T11:36:56.891998Z ERROR ferro_cli::linux_cli: docker: unknown image bench/gitea:latest
error: docker: unknown image bench/gitea:latest
` |
| gitea | rmi-tag | 1 | `rmi: bench/gitea:bench-tag: rmi: not found registry-1.docker.io/bench/gitea:bench-tag
2026-08-28T11:36:57.013221Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | load | 1 | `2026-08-28T11:36:57.126018Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| gitea | run-detached | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | health | 1 | `` |
| gitea | logs | 1 | `2026-08-28T11:37:28.443947Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | inspect | 1 | `2026-08-28T11:37:28.566768Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | top | 1 | `2026-08-28T11:37:28.688553Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | stats | 1 | `2026-08-28T11:37:28.811457Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | exec | 1 | `2026-08-28T11:37:28.936987Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-out | 1 | `2026-08-28T11:37:29.048245Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-in | 1 | `2026-08-28T11:37:29.168578Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | diff | 1 | `2026-08-28T11:37:29.284986Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | pause | 1 | `pause: bench-gitea: container not found: bench-gitea
2026-08-28T11:37:29.401827Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
error: pause` |
| gitea | unpause | 1 | `unpause: bench-gitea: container not found: bench-gitea
2026-08-28T11:37:29.544230Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) failed
error: u` |
| gitea | restart | 1 | `restart: bench-gitea: container not found: bench-gitea
2026-08-28T11:37:29.662341Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) failed
error: r` |
| gitea | stop | 1 | `stop: bench-gitea: container not found: bench-gitea
2026-08-28T11:37:29.782154Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
error: stop: 1` |
| gitea | start | 1 | `start: bench-gitea: container not found: bench-gitea
2026-08-28T11:37:29.901681Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
error: start` |
| gitea | rename | 1 | `2026-08-28T11:37:30.055885Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | commit | 1 | `2026-08-28T11:37:30.137741Z ERROR ferro_cli::linux_cli: commit: container not found: bench-gitea-r
error: commit: container not found: bench-gitea-r
` |
| gitea | export | 1 | `2026-08-28T11:37:30.261873Z ERROR ferro_cli::linux_cli: container not found: bench-gitea-r
error: container not found: bench-gitea-r
` |
| gitea | kill | 1 | `kill: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T11:37:30.379668Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) failed
error: kil` |
| gitea | wait | 1 | `wait: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T11:37:30.500789Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) failed
error: wai` |
| gitea | rm | 1 | `rm: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T11:37:30.716667Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
error: rm: 1 c` |
| gitea | rmi-committed | 1 | `rmi: bench/gitea:committed: rmi: not found registry-1.docker.io/bench/gitea:committed
2026-08-28T11:37:30.842766Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | network-run | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | err-port-in-use | 1 | `Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/gitea:latest failed: registry error: registry returned HT` |
| kutt | compose-health | 1 | `` |
| mdn-static | health | 1 | `` |
| mdn-static | top | 1 | `2026-08-28T11:41:20.113306Z ERROR ferro_cli::linux_cli: container f27a8208bed6f5cac50e69a13453bef8e5b54fe1b28ece6f9b584b5dd0cbd9dc is not running
error: contain` |
| mdn-static | exec | 1 | `2026-08-28T11:41:20.356038Z ERROR ferro_cli::linux_cli: container f27a8208bed6f5cac50e69a13453bef8e5b54fe1b28ece6f9b584b5dd0cbd9dc is not running
error: contain` |
| mdn-static | cp-in | 1 | `2026-08-28T11:41:20.698229Z ERROR ferro_cli::linux_cli: container f27a8208bed6f5cac50e69a13453bef8e5b54fe1b28ece6f9b584b5dd0cbd9dc is not running
error: contain` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T11:41:20.975395Z ERROR ferro_cli::linux_cli: pause: 1 container operati` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T11:41:21.094370Z ERROR ferro_cli::linux_cli: unpause: 1 container ope` |
| mdn-static | restart | 1 | `` |
| mdn-static | start | 1 | `` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: cannot kill container: f27a8208bed6f5cac50e69a13453bef8e5b54fe1b28ece6f9b584b5dd0cbd9dc: container f27a8208bed6f5cac50e69a13453bef8e5b` |
| mdn-static | compose-health | 1 | `` |
| node-getting-started | start | 1 | `` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: cannot kill container: 442505590ebcbe509fe205454e0920bb0af0b5c4d270503c869b197b80724514: container 442505590ebcbe509fe205454` |
| spring-petclinic | build | 1 | `2026-08-28T11:48:30.668362Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| spring-petclinic | image-inspect | 1 | `2026-08-28T11:48:30.860938Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-28T11:48:30.976474Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-28T11:48:31.096852Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-28T11:48:31.221175Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-28T11:48:31.341705Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-28T11:48:31.460238Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-28T11:49:02.667053Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-28T11:49:02.783648Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-28T11:49:02.903773Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-28T11:49:03.022682Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-28T11:49:03.142318Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-28T11:49:03.260670Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-28T11:49:03.381743Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-28T11:49:03.497809Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T11:49:03.619821Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T11:49:03.738644Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T11:49:03.872697Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T11:49:03.989000Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T11:49:04.108432Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-28T11:49:04.227870Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-28T11:49:04.350744Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-28T11:49:04.471173Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T11:49:04.593623Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T11:49:04.713629Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T11:49:04.930712Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-28T11:49:05.048308Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `ce615a196f22a2f5b845f02d016dd0bdc9ac48810cdecbc6b3d1b0ddf27ff creation failed, cleaning up resources
2026-08-28T11:49:12.262918Z ERROR ferro_cli::linux_cli: com` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
