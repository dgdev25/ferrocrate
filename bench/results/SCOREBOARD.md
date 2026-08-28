# Real-app bench scoreboard

Generated 2026-08-28 10:16Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-28T09:53Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| battleships | 2026-08-28T09:55Z | 53/57 | 57/57 | 4 | 0 | 0 | 0 |
| docker-flask | 2026-08-28T09:56Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-28T09:58Z | 40/52 | 52/52 | 12 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-28T10:02Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-28T10:02Z | 54/57 | 57/57 | 3 | 0 | 0 | 0 |
| gin-basic | 2026-08-28T10:03Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| gitea | 2026-08-28T10:04Z | 21/52 | 52/52 | 31 | 0 | 0 | 0 |
| kutt | 2026-08-28T10:05Z | 18/52 | 19/52 | 1 | 0 | 33 | 0 |
| mdn-static | 2026-08-28T10:07Z | 42/52 | 52/52 | 10 | 0 | 0 | 0 |
| microblog | 2026-08-28T10:11Z | 14/47 | 14/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-28T10:11Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-28T10:12Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-28T10:13Z | 18/57 | 19/57 | 1 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 44 | 0 | 0 | 1 |
| image | 81 | 14 | 0 | 40 |
| lifecycle | 131 | 76 | 0 | 138 |
| data | 15 | 0 | 0 | 5 |
| network | 50 | 2 | 1 | 7 |
| compose | 43 | 11 | 0 | 1 |
| errors | 37 | 2 | 0 | 6 |
| extras | 72 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | start | 1 | `` |
| actix-basics | kill | 1 | `kill: bench-actix-basics-r: cannot kill container: ecdd8a30bf752e9dfc689fee6bdbe16fedd55cf33d68b3edac5c519879c93fd6: container ecdd8a30bf752e9dfc689fee6bdbe16fe` |
| battleships | start | 1 | `` |
| battleships | commit | 1 | `2026-08-28T09:56:27.605503Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| battleships | kill | 1 | `kill: bench-battleships-r: cannot kill container: 87c0e6d59b6fe9ab9ac142ee52a3c48ba32e34feaceeaa387e088ab727c5442f: container 87c0e6d59b6fe9ab9ac142ee52a3c48ba3` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
2026-08-28T09:56:28.604170Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-flask | compose-up | 1 | `2026-08-28T09:56:51.670937Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `2026-08-28T09:58:52.744607Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-logs | 1 | `2026-08-28T09:58:52.867180Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-down | 1 | `2026-08-28T09:58:52.985271Z ERROR ferro_cli::linux_cli: compose validation error: service 'web' must specify image or build
error: compose validation error: ser` |
| docker-todo | health | 1 | `` |
| docker-todo | top | 1 | `2026-08-28T09:59:32.015053Z ERROR ferro_cli::linux_cli: container 8734ecd69f70aa3d058e02f0234cc715ad82433b5fcde5f417eeb13377c83c3d is not running
error: contain` |
| docker-todo | exec | 1 | `2026-08-28T09:59:32.246422Z ERROR ferro_cli::linux_cli: container 8734ecd69f70aa3d058e02f0234cc715ad82433b5fcde5f417eeb13377c83c3d is not running
error: contain` |
| docker-todo | cp-out | 1 | `2026-08-28T09:59:32.360463Z ERROR ferro_cli::linux_cli: docker: archive path is unavailable: No such file or directory (os error 2)
error: docker: archive path ` |
| docker-todo | cp-in | 1 | `2026-08-28T09:59:32.502341Z ERROR ferro_cli::linux_cli: container 8734ecd69f70aa3d058e02f0234cc715ad82433b5fcde5f417eeb13377c83c3d is not running
error: contain` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T09:59:32.727037Z ERROR ferro_cli::linux_cli: pause: 1 container operat` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T09:59:32.850153Z ERROR ferro_cli::linux_cli: unpause: 1 container op` |
| docker-todo | restart | 1 | `` |
| docker-todo | start | 1 | `` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: cannot kill container: 8734ecd69f70aa3d058e02f0234cc715ad82433b5fcde5f417eeb13377c83c3d: container 8734ecd69f70aa3d058e02f0234cc715ad` |
| docker-todo | compose-up | 1 | `10757b27724433cb9f3c3 pid=2963666 network_backend=ebpf
2026-08-28T10:00:47.616980Z  WARN ferro_core::runtime: [rollback] container 9716dab0b267080fd47d083a39acf` |
| docker-todo | compose-health | 1 | `` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `2026-08-28T10:03:40.456885Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
2026-08-28T10:03:41.254553Z ERROR ferro_cli::linux_cli: ` |
| gin-basic | start | 1 | `` |
| gin-basic | kill | 1 | `kill: bench-gin-basic-r: cannot kill container: 7bcfe7e9f79ef919846f38a1e0cca3c98781e912762a8a8f176194254d6b8709: container 7bcfe7e9f79ef919846f38a1e0cca3c98781` |
| gitea | build | 1 | `2026-08-28T10:04:43.803746Z ERROR ferro_cli::linux_cli: invalid Dockerfile: FROM --platform must use OS/architecture form
error: invalid Dockerfile: FROM --plat` |
| gitea | image-inspect | 1 | `2026-08-28T10:04:44.055774Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/gitea:latest
error: image inspect: not found registr` |
| gitea | history | 1 | `2026-08-28T10:04:44.166458Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/gitea:latest
error: history: not found registry-1.docker.i` |
| gitea | tag | 1 | `2026-08-28T10:04:44.289709Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/gitea:latest
error: source image not found: registry-` |
| gitea | save | 1 | `2026-08-28T10:04:44.407936Z ERROR ferro_cli::linux_cli: docker: unknown image bench/gitea:latest
error: docker: unknown image bench/gitea:latest
` |
| gitea | rmi-tag | 1 | `rmi: bench/gitea:bench-tag: rmi: not found registry-1.docker.io/bench/gitea:bench-tag
2026-08-28T10:04:44.521814Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | load | 1 | `2026-08-28T10:04:44.639291Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| gitea | run-detached | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | health | 1 | `` |
| gitea | logs | 1 | `2026-08-28T10:05:15.842081Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | inspect | 1 | `2026-08-28T10:05:15.963209Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | top | 1 | `2026-08-28T10:05:16.084251Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | stats | 1 | `2026-08-28T10:05:16.202845Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | exec | 1 | `2026-08-28T10:05:16.320568Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-out | 1 | `2026-08-28T10:05:16.438604Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-in | 1 | `2026-08-28T10:05:16.558313Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | diff | 1 | `2026-08-28T10:05:16.675703Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | pause | 1 | `pause: bench-gitea: container not found: bench-gitea
2026-08-28T10:05:16.796233Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
error: pause` |
| gitea | unpause | 1 | `unpause: bench-gitea: container not found: bench-gitea
2026-08-28T10:05:16.914296Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) failed
error: u` |
| gitea | restart | 1 | `restart: bench-gitea: container not found: bench-gitea
2026-08-28T10:05:17.037779Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) failed
error: r` |
| gitea | stop | 1 | `stop: bench-gitea: container not found: bench-gitea
2026-08-28T10:05:17.153400Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
error: stop: 1` |
| gitea | start | 1 | `start: bench-gitea: container not found: bench-gitea
2026-08-28T10:05:17.277005Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
error: start` |
| gitea | rename | 1 | `2026-08-28T10:05:17.391638Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | commit | 1 | `2026-08-28T10:05:17.510321Z ERROR ferro_cli::linux_cli: commit: container not found: bench-gitea-r
error: commit: container not found: bench-gitea-r
` |
| gitea | export | 1 | `2026-08-28T10:05:17.631946Z ERROR ferro_cli::linux_cli: container not found: bench-gitea-r
error: container not found: bench-gitea-r
` |
| gitea | kill | 1 | `kill: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T10:05:17.748254Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) failed
error: kil` |
| gitea | wait | 1 | `wait: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T10:05:17.869102Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) failed
error: wai` |
| gitea | rm | 1 | `rm: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T10:05:18.094892Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
error: rm: 1 c` |
| gitea | rmi-committed | 1 | `rmi: bench/gitea:committed: rmi: not found registry-1.docker.io/bench/gitea:committed
2026-08-28T10:05:18.208394Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | network-run | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | err-port-in-use | 1 | `Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/gitea:latest failed: registry error: registry returned HT` |
| kutt | compose-health | 1 | `` |
| mdn-static | health | 1 | `` |
| mdn-static | top | 1 | `2026-08-28T10:08:16.268795Z ERROR ferro_cli::linux_cli: container 9c7c854e50f81a95fce0a6de7c4d2e72e824d0dbac3d08aa47a8cd7f10c19318 is not running
error: contain` |
| mdn-static | exec | 1 | `2026-08-28T10:08:16.508783Z ERROR ferro_cli::linux_cli: container 9c7c854e50f81a95fce0a6de7c4d2e72e824d0dbac3d08aa47a8cd7f10c19318 is not running
error: contain` |
| mdn-static | cp-in | 1 | `2026-08-28T10:08:16.825216Z ERROR ferro_cli::linux_cli: container 9c7c854e50f81a95fce0a6de7c4d2e72e824d0dbac3d08aa47a8cd7f10c19318 is not running
error: contain` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T10:08:17.129326Z ERROR ferro_cli::linux_cli: pause: 1 container operati` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T10:08:17.245300Z ERROR ferro_cli::linux_cli: unpause: 1 container ope` |
| mdn-static | restart | 1 | `` |
| mdn-static | start | 1 | `` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: cannot kill container: 9c7c854e50f81a95fce0a6de7c4d2e72e824d0dbac3d08aa47a8cd7f10c19318: container 9c7c854e50f81a95fce0a6de7c4d2e72e82` |
| mdn-static | compose-health | 1 | `` |
| node-getting-started | start | 1 | `` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: cannot kill container: 14ca0e5874bb43da054b303c491b735a9da1f5733ad98322176b80bf1993fcc2: container 14ca0e5874bb43da054b303c4` |
| spring-petclinic | build | 1 | `2026-08-28T10:12:58.955320Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| spring-petclinic | image-inspect | 1 | `2026-08-28T10:12:59.161940Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-28T10:12:59.287492Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-28T10:12:59.410771Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-28T10:12:59.529905Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-28T10:12:59.651413Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-28T10:12:59.770783Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-28T10:13:31.079470Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-28T10:13:31.198887Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-28T10:13:31.316378Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-28T10:13:31.438536Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-28T10:13:31.555862Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-28T10:13:31.674970Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-28T10:13:31.796856Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-28T10:13:31.913975Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T10:13:32.031353Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T10:13:32.156296Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T10:13:32.275795Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T10:13:32.392282Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T10:13:32.516592Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-28T10:13:32.632457Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-28T10:13:32.755412Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-28T10:13:32.879827Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T10:13:32.997019Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T10:13:33.125372Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T10:13:33.340811Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-28T10:13:33.460877Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `4c4202eb5328f156108a55d3048984bf8d996ee7ade701a2c7328e46d9b22 creation failed, cleaning up resources
2026-08-28T10:13:40.554633Z ERROR ferro_cli::linux_cli: com` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-health | 1 | `` |
