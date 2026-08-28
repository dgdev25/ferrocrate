# Real-app bench scoreboard

Generated 2026-08-28 09:46Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-28T08:51Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| battleships | 2026-08-28T08:58Z | 53/57 | 57/57 | 4 | 0 | 0 | 0 |
| docker-flask | 2026-08-28T09:01Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-28T09:03Z | 39/52 | 52/52 | 13 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-28T09:12Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-28T09:12Z | 54/57 | 57/57 | 3 | 0 | 0 | 0 |
| gin-basic | 2026-08-28T09:14Z | 49/52 | 52/52 | 3 | 0 | 0 | 0 |
| gitea | 2026-08-28T09:17Z | 21/52 | 52/52 | 31 | 0 | 0 | 0 |
| kutt | 2026-08-28T09:19Z | 18/52 | 19/52 | 1 | 0 | 33 | 0 |
| mdn-static | 2026-08-28T09:22Z | 42/52 | 52/52 | 10 | 0 | 0 | 0 |
| microblog | 2026-08-28T09:27Z | 14/47 | 14/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-28T09:27Z | 50/52 | 52/52 | 2 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-28T09:30Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-28T09:35Z | 18/57 | 19/57 | 1 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 44 | 0 | 0 | 1 |
| image | 81 | 14 | 0 | 40 |
| lifecycle | 131 | 76 | 0 | 138 |
| data | 15 | 0 | 0 | 5 |
| network | 50 | 2 | 1 | 7 |
| compose | 43 | 11 | 0 | 1 |
| errors | 35 | 4 | 0 | 6 |
| extras | 72 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | start | 1 | `` |
| actix-basics | kill | 1 | `kill: bench-actix-basics-r: cannot kill container: 41d1c7d12c90823c7529ed015b1f03a823eda43afd5628fa0240fbf1248ab829: container 41d1c7d12c90823c7529ed015b1f03a82` |
| battleships | start | 1 | `` |
| battleships | commit | 1 | `2026-08-28T09:00:59.308672Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| battleships | kill | 1 | `kill: bench-battleships-r: cannot kill container: 3b3b29952328bbfcab7c80356e091c8f5bced3b52c99fce353e5a1dae6283a00: container 3b3b29952328bbfcab7c80356e091c8f5b` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
2026-08-28T09:01:00.402526Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-flask | compose-up | 1 | `2026-08-28T09:01:53.708391Z ERROR ferro_cli::linux_cli: compose validation error: service 'css' must specify image or build
error: compose validation error: ser` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `2026-08-28T09:03:54.841273Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-flask | compose-logs | 1 | `2026-08-28T09:03:54.967117Z ERROR ferro_cli::linux_cli: compose validation error: service 'web' must specify image or build
error: compose validation error: ser` |
| docker-flask | compose-down | 1 | `2026-08-28T09:03:55.096690Z ERROR ferro_cli::linux_cli: compose validation error: service 'worker' must specify image or build
error: compose validation error: ` |
| docker-todo | health | 1 | `` |
| docker-todo | top | 1 | `2026-08-28T09:07:53.024524Z ERROR ferro_cli::linux_cli: container b9a450498544552e72ad32a1ad06927cb0ce34009df963d65ca4570ceb692a65 is not running
error: contain` |
| docker-todo | exec | 1 | `2026-08-28T09:07:53.267730Z ERROR ferro_cli::linux_cli: container b9a450498544552e72ad32a1ad06927cb0ce34009df963d65ca4570ceb692a65 is not running
error: contain` |
| docker-todo | cp-out | 1 | `2026-08-28T09:07:53.389354Z ERROR ferro_cli::linux_cli: docker: archive path is unavailable: No such file or directory (os error 2)
error: docker: archive path ` |
| docker-todo | cp-in | 1 | `2026-08-28T09:07:53.593590Z ERROR ferro_cli::linux_cli: container b9a450498544552e72ad32a1ad06927cb0ce34009df963d65ca4570ceb692a65 is not running
error: contain` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T09:07:53.909447Z ERROR ferro_cli::linux_cli: pause: 1 container operat` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: cgroup error: io error: No such process (os error 3)
2026-08-28T09:07:54.060164Z ERROR ferro_cli::linux_cli: unpause: 1 container op` |
| docker-todo | restart | 1 | `` |
| docker-todo | start | 1 | `` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: cannot kill container: b9a450498544552e72ad32a1ad06927cb0ce34009df963d65ca4570ceb692a65: container b9a450498544552e72ad32a1ad06927cb0` |
| docker-todo | compose-up | 1 | `90c4fd1143c09f76d9d55 pid=2432154 network_backend=ebpf
2026-08-28T09:10:11.203278Z  WARN ferro_core::runtime: [rollback] container 7daa4bd0d46812208b0352fe23796` |
| docker-todo | compose-health | 1 | `` |
| docker-todo | err-port-in-use | 1 | `2026-08-28T09:12:15.674184Z ERROR ferro_cli::linux_cli: io error: Connection reset by peer (os error 104)
error: io error: Connection reset by peer (os error 10` |
| flask-tutorial | start | 1 | `` |
| flask-tutorial | commit | 1 | `2026-08-28T09:14:40.745414Z ERROR ferro_cli::linux_cli: commit: bind and tmpfs mounts must be removed before committing the rootfs
error: commit: bind and tmpfs` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
2026-08-28T09:14:41.756979Z ERROR ferro_cli::linux_cli: ` |
| gin-basic | start | 1 | `` |
| gin-basic | kill | 1 | `kill: bench-gin-basic-r: cannot kill container: f53e5204d14ddef4d614949c94bbc05cde9e12316962a71b57d88da3cac9cf29: container f53e5204d14ddef4d614949c94bbc05cde9e` |
| gin-basic | err-port-in-use | 1 | `2026-08-28T09:17:50.221070Z ERROR ferro_cli::linux_cli: io error: Connection reset by peer (os error 104)
error: io error: Connection reset by peer (os error 10` |
| gitea | build | 1 | `2026-08-28T09:19:07.329045Z ERROR ferro_cli::linux_cli: invalid Dockerfile: FROM --platform must use OS/architecture form
error: invalid Dockerfile: FROM --plat` |
| gitea | image-inspect | 1 | `2026-08-28T09:19:07.569948Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/gitea:latest
error: image inspect: not found registr` |
| gitea | history | 1 | `2026-08-28T09:19:07.687397Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/gitea:latest
error: history: not found registry-1.docker.i` |
| gitea | tag | 1 | `2026-08-28T09:19:07.810112Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/gitea:latest
error: source image not found: registry-` |
| gitea | save | 1 | `2026-08-28T09:19:07.935911Z ERROR ferro_cli::linux_cli: docker: unknown image bench/gitea:latest
error: docker: unknown image bench/gitea:latest
` |
| gitea | rmi-tag | 1 | `rmi: bench/gitea:bench-tag: rmi: not found registry-1.docker.io/bench/gitea:bench-tag
2026-08-28T09:19:08.052964Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | load | 1 | `2026-08-28T09:19:08.172866Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| gitea | run-detached | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | health | 1 | `` |
| gitea | logs | 1 | `2026-08-28T09:19:39.380047Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | inspect | 1 | `2026-08-28T09:19:39.503352Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | top | 1 | `2026-08-28T09:19:39.621090Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | stats | 1 | `2026-08-28T09:19:39.744263Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | exec | 1 | `2026-08-28T09:19:39.863993Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-out | 1 | `2026-08-28T09:19:39.989779Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | cp-in | 1 | `2026-08-28T09:19:40.111823Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | diff | 1 | `2026-08-28T09:19:40.230930Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | pause | 1 | `pause: bench-gitea: container not found: bench-gitea
2026-08-28T09:19:40.352861Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
error: pause` |
| gitea | unpause | 1 | `unpause: bench-gitea: container not found: bench-gitea
2026-08-28T09:19:40.473446Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) failed
error: u` |
| gitea | restart | 1 | `restart: bench-gitea: container not found: bench-gitea
2026-08-28T09:19:40.596675Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) failed
error: r` |
| gitea | stop | 1 | `stop: bench-gitea: container not found: bench-gitea
2026-08-28T09:19:40.719893Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
error: stop: 1` |
| gitea | start | 1 | `start: bench-gitea: container not found: bench-gitea
2026-08-28T09:19:40.845514Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
error: start` |
| gitea | rename | 1 | `2026-08-28T09:19:40.967516Z ERROR ferro_cli::linux_cli: container not found: bench-gitea
error: container not found: bench-gitea
` |
| gitea | commit | 1 | `2026-08-28T09:19:41.086991Z ERROR ferro_cli::linux_cli: commit: container not found: bench-gitea-r
error: commit: container not found: bench-gitea-r
` |
| gitea | export | 1 | `2026-08-28T09:19:41.227143Z ERROR ferro_cli::linux_cli: container not found: bench-gitea-r
error: container not found: bench-gitea-r
` |
| gitea | kill | 1 | `kill: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T09:19:41.343109Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) failed
error: kil` |
| gitea | wait | 1 | `wait: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T09:19:41.467144Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) failed
error: wai` |
| gitea | rm | 1 | `rm: bench-gitea-r: container not found: bench-gitea-r
2026-08-28T09:19:41.685661Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
error: rm: 1 c` |
| gitea | rmi-committed | 1 | `rmi: bench/gitea:committed: rmi: not found registry-1.docker.io/bench/gitea:committed
2026-08-28T09:19:41.807517Z ERROR ferro_cli::linux_cli: rmi: 1 container o` |
| gitea | network-run | 125 | `HORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registr` |
| gitea | err-port-in-use | 1 | `Class":"","Name":"bench/gitea","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/gitea:latest failed: registry error: registry returned HT` |
| kutt | compose-health | 1 | `` |
| mdn-static | health | 1 | `` |
| mdn-static | top | 1 | `2026-08-28T09:23:56.085418Z ERROR ferro_cli::linux_cli: container 9bab95bf6d8d2b843db760a4d6b6c45fa1b0a5b000f82e981e0b9ac8cfcc3cb8 is not running
error: contain` |
| mdn-static | exec | 1 | `2026-08-28T09:23:56.328594Z ERROR ferro_cli::linux_cli: container 9bab95bf6d8d2b843db760a4d6b6c45fa1b0a5b000f82e981e0b9ac8cfcc3cb8 is not running
error: contain` |
| mdn-static | cp-in | 1 | `2026-08-28T09:23:56.687036Z ERROR ferro_cli::linux_cli: container 9bab95bf6d8d2b843db760a4d6b6c45fa1b0a5b000f82e981e0b9ac8cfcc3cb8 is not running
error: contain` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T09:23:56.954791Z ERROR ferro_cli::linux_cli: pause: 1 container operati` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: cgroup error: io error: No such process (os error 3)
2026-08-28T09:23:57.080626Z ERROR ferro_cli::linux_cli: unpause: 1 container ope` |
| mdn-static | restart | 1 | `` |
| mdn-static | start | 1 | `` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: cannot kill container: 9bab95bf6d8d2b843db760a4d6b6c45fa1b0a5b000f82e981e0b9ac8cfcc3cb8: container 9bab95bf6d8d2b843db760a4d6b6c45fa1b` |
| mdn-static | compose-health | 1 | `` |
| node-getting-started | start | 1 | `` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: cannot kill container: 726add58b3aa80bd1577b9a404b2c208247c46cfbb05be642f4149712298e3d8: container 726add58b3aa80bd1577b9a40` |
| spring-petclinic | build | 1 | `85b1137f82406f33e6f44bba79d6: registry (verified)
layer sha256:f6795b7189ec73f2774735d97a688bf9205d69cf49ceeb539654ddd7d70efe53: registry (verified)
2026-08-28T` |
| spring-petclinic | image-inspect | 1 | `2026-08-28T09:33:52.959949Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-28T09:33:53.081686Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-28T09:33:53.204756Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-28T09:33:53.340864Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-28T09:33:53.461913Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-28T09:33:53.599635Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-28T09:34:26.213488Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-28T09:34:26.353397Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-28T09:34:26.464768Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-28T09:34:26.588498Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-28T09:34:26.711050Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-28T09:34:26.842915Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-28T09:34:26.961750Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-28T09:34:27.083460Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T09:34:27.201051Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T09:34:27.318955Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T09:34:27.449017Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T09:34:27.644220Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-28T09:34:27.770620Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-28T09:34:27.872186Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-28T09:34:27.994203Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-28T09:34:28.116355Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T09:34:28.239313Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T09:34:28.361048Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-28T09:34:28.586869Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-28T09:34:28.701840Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 125 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `d52e178f18efa619b4691c7d2b7f540ed274afa64cb5bf7588deb23ccb001 creation failed, cleaning up resources
2026-08-28T09:35:27.643188Z ERROR ferro_cli::linux_cli: com` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-health | 1 | `` |
