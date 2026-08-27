# Real-app bench scoreboard

Generated 2026-08-27 20:29Z from the newest result file per app and engine.
Product = fails on Ferrocrate, passes on Docker. App/env = fails on both. Boundary = manifest skip.

| App | Run | Ferrocrate pass | Docker pass | Product | App/env | Boundary | Unpaired |
|---|---|---:|---:|---:|---:|---:|---:|
| actix-basics | 2026-08-27T19:10Z | 38/52 | 52/52 | 14 | 0 | 0 | 0 |
| battleships | 2026-08-27T19:13Z | 43/57 | 57/57 | 14 | 0 | 0 | 0 |
| docker-flask | 2026-08-27T19:17Z | 14/52 | 19/52 | 5 | 0 | 33 | 0 |
| docker-todo | 2026-08-27T19:20Z | 19/52 | 52/52 | 33 | 0 | 0 | 0 |
| fastapi-fullstack | 2026-08-27T19:26Z | 14/47 | 14/47 | 0 | 0 | 33 | 0 |
| flask-tutorial | 2026-08-27T19:26Z | 43/57 | 57/57 | 14 | 0 | 0 | 0 |
| gin-basic | 2026-08-27T19:30Z | 38/52 | 52/52 | 14 | 0 | 0 | 0 |
| gitea | 2026-08-27T19:33Z | 21/52 | 0/- | 0 | 0 | 0 | 31 |
| kutt | 2026-08-27T19:34Z | 17/52 | 19/52 | 2 | 0 | 33 | 0 |
| mdn-static | 2026-08-27T19:37Z | 26/52 | 52/52 | 26 | 0 | 0 | 0 |
| microblog | 2026-08-27T19:40Z | 14/47 | 16/47 | 0 | 1 | 32 | 0 |
| node-getting-started | 2026-08-27T19:40Z | 27/52 | 52/52 | 25 | 0 | 0 | 0 |
| scratch | 2026-08-27T00:22Z | 16/47 | 16/47 | 0 | 0 | 31 | 0 |
| spring-petclinic | 2026-08-27T19:43Z | 19/52 | 51/52 | 32 | 0 | 1 | 0 |
| uptime-kuma | 2026-08-27T19:47Z | 17/57 | 19/57 | 2 | 0 | 38 | 0 |

## By group (Ferrocrate)

| Group | Pass | Product | App/env | Boundary |
|---|---:|---:|---:|---:|
| engine | 44 | 0 | 0 | 1 |
| image | 74 | 14 | 0 | 40 |
| lifecycle | 53 | 132 | 0 | 138 |
| data | 15 | 0 | 0 | 5 |
| network | 48 | 3 | 1 | 7 |
| compose | 30 | 24 | 0 | 1 |
| errors | 30 | 8 | 0 | 6 |
| extras | 72 | 0 | 0 | 3 |
| other | 0 | 0 | 0 | 0 |

## Open product failures (ticket candidates)

| App | Step | Exit | Ferrocrate stderr (tail) |
|---|---|---:|---|
| actix-basics | run-detached | 1 | `2026-08-27T19:10:50.846958Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| actix-basics | health | 1 | `` |
| actix-basics | cp-out | 1 | `2026-08-27T19:11:22.055498Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/bfd7f923` |
| actix-basics | cp-in | 1 | `2026-08-27T19:11:22.181434Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: No such file or directory (os error 2)
error: docker: container` |
| actix-basics | pause | 1 | `pause: bench-actix-basics: cgroup error: io error: No such process (os error 3)
2026-08-27T19:11:22.475817Z ERROR ferro_cli::linux_cli: pause: 1 container opera` |
| actix-basics | unpause | 1 | `unpause: bench-actix-basics: cgroup error: io error: No such process (os error 3)
2026-08-27T19:11:22.589438Z ERROR ferro_cli::linux_cli: unpause: 1 container o` |
| actix-basics | restart | 1 | `restart: bench-actix-basics: io error: No such file or directory (os error 2)
2026-08-27T19:11:22.712066Z ERROR ferro_cli::linux_cli: restart: 1 container opera` |
| actix-basics | start | 1 | `start: bench-actix-basics: io error: No such file or directory (os error 2)
2026-08-27T19:11:22.952205Z ERROR ferro_cli::linux_cli: start: 1 container operation` |
| actix-basics | commit | 1 | `2026-08-27T19:11:23.244483Z ERROR ferro_cli::linux_cli: commit: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/bfd7f923` |
| actix-basics | export | 1 | `2026-08-27T19:11:23.363168Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/bfd7f923` |
| actix-basics | rmi-committed | 1 | `rmi: bench/actix-basics:committed: rmi: not found registry-1.docker.io/bench/actix-basics:committed
2026-08-27T19:11:24.029623Z ERROR ferro_cli::linux_cli: rmi:` |
| actix-basics | compose-up | 1 | `2026-08-27T19:11:38.734370Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: network error: slirp4netns API socket did not become ready: path` |
| actix-basics | compose-health | 1 | `` |
| actix-basics | err-port-in-use | 1 | `2026-08-27T19:13:49.703618Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| battleships | run-detached | 1 | `2026-08-27T19:14:38.237063Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| battleships | health | 1 | `` |
| battleships | cp-out | 1 | `2026-08-27T19:15:09.434436Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/d6bfddab` |
| battleships | cp-in | 1 | `2026-08-27T19:15:09.549660Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: No such file or directory (os error 2)
error: docker: container` |
| battleships | pause | 1 | `pause: bench-battleships: cgroup error: io error: No such process (os error 3)
2026-08-27T19:15:09.838278Z ERROR ferro_cli::linux_cli: pause: 1 container operat` |
| battleships | unpause | 1 | `unpause: bench-battleships: cgroup error: io error: No such process (os error 3)
2026-08-27T19:15:09.957726Z ERROR ferro_cli::linux_cli: unpause: 1 container op` |
| battleships | restart | 1 | `restart: bench-battleships: io error: No such file or directory (os error 2)
2026-08-27T19:15:10.076433Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| battleships | start | 1 | `start: bench-battleships: io error: No such file or directory (os error 2)
2026-08-27T19:15:10.318494Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| battleships | commit | 1 | `2026-08-27T19:15:10.612511Z ERROR ferro_cli::linux_cli: commit: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/d6bfddab` |
| battleships | export | 1 | `2026-08-27T19:15:10.731109Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/d6bfddab` |
| battleships | rmi-committed | 1 | `rmi: bench/battleships:committed: rmi: not found registry-1.docker.io/bench/battleships:committed
2026-08-27T19:15:11.404317Z ERROR ferro_cli::linux_cli: rmi: 1` |
| battleships | compose-up | 1 | `2026-08-27T19:15:32.564312Z ERROR ferro_cli::linux_cli: compose partial result: battleships run failed: network error: slirp4netns API socket did not become rea` |
| battleships | compose-health | 1 | `` |
| battleships | err-port-in-use | 1 | `2026-08-27T19:17:51.136075Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| docker-flask | compose-up | 1 | `2026-08-27T19:17:58.200339Z ERROR ferro_cli::linux_cli: compose parse error: services.web.healthcheck.test: invalid type: string "curl localhost:8000/up", expec` |
| docker-flask | compose-health | 1 | `` |
| docker-flask | compose-ps | 1 | `2026-08-27T19:20:01.075252Z ERROR ferro_cli::linux_cli: compose parse error: services.web.healthcheck.test: invalid type: string "curl localhost:8000/up", expec` |
| docker-flask | compose-logs | 1 | `2026-08-27T19:20:01.166788Z ERROR ferro_cli::linux_cli: compose parse error: services.web.healthcheck.test: invalid type: string "curl localhost:8000/up", expec` |
| docker-flask | compose-down | 1 | `2026-08-27T19:20:01.299022Z ERROR ferro_cli::linux_cli: compose parse error: services.web.healthcheck.test: invalid type: string "curl localhost:8000/up", expec` |
| docker-todo | build | 1 | ` at Object.<anonymous> (node_modules/sqlite3/lib/sqlite3.js:2:17)
      at Object.<anonymous> (src/persistence/sqlite.js:1:45)
      at Object.<anonymous> (spec` |
| docker-todo | image-inspect | 1 | `2026-08-27T19:22:44.971064Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/docker-todo:latest
error: image inspect: not found r` |
| docker-todo | history | 1 | `2026-08-27T19:22:45.105288Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/docker-todo:latest
error: history: not found registry-1.do` |
| docker-todo | tag | 1 | `2026-08-27T19:22:45.224992Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/docker-todo:latest
error: source image not found: reg` |
| docker-todo | save | 1 | `2026-08-27T19:22:45.349071Z ERROR ferro_cli::linux_cli: docker: unknown image bench/docker-todo:latest
error: docker: unknown image bench/docker-todo:latest
` |
| docker-todo | rmi-tag | 1 | `rmi: bench/docker-todo:bench-tag: rmi: not found registry-1.docker.io/bench/docker-todo:bench-tag
2026-08-27T19:22:45.484039Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | load | 1 | `2026-08-27T19:22:45.621617Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| docker-todo | run-detached | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | health | 1 | `` |
| docker-todo | logs | 1 | `2026-08-27T19:23:18.568800Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | inspect | 1 | `2026-08-27T19:23:18.752916Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | top | 1 | `2026-08-27T19:23:18.914119Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | stats | 1 | `2026-08-27T19:23:19.324004Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | exec | 1 | `2026-08-27T19:23:19.677115Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-out | 1 | `2026-08-27T19:23:19.902210Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | cp-in | 1 | `2026-08-27T19:23:20.162061Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | diff | 1 | `2026-08-27T19:23:20.355949Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | pause | 1 | `pause: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T19:23:20.719455Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
` |
| docker-todo | unpause | 1 | `unpause: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T19:23:20.853003Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) fai` |
| docker-todo | restart | 1 | `restart: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T19:23:21.004449Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) fai` |
| docker-todo | stop | 1 | `stop: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T19:23:21.182774Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
er` |
| docker-todo | start | 1 | `start: bench-docker-todo: container not found: bench-docker-todo
2026-08-27T19:23:21.319104Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
` |
| docker-todo | rename | 1 | `2026-08-27T19:23:21.461777Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo
error: container not found: bench-docker-todo
` |
| docker-todo | commit | 1 | `2026-08-27T19:23:21.646440Z ERROR ferro_cli::linux_cli: commit: container not found: bench-docker-todo-r
error: commit: container not found: bench-docker-todo-r` |
| docker-todo | export | 1 | `2026-08-27T19:23:21.797953Z ERROR ferro_cli::linux_cli: container not found: bench-docker-todo-r
error: container not found: bench-docker-todo-r
` |
| docker-todo | kill | 1 | `kill: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T19:23:22.008264Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) faile` |
| docker-todo | wait | 1 | `wait: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T19:23:22.355461Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) faile` |
| docker-todo | rm | 1 | `rm: bench-docker-todo-r: container not found: bench-docker-todo-r
2026-08-27T19:23:22.722580Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
er` |
| docker-todo | rmi-committed | 1 | `rmi: bench/docker-todo:committed: rmi: not found registry-1.docker.io/bench/docker-todo:committed
2026-08-27T19:23:22.894561Z ERROR ferro_cli::linux_cli: rmi: 1` |
| docker-todo | network-run | 1 | `:"authentication required","detail":[{"Type":"repository","Class":"","Name":"bench/docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.i` |
| docker-todo | compose-up | 1 | `such file or directory; proxy run failed: mount error: io error: Too many levels of symbolic links (os error 40); mysql run failed: rootfs error: failed to read` |
| docker-todo | compose-health | 1 | `` |
| docker-todo | err-port-in-use | 1 | `docker-todo","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/docker-todo:latest failed: registry error: registry returned HTTP 401: {"er` |
| flask-tutorial | run-detached | 1 | `2026-08-27T19:27:16.551887Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| flask-tutorial | health | 1 | `` |
| flask-tutorial | cp-out | 1 | `2026-08-27T19:27:51.000469Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ebfc35d8` |
| flask-tutorial | cp-in | 1 | `2026-08-27T19:27:51.194779Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: No such file or directory (os error 2)
error: docker: container` |
| flask-tutorial | pause | 1 | `pause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
2026-08-27T19:27:51.604988Z ERROR ferro_cli::linux_cli: pause: 1 container ope` |
| flask-tutorial | unpause | 1 | `unpause: bench-flask-tutorial: cgroup error: io error: No such process (os error 3)
2026-08-27T19:27:52.296740Z ERROR ferro_cli::linux_cli: unpause: 1 container` |
| flask-tutorial | restart | 1 | `restart: bench-flask-tutorial: io error: No such file or directory (os error 2)
2026-08-27T19:27:53.088091Z ERROR ferro_cli::linux_cli: restart: 1 container ope` |
| flask-tutorial | start | 1 | `start: bench-flask-tutorial: io error: No such file or directory (os error 2)
2026-08-27T19:27:53.785451Z ERROR ferro_cli::linux_cli: start: 1 container operati` |
| flask-tutorial | commit | 1 | `2026-08-27T19:27:54.275532Z ERROR ferro_cli::linux_cli: commit: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ebfc35d8` |
| flask-tutorial | export | 1 | `2026-08-27T19:27:54.368996Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ebfc35d8` |
| flask-tutorial | rmi-committed | 1 | `rmi: bench/flask-tutorial:committed: rmi: not found registry-1.docker.io/bench/flask-tutorial:committed
2026-08-27T19:27:55.104100Z ERROR ferro_cli::linux_cli: ` |
| flask-tutorial | compose-up | 1 | `2026-08-27T19:28:18.829351Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: network error: slirp4netns API socket did not become ready: path` |
| flask-tutorial | compose-health | 1 | `` |
| flask-tutorial | err-port-in-use | 1 | `2026-08-27T19:30:37.197823Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| gin-basic | run-detached | 1 | `2026-08-27T19:30:54.517392Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| gin-basic | health | 1 | `` |
| gin-basic | cp-out | 1 | `2026-08-27T19:31:30.347190Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ef0c177d` |
| gin-basic | cp-in | 1 | `2026-08-27T19:31:30.483992Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: No such file or directory (os error 2)
error: docker: container` |
| gin-basic | pause | 1 | `pause: bench-gin-basic: cgroup error: io error: No such process (os error 3)
2026-08-27T19:31:30.821879Z ERROR ferro_cli::linux_cli: pause: 1 container operatio` |
| gin-basic | unpause | 1 | `unpause: bench-gin-basic: cgroup error: io error: No such process (os error 3)
2026-08-27T19:31:31.036605Z ERROR ferro_cli::linux_cli: unpause: 1 container oper` |
| gin-basic | restart | 1 | `restart: bench-gin-basic: io error: No such file or directory (os error 2)
2026-08-27T19:31:31.176034Z ERROR ferro_cli::linux_cli: restart: 1 container operatio` |
| gin-basic | start | 1 | `start: bench-gin-basic: io error: No such file or directory (os error 2)
2026-08-27T19:31:31.650973Z ERROR ferro_cli::linux_cli: start: 1 container operation(s)` |
| gin-basic | commit | 1 | `2026-08-27T19:31:32.045580Z ERROR ferro_cli::linux_cli: commit: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ef0c177d` |
| gin-basic | export | 1 | `2026-08-27T19:31:32.175138Z ERROR ferro_cli::linux_cli: docker: container rootfs is unavailable: /path/to/ferrocrate-lab/runtimes/apptriage/containers/ef0c177d` |
| gin-basic | rmi-committed | 1 | `rmi: bench/gin-basic:committed: rmi: not found registry-1.docker.io/bench/gin-basic:committed
2026-08-27T19:31:32.995099Z ERROR ferro_cli::linux_cli: rmi: 1 con` |
| gin-basic | compose-up | 1 | `2026-08-27T19:31:42.048782Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: network error: slirp4netns API socket did not become ready: path` |
| gin-basic | compose-health | 1 | `` |
| gin-basic | err-port-in-use | 1 | `2026-08-27T19:33:53.373269Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| kutt | compose-up | 1 | `2026-08-27T19:35:00.272262Z ERROR ferro_cli::linux_cli: invalid Dockerfile: cache mount target must be an absolute non-parent path
error: invalid Dockerfile: ca` |
| kutt | compose-health | 1 | `` |
| mdn-static | run-detached | 1 | `2026-08-27T19:37:15.438984Z ERROR ferro_cli::linux_cli: command is required to run container
error: command is required to run container
` |
| mdn-static | health | 1 | `` |
| mdn-static | logs | 1 | `2026-08-27T19:37:49.333096Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | inspect | 1 | `2026-08-27T19:37:49.551680Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | top | 1 | `2026-08-27T19:37:49.945675Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | stats | 1 | `2026-08-27T19:37:50.187961Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | exec | 1 | `2026-08-27T19:37:50.532963Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | cp-out | 1 | `2026-08-27T19:37:50.701602Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | cp-in | 1 | `2026-08-27T19:37:51.074076Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | diff | 1 | `2026-08-27T19:37:51.347465Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | pause | 1 | `pause: bench-mdn-static: container not found: bench-mdn-static
2026-08-27T19:37:51.698483Z ERROR ferro_cli::linux_cli: pause: 1 container operation(s) failed
er` |
| mdn-static | unpause | 1 | `unpause: bench-mdn-static: container not found: bench-mdn-static
2026-08-27T19:37:51.982134Z ERROR ferro_cli::linux_cli: unpause: 1 container operation(s) faile` |
| mdn-static | restart | 1 | `restart: bench-mdn-static: container not found: bench-mdn-static
2026-08-27T19:37:52.168592Z ERROR ferro_cli::linux_cli: restart: 1 container operation(s) faile` |
| mdn-static | stop | 1 | `stop: bench-mdn-static: container not found: bench-mdn-static
2026-08-27T19:37:52.590661Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s) failed
erro` |
| mdn-static | start | 1 | `start: bench-mdn-static: container not found: bench-mdn-static
2026-08-27T19:37:52.752013Z ERROR ferro_cli::linux_cli: start: 1 container operation(s) failed
er` |
| mdn-static | rename | 1 | `2026-08-27T19:37:52.951463Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static
error: container not found: bench-mdn-static
` |
| mdn-static | commit | 1 | `2026-08-27T19:37:53.164852Z ERROR ferro_cli::linux_cli: commit: container not found: bench-mdn-static-r
error: commit: container not found: bench-mdn-static-r
` |
| mdn-static | export | 1 | `2026-08-27T19:37:53.489222Z ERROR ferro_cli::linux_cli: container not found: bench-mdn-static-r
error: container not found: bench-mdn-static-r
` |
| mdn-static | kill | 1 | `kill: bench-mdn-static-r: container not found: bench-mdn-static-r
2026-08-27T19:37:53.663437Z ERROR ferro_cli::linux_cli: kill: 1 container operation(s) failed
` |
| mdn-static | wait | 1 | `wait: bench-mdn-static-r: container not found: bench-mdn-static-r
2026-08-27T19:37:54.475645Z ERROR ferro_cli::linux_cli: wait: 1 container operation(s) failed
` |
| mdn-static | rm | 1 | `rm: bench-mdn-static-r: container not found: bench-mdn-static-r
2026-08-27T19:37:54.853343Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s) failed
erro` |
| mdn-static | rmi-committed | 1 | `rmi: bench/mdn-static:committed: rmi: not found registry-1.docker.io/bench/mdn-static:committed
2026-08-27T19:37:54.982177Z ERROR ferro_cli::linux_cli: rmi: 1 c` |
| mdn-static | network-run | 1 | `2026-08-27T19:37:56.506512Z ERROR ferro_cli::linux_cli: command is required to run container
error: command is required to run container
` |
| mdn-static | compose-up | 1 | `2026-08-27T19:37:57.536689Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: command is required to run container
error: compose partial resu` |
| mdn-static | compose-health | 1 | `` |
| mdn-static | err-port-in-use | 1 | `2026-08-27T19:40:04.631483Z ERROR ferro_cli::linux_cli: command is required to run container
error: command is required to run container
grep: /tmp/bench-mdn-st` |
| node-getting-started | run-detached | 1 | `2026-08-27T19:40:27.901195Z ERROR ferro_cli::linux_cli: run: env must be KEY=VALUE
error: run: env must be KEY=VALUE
` |
| node-getting-started | health | 1 | `` |
| node-getting-started | logs | 1 | `2026-08-27T19:40:59.049540Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | inspect | 1 | `2026-08-27T19:40:59.179172Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | top | 1 | `2026-08-27T19:40:59.304574Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | stats | 1 | `2026-08-27T19:40:59.437802Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | exec | 1 | `2026-08-27T19:40:59.573242Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | cp-out | 1 | `2026-08-27T19:40:59.698919Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | cp-in | 1 | `2026-08-27T19:40:59.844194Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | diff | 1 | `2026-08-27T19:40:59.977762Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | pause | 1 | `pause: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T19:41:00.102340Z ERROR ferro_cli::linux_cli: pause: 1 container op` |
| node-getting-started | unpause | 1 | `unpause: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T19:41:00.249698Z ERROR ferro_cli::linux_cli: unpause: 1 containe` |
| node-getting-started | restart | 1 | `restart: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T19:41:00.376554Z ERROR ferro_cli::linux_cli: restart: 1 containe` |
| node-getting-started | stop | 1 | `stop: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T19:41:00.507622Z ERROR ferro_cli::linux_cli: stop: 1 container oper` |
| node-getting-started | start | 1 | `start: bench-node-getting-started: container not found: bench-node-getting-started
2026-08-27T19:41:00.646260Z ERROR ferro_cli::linux_cli: start: 1 container op` |
| node-getting-started | rename | 1 | `2026-08-27T19:41:00.771703Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started
error: container not found: bench-node-getting-started
` |
| node-getting-started | commit | 1 | `2026-08-27T19:41:00.913518Z ERROR ferro_cli::linux_cli: commit: container not found: bench-node-getting-started-r
error: commit: container not found: bench-node` |
| node-getting-started | export | 1 | `2026-08-27T19:41:01.045844Z ERROR ferro_cli::linux_cli: container not found: bench-node-getting-started-r
error: container not found: bench-node-getting-started` |
| node-getting-started | kill | 1 | `kill: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T19:41:01.183216Z ERROR ferro_cli::linux_cli: kill: 1 container ` |
| node-getting-started | wait | 1 | `wait: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T19:41:01.305246Z ERROR ferro_cli::linux_cli: wait: 1 container ` |
| node-getting-started | rm | 1 | `rm: bench-node-getting-started-r: container not found: bench-node-getting-started-r
2026-08-27T19:41:01.535797Z ERROR ferro_cli::linux_cli: rm: 1 container oper` |
| node-getting-started | rmi-committed | 1 | `rmi: bench/node-getting-started:committed: rmi: not found registry-1.docker.io/bench/node-getting-started:committed
2026-08-27T19:41:01.662565Z ERROR ferro_cli:` |
| node-getting-started | compose-up | 1 | `2026-08-27T19:41:14.370437Z ERROR ferro_cli::linux_cli: compose partial result: app run failed: network error: slirp4netns API socket did not become ready: path` |
| node-getting-started | compose-health | 1 | `` |
| node-getting-started | err-port-in-use | 1 | `2026-08-27T19:43:29.248781Z ERROR ferro_cli::linux_cli: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
error: net` |
| spring-petclinic | build | 1 | `2026-08-27T19:46:55.050995Z ERROR ferro_cli::linux_cli: invalid Dockerfile: COPY --from source is unavailable: No such file or directory (os error 2)
error: inv` |
| spring-petclinic | image-inspect | 1 | `2026-08-27T19:46:55.396296Z ERROR ferro_cli::linux_cli: image inspect: not found registry-1.docker.io/bench/spring-petclinic:latest
error: image inspect: not fo` |
| spring-petclinic | history | 1 | `2026-08-27T19:46:55.535521Z ERROR ferro_cli::linux_cli: history: not found registry-1.docker.io/bench/spring-petclinic:latest
error: history: not found registry` |
| spring-petclinic | tag | 1 | `2026-08-27T19:46:55.675181Z ERROR ferro_cli::linux_cli: source image not found: registry-1.docker.io/bench/spring-petclinic:latest
error: source image not found` |
| spring-petclinic | save | 1 | `2026-08-27T19:46:55.805483Z ERROR ferro_cli::linux_cli: docker: unknown image bench/spring-petclinic:latest
error: docker: unknown image bench/spring-petclinic:` |
| spring-petclinic | rmi-tag | 1 | `rmi: bench/spring-petclinic:bench-tag: rmi: not found registry-1.docker.io/bench/spring-petclinic:bench-tag
2026-08-27T19:46:55.941810Z ERROR ferro_cli::linux_c` |
| spring-petclinic | load | 1 | `2026-08-27T19:46:56.078717Z ERROR ferro_cli::linux_cli: docker: load read failed: No such file or directory (os error 2)
error: docker: load read failed: No suc` |
| spring-petclinic | run-detached | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | health | 1 | `` |
| spring-petclinic | logs | 1 | `2026-08-27T19:47:28.994254Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | inspect | 1 | `2026-08-27T19:47:29.119933Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | top | 1 | `2026-08-27T19:47:29.244386Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | stats | 1 | `2026-08-27T19:47:29.374133Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | exec | 1 | `2026-08-27T19:47:29.502797Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-out | 1 | `2026-08-27T19:47:29.632551Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | cp-in | 1 | `2026-08-27T19:47:29.764044Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | diff | 1 | `2026-08-27T19:47:29.889254Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | pause | 1 | `pause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T19:47:30.027409Z ERROR ferro_cli::linux_cli: pause: 1 container operation(` |
| spring-petclinic | unpause | 1 | `unpause: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T19:47:30.168350Z ERROR ferro_cli::linux_cli: unpause: 1 container operat` |
| spring-petclinic | restart | 1 | `restart: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T19:47:30.291291Z ERROR ferro_cli::linux_cli: restart: 1 container operat` |
| spring-petclinic | stop | 1 | `stop: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T19:47:30.418751Z ERROR ferro_cli::linux_cli: stop: 1 container operation(s)` |
| spring-petclinic | start | 1 | `start: bench-spring-petclinic: container not found: bench-spring-petclinic
2026-08-27T19:47:30.550677Z ERROR ferro_cli::linux_cli: start: 1 container operation(` |
| spring-petclinic | rename | 1 | `2026-08-27T19:47:30.669851Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic
error: container not found: bench-spring-petclinic
` |
| spring-petclinic | commit | 1 | `2026-08-27T19:47:30.795432Z ERROR ferro_cli::linux_cli: commit: container not found: bench-spring-petclinic-r
error: commit: container not found: bench-spring-p` |
| spring-petclinic | export | 1 | `2026-08-27T19:47:30.913463Z ERROR ferro_cli::linux_cli: container not found: bench-spring-petclinic-r
error: container not found: bench-spring-petclinic-r
` |
| spring-petclinic | kill | 1 | `kill: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T19:47:31.037881Z ERROR ferro_cli::linux_cli: kill: 1 container operatio` |
| spring-petclinic | wait | 1 | `wait: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T19:47:31.162569Z ERROR ferro_cli::linux_cli: wait: 1 container operatio` |
| spring-petclinic | rm | 1 | `rm: bench-spring-petclinic-r: container not found: bench-spring-petclinic-r
2026-08-27T19:47:31.387088Z ERROR ferro_cli::linux_cli: rm: 1 container operation(s)` |
| spring-petclinic | rmi-committed | 1 | `rmi: bench/spring-petclinic:committed: rmi: not found registry-1.docker.io/bench/spring-petclinic:committed
2026-08-27T19:47:31.517213Z ERROR ferro_cli::linux_c` |
| spring-petclinic | network-run | 1 | `n required","detail":[{"Type":"repository","Class":"","Name":"bench/spring-petclinic","Action":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/sp` |
| spring-petclinic | compose-up | 1 | `r archive: Permission denied (os error 13); postgres run failed: network error: slirp4netns API socket did not become ready: path must be shorter than SUN_LEN
e` |
| spring-petclinic | err-port-in-use | 1 | `ction":"pull"}]}]}

error: run: pull image registry-1.docker.io/bench/spring-petclinic:latest failed: registry error: registry returned HTTP 401: {"errors":[{"c` |
| uptime-kuma | compose-up | 1 | `2026-08-27T19:48:27.643265Z ERROR ferro_cli::linux_cli: compose partial result: uptime-kuma run failed: network error: slirp4netns API socket did not become rea` |
| uptime-kuma | compose-health | 1 | `` |
