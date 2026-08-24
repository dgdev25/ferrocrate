import test from "node:test";
import assert from "node:assert/strict";

import { buildRunContainerOptions } from "./runContainer.mjs";

test("run dialog converts friendly fields into daemon run options", () => {
  assert.deepEqual(buildRunContainerOptions({
    command: "sh -c echo-ready",
    ports: [{ host: "8080", container: "80" }, { host: "", container: "" }],
    volumes: [{ source: "data", target: "/data" }],
    memoryMb: "128",
    cpus: "0.5",
  }), {
    command: ["sh", "-c", "echo-ready"],
    ports: ["8080:80"],
    volumes: ["data:/data"],
    memory: 134217728,
    cpuQuota: 50000,
    cpuPeriod: 100000,
  });
});
