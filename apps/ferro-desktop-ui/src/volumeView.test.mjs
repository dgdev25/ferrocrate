import assert from "node:assert/strict";
import test from "node:test";

import { formatVolumeMount, volumeIsInUse } from "./volumeView.mjs";

test("volume mounts display container, destination, and access mode", () => {
  assert.equal(
    formatVolumeMount({
      container_name: "api",
      destination: "/var/lib/data",
      read_write: true,
    }),
    "api → /var/lib/data (rw)",
  );
  assert.equal(
    formatVolumeMount({
      container_name: "backup",
      destination: "/snapshot",
      read_write: false,
    }),
    "backup → /snapshot (ro)",
  );
});

test("a volume is in use when any container mount references it", () => {
  assert.equal(volumeIsInUse({ mounts: [] }), false);
  assert.equal(volumeIsInUse({ mounts: [{ container_id: "container-1" }] }), true);
});
