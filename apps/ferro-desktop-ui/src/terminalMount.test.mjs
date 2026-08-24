import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("the terminal mount effect reruns when its conditional host appears", async () => {
  const app = await readFile(new URL("./App.tsx", import.meta.url), "utf8");

  assert.match(app, /const \[terminalHost, setTerminalHost\] = useState/);
  assert.match(app, /ref=\{setTerminalHost\}/);
  assert.match(app, /\}, \[terminalHost\]\);/);
});
