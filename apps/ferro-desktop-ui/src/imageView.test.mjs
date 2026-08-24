import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const appSource = await readFile(new URL("./App.tsx", import.meta.url), "utf8");

test("images page presents a table, pull dialog, and overflow actions instead of permanent controls", () => {
  assert.match(appSource, /const imageRows = useMemo\(\(\) => parseImageRows/);
  assert.match(appSource, /<th>Repository<\/th><th>Size<\/th><th>Created<\/th><th>In use<\/th>/);
  assert.match(appSource, /onClick=\{\(\) => setPullImageDialogOpen\(true\)\}/);
  assert.match(appSource, /image-toolbar-overflow/);
  assert.match(appSource, /aria-labelledby="pull-image-dialog-title"/);
  assert.doesNotMatch(appSource, /onClick=\{\(\) => void runAction\("pull_image", "Image Pull", imageTarget\)\}/);
});
