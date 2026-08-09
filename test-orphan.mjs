// Verifies: killing mayI also kills its child (no orphans).
// Spawns mayi.mjs as a subprocess of THIS script, sends it SIGINT after
// a short delay, and checks whether the filesystem server child (which
// logs a line to stderr on startup) is still alive afterward by trying
// to signal its pid with signal 0 (a no-op existence check).

import { spawn } from "node:child_process";

const mayi = spawn(
  "node",
  ["mayi.mjs", "--", "node", "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "./sandbox"],
  { stdio: ["pipe", "pipe", "pipe"] }
);

let childPid = null;
mayi.stderr.on("data", (chunk) => {
  const text = chunk.toString();
  process.stdout.write("mayI child stderr: " + text);
});

// mayI doesn't print its child's pid, so we grep the process tree for it
// via `pgrep -P <mayi pid>` once we know mayI itself started.
import { execSync } from "node:child_process";

setTimeout(() => {
  try {
    childPid = execSync(`pgrep -P ${mayi.pid}`).toString().trim();
  } catch {
    childPid = null;
  }
  console.log(`mayI pid=${mayi.pid}, child pid=${childPid || "(not found)"}`);

  console.log("sending SIGINT to mayI...");
  mayi.kill("SIGINT");

  setTimeout(() => {
    if (!childPid) {
      console.log("could not determine child pid -- inconclusive");
    } else {
      try {
        process.kill(Number(childPid), 0); // throws if process doesn't exist
        console.log(`child pid ${childPid} STILL ALIVE -- ORPHAN (bad)`);
      } catch {
        console.log(`child pid ${childPid} is gone -- no orphan (good)`);
      }
    }
    process.exit(0);
  }, 1000);
}, 1000);
