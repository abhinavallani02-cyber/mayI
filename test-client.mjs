// Drives whatever process is passed as argv, via -- <command> [args...],
// exactly like a real MCP client would: initialize, tools/list, tools/call.
// Used to test mayi.mjs (spawns it, which spawns the real server) and,
// separately, the real server directly -- so the two outputs can be
// diffed to prove the proxy is byte-for-byte transparent.

import { spawn } from "node:child_process";

const sepIndex = process.argv.indexOf("--");
const [command, ...args] = process.argv.slice(sepIndex + 1);

const proc = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });

let inBuffer = "";
const pending = new Map();
proc.stdout.on("data", (chunk) => {
  inBuffer += chunk.toString();
  let i;
  while ((i = inBuffer.indexOf("\n")) !== -1) {
    const line = inBuffer.slice(0, i);
    inBuffer = inBuffer.slice(i + 1);
    if (!line) continue;
    console.log(line); // print raw response lines only, for diffing
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

let nextId = 1;
function send(method, params) {
  const id = nextId++;
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve) => pending.set(id, resolve));
}
function sendNotification(method, params) {
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

async function main() {
  await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "test-client", version: "0.0.1" },
  });
  sendNotification("notifications/initialized", {});
  await send("tools/list", {});
  await send("tools/call", { name: "read_text_file", arguments: { path: "hello.txt" } });
  await send("tools/call", { name: "list_directory", arguments: { path: "." } });
  await send("tools/call", { name: "get_file_info", arguments: { path: "hello.txt" } });

  proc.stdin.end();
  proc.kill();
  process.exit(0);
}

main();
