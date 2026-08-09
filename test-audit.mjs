// Drives mayi.mjs through calls that hit allow, deny, and ask-> denied
// (no tty in this sandbox), then leaves the audit file for inspection.
// Usage: node test-audit.mjs <audit-file> [--audit-include-args]

import { spawn } from "node:child_process";

const auditFile = process.argv[2] ?? "audit.jsonl";
const extraFlags = process.argv.includes("--audit-include-args") ? ["--audit-include-args"] : [];

const proc = spawn(
  "node",
  ["mayi.mjs", "--policy", "policy.yaml", "--audit", auditFile, ...extraFlags, "--", "node",
   "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "./sandbox"],
  { stdio: ["pipe", "pipe", "inherit"] }
);

let inBuffer = "";
const pending = new Map();
proc.stdout.on("data", (chunk) => {
  inBuffer += chunk.toString();
  let i;
  while ((i = inBuffer.indexOf("\n")) !== -1) {
    const line = inBuffer.slice(0, i);
    inBuffer = inBuffer.slice(i + 1);
    if (!line) continue;
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

  console.log("\n>>> read_text_file (policy: read_* -> allow)");
  console.log("response:", JSON.stringify(await send("tools/call", { name: "read_text_file", arguments: { path: "hello.txt" } })));

  console.log("\n>>> write_file (policy: write_* -> ask; no tty here, so ask -> denied)");
  console.log("response:", JSON.stringify(await send("tools/call", { name: "write_file", arguments: { path: "hello.txt", content: "nope" } })));

  proc.stdin.end();
  proc.kill();
  process.exit(0);
}

main();
