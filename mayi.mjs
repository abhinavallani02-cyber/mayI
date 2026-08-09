#!/usr/bin/env node
// mayI -- MCP proxy with a policy engine and human-in-the-loop approval.
// Spawns a real MCP server as a child process and forwards every line
// stdin -> child.stdin and child.stdout -> stdout unchanged, EXCEPT
// tools/call requests: those are checked against policy.yaml first.
//   allow -> forwarded to the server, like any other line
//   deny  -> never reaches the server; a JSON-RPC error goes back to
//            the client instead, on the same id
//   ask   -> a human is prompted on the controlling terminal (/dev/tty,
//            not stdin -- stdin is the MCP client's channel, not a
//            human's). y -> forwarded like allow. n or a 30s timeout ->
//            denied like deny. Other in-flight lines are NOT blocked
//            while a prompt is pending -- only that one request waits.
// Everything that isn't a tools/call request is still pure passthrough.

import { readFileSync, createReadStream, createWriteStream, appendFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { parse as parseYaml } from "yaml";

const HELP_TEXT = `mayi -- an MCP proxy that enforces allow/deny/ask policy on tool calls

Usage:
  mayi [--policy <file>] [--audit <file>] [--audit-include-args] -- <command> [args...]

Everything after -- is the real MCP server to spawn and front.

Options:
  --policy <file>       Policy YAML file. Defaults to ./policy.yaml if it
                         exists, otherwise a built-in conservative default
                         (reads allowed, everything else asks).
  --audit <file>        Audit log path. Defaults to ./audit.jsonl.
  --audit-include-args  Include call arguments in the audit log. Off by
                         default -- arguments can carry file contents,
                         paths, or other sensitive data.
  -h, --help            Show this help and exit.

Example:
  mayi --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /path/to/allow`;

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(HELP_TEXT);
  process.exit(0);
}

const sepIndex = process.argv.indexOf("--");
if (sepIndex === -1 || sepIndex === process.argv.length - 1) {
  console.error("mayi: no server command given -- everything after \"--\" is the command to run.");
  console.error();
  console.error(HELP_TEXT);
  process.exit(1);
}
const beforeSep = process.argv.slice(2, sepIndex);
const policyFlagIndex = beforeSep.indexOf("--policy");
const explicitPolicyPath = policyFlagIndex === -1 ? null : beforeSep[policyFlagIndex + 1];
const auditFlagIndex = beforeSep.indexOf("--audit");
const auditPath = auditFlagIndex === -1 ? "audit.jsonl" : beforeSep[auditFlagIndex + 1];
const auditIncludeArgs = beforeSep.includes("--audit-include-args");
const [command, ...args] = process.argv.slice(sepIndex + 1);

// Zero-config fallback: if no --policy was given and there's no
// policy.yaml in the current directory, use a built-in conservative
// default rather than requiring a config file to exist before mayI can
// run at all. Reads are safe on their own; everything else asks, so a
// brand-new user gets prompted rather than silently allowed or blocked.
const BUILTIN_DEFAULT_POLICY = {
  rules: [
    { tool: "read_*", action: "allow" },
    { tool: "list_*", action: "allow" },
    { tool: "get_*", action: "allow" },
    { tool: "search_*", action: "allow" },
    { tool: "*", action: "ask" },
  ],
};

let policyPath = explicitPolicyPath;
let policy;
let policySource;
if (policyPath) {
  if (!existsSync(policyPath)) {
    console.error(`mayi: policy file not found: ${policyPath}`);
    process.exit(1);
  }
  policy = loadPolicyFile(policyPath);
  policySource = policyPath;
} else if (existsSync("policy.yaml")) {
  policyPath = "policy.yaml";
  policy = loadPolicyFile(policyPath);
  policySource = policyPath;
} else {
  policy = BUILTIN_DEFAULT_POLICY;
  policySource = "built-in default (reads allowed, everything else asks)";
}

// Reads and parses a policy YAML file, exiting with a clear message
// instead of a raw stack trace on malformed YAML or a missing/invalid
// rules list -- the two ways a hand-edited policy file commonly breaks.
function loadPolicyFile(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`mayi: couldn't read policy file ${path}: ${err.message}`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    console.error(`mayi: policy file ${path} is not valid YAML: ${err.message}`);
    process.exit(1);
  }
  if (!parsed || !Array.isArray(parsed.rules)) {
    console.error(`mayi: policy file ${path} must have a top-level "rules" list.`);
    process.exit(1);
  }
  return parsed;
}

console.error(`[CONFIG] policy: ${policySource}`);
console.error(`[CONFIG] audit mode: ${auditIncludeArgs ? "decisions + args" : "decisions only"}`);

// Appends one decision to the audit log. fs.appendFileSync issues a
// single write syscall per call with the O_APPEND flag, so concurrent
// appends from this process can't interleave mid-line -- each call is
// atomic at the line level. Deliberately excludes the response payload
// always. Whether it includes the call arguments is controlled by
// --audit-include-args -- off by default, since arguments can carry
// file contents, paths, or other sensitive data that shouldn't land on
// disk in plaintext without the operator opting in explicitly.
function appendAudit(id, name, verdict, callArgs) {
  const entry = { timestamp: new Date().toISOString(), id, tool: name, verdict };
  if (auditIncludeArgs) entry.args = callArgs;
  appendFileSync(auditPath, JSON.stringify(entry) + "\n");
}

// Converts a glob like "fs.write_*" into a fully-anchored RegExp. Only
// "*" is special (matches any run of characters); every other character
// is escaped literally, so tool names containing regex metacharacters
// (e.g. a tool literally named "a+b") still match exactly as written.
function globToRegex(glob) {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`);
}
const compiledRules = policy.rules.map((rule) => ({ ...rule, regex: globToRegex(rule.tool) }));

// Argument keys checked against a rule's path_prefix. Different tools
// use different names for "the path this call touches" -- read/write
// tools use `path`, move/rename tools use `source`/`destination`. A
// rule matches if ANY of these keys is present and starts with the
// prefix, so one rule can cover write_file and move_file alike.
const PATH_ARG_KEYS = ["path", "source", "destination"];

// True if this rule has no path_prefix (always matches on that axis),
// or if at least one path-bearing argument starts with it.
function pathMatches(rule, callArgs) {
  if (!rule.path_prefix) return true;
  if (!callArgs) return false;
  return PATH_ARG_KEYS.some(
    (key) => typeof callArgs[key] === "string" && callArgs[key].startsWith(rule.path_prefix)
  );
}

// First matching rule wins; a policy file is expected to end with a
// catch-all ("*") rule, but if it doesn't, unmatched calls default to
// ask. A rule with a path_prefix only matches calls whose path-bearing
// argument starts with that prefix -- e.g. `tool: write_*, path_prefix:
// /etc` matches a write to /etc/hosts but not one to ~/notes.md.
function decide(toolName, callArgs) {
  const rule = compiledRules.find((r) => r.regex.test(toolName) && pathMatches(r, callArgs));
  return rule
    ? { action: rule.action, matchedRule: rule.path_prefix ? `${rule.tool} (path_prefix: ${rule.path_prefix})` : rule.tool }
    : { action: "ask", matchedRule: "(no match, default)" };
}

const ASK_TIMEOUT_MS = 30000;

// Opens /dev/tty and asks one y/n question, then closes it immediately.
// /dev/tty is deliberately NOT held open between prompts: on macOS (and
// most Unixes) it resolves to the same underlying terminal device as
// process.stdin when stdin is a tty. Two independent readers on that
// one device race for every keystroke the OS delivers, and readline
// reliably wins that race -- so a persistent /dev/tty reader silently
// starves process.stdin for the entire life of the process, not just
// during a prompt. Opening lazily, only for the duration of a single
// question, means /dev/tty is only ever in that race for the brief
// window an answer is actually being read.
//
// Not exported directly -- see askHuman below, which serializes calls
// to this so two concurrent tools/call requests needing "ask" can never
// open two /dev/tty readers at once and reintroduce the same race.
//
// Needs BOTH a read stream and a write stream on /dev/tty: readline
// writes the prompt text to `output`, and reads the answer from
// `input`. Without an output, question() has nowhere to put the prompt
// and it's silently never shown, even though the interface is still
// correctly reading answers. Both are opened lazily and closed in
// finish(), same as the read side alone was before -- this doubles the
// fds involved but not the duration either is held open for.
function promptOnce(id, name, args) {
  return new Promise((resolve) => {
    let settled = false;
    let ttyIn, ttyOut, rl;
    let inReady = false, outReady = false;

    function finish(outcome) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (rl) rl.close();
      if (ttyIn) ttyIn.destroy();
      if (ttyOut) ttyOut.destroy();
      resolve(outcome);
    }

    function onTtyError(err) {
      // Both ttyIn and ttyOut can error independently (e.g. no
      // controlling terminal at all -- both fail with ENXIO), but
      // finish() is idempotent and only the first error is the
      // interesting one, so only log once.
      if (settled) return;
      console.error(`[ASK] id=${id} tool=${name} args=${JSON.stringify(args)} -- no tty available (${err.message}), defaulting to deny`);
      finish("denied");
    }

    // Only ask once BOTH streams are open -- question() writes the
    // prompt through `output` as soon as it's called, so if output
    // isn't ready yet the prompt would be silently dropped just like
    // the original bug, only for the write side instead of missing
    // entirely.
    function maybeAsk() {
      if (!inReady || !outReady || settled) return;
      rl = createInterface({ input: ttyIn, output: ttyOut });
      rl.question(
        `[ASK] id=${id} tool=${name} args=${JSON.stringify(args)}. Approve? (y/n): `,
        (answer) => finish(answer.trim().toLowerCase() === "y" ? "approved" : "denied")
      );
    }

    const timer = setTimeout(() => {
      console.error(`\n[ASK] id=${id} timed out after ${ASK_TIMEOUT_MS}ms, defaulting to deny`);
      finish("denied");
    }, ASK_TIMEOUT_MS);

    ttyIn = createReadStream("/dev/tty");
    ttyIn.on("error", onTtyError);
    ttyIn.on("open", () => { inReady = true; maybeAsk(); });

    ttyOut = createWriteStream("/dev/tty");
    ttyOut.on("error", onTtyError);
    ttyOut.on("open", () => { outReady = true; maybeAsk(); });
  });
}

// Serializes prompts: if a second tools/call needs "ask" while a prompt
// is already pending, its question waits for the current one to finish
// (answered or timed out) before /dev/tty is opened again. This is the
// only thing that queues -- handleClientLine is still fired-and-not-
// awaited per line, so other allow/deny decisions and server traffic
// keep flowing while a prompt (or several, queued) is pending.
let askQueue = Promise.resolve();
function askHuman(id, name, args) {
  const result = askQueue.then(() => promptOnce(id, name, args));
  askQueue = result.catch(() => {}); // keep the chain alive even if a link ever rejects
  return result;
}

const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });

// stdin -> child.stdin, buffered and split on newlines. Every line is
// still forwarded verbatim UNLESS it's a tools/call request that policy
// denies -- that's the one case where the raw `line` is deliberately not
// written to child.stdin. Buffering/splitting logic is unchanged from
// the pure-passthrough version: preserves line boundaries regardless of
// how bytes were chunked on the way in.
let stdinBuffer = "";
process.stdin.on("data", (chunk) => {
  stdinBuffer += chunk.toString();
  let newlineIndex;
  while ((newlineIndex = stdinBuffer.indexOf("\n")) !== -1) {
    const line = stdinBuffer.slice(0, newlineIndex);
    stdinBuffer = stdinBuffer.slice(newlineIndex + 1);
    handleClientLine(line);
  }
});
process.stdin.on("end", () => child.stdin.end());

// Parses a raw line from the client. Non-JSON-RPC or non-tools/call
// lines are forwarded untouched -- policy only ever looks at tools/call.
// A tools/call line is checked against policy before forwarding; on
// deny (including an ask that gets refused or times out), the line
// never reaches the server and an error goes back to the client on
// stdout instead. This is async because "ask" waits on a human, but the
// caller (the stdin drain loop) does NOT await it -- so a slow human
// answering one prompt never blocks any other line already in flight.
async function handleClientLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    child.stdin.write(line + "\n"); // not JSON -- not ours to inspect, pass through
    return;
  }
  if (msg.method !== "tools/call") {
    child.stdin.write(line + "\n");
    return;
  }

  const { name, arguments: args } = msg.params ?? {};
  console.error(`[INSPECT] id=${msg.id} tool=${name} args=${JSON.stringify(args)}`);

  const { action, matchedRule } = decide(name, args);
  let decision = action;
  let verdictLabel = action;

  if (action === "ask") {
    const outcome = await askHuman(msg.id, name, args); // "approved" | "denied"
    decision = outcome === "approved" ? "allow" : "deny";
    verdictLabel = `ask→${outcome}`;
  }

  console.error(`[VERDICT] id=${msg.id} tool=${name} decision=${verdictLabel}`);
  appendAudit(msg.id, name, verdictLabel, args);

  if (decision === "deny") {
    const errorResponse = {
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32602, message: `Blocked by policy: ${matchedRule}` },
    };
    process.stdout.write(JSON.stringify(errorResponse) + "\n");
    return; // never forwarded to the server
  }

  child.stdin.write(line + "\n");
}

// child.stdout -> stdout, same buffering treatment in the other direction.
let stdoutBuffer = "";
child.stdout.on("data", (chunk) => {
  stdoutBuffer += chunk.toString();
  let newlineIndex;
  while ((newlineIndex = stdoutBuffer.indexOf("\n")) !== -1) {
    const line = stdoutBuffer.slice(0, newlineIndex);
    stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
    process.stdout.write(line + "\n");
  }
});

// child.stderr is already wired straight through via stdio: "inherit"
// above -- no buffering needed, it's not part of the framed protocol.

// If the child dies, we die the same way, so the client sees the same
// failure mode as if it had spawned the real server itself.
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 0);
  }
});

child.on("error", (err) => {
  console.error(`mayI: failed to start child process: ${err.message}`);
  process.exit(1);
});

// If mayI itself is killed, kill the child too -- no orphaned processes.
// Registering a signal listener at all disables Node's default behavior
// of exiting on that signal, so this handler must exit explicitly --
// otherwise mayI hangs forever after Ctrl+C, waiting on nothing.
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => {
    child.kill(sig);
    process.exit(0);
  });
}
