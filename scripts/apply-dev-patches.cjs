const { existsSync, readFileSync } = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const patches = [
  ["hardhat", "3.21.2"],
  ["@nomicfoundation/hardhat-mocha", "4.0.1"],
  ["@nomicfoundation/hardhat-zod-utils", "3.0.8"],
];

function gitApply(args, patchPath) {
  // On Windows, Git checkout may rewrite tracked .patch files as CRLF.
  // Normalize only the patch text before supplying it to git apply; keep
  // strict context matching and version checks so incompatible patches fail.
  const input = readFileSync(patchPath, "utf8").replace(/\r\n/g, "\n");
  const result = spawnSync("git", ["apply", ...args, "-"], {
    cwd: root,
    encoding: "utf8",
    input,
  });
  if (result.error) throw result.error;
  return result;
}

if (process.env.NODE_ENV === "production" && patches.every(([name]) => !existsSync(path.join(root, "node_modules", name)))) {
  console.log("Development dependencies omitted; no Hardhat consumers need patching.");
} else {
  for (const [name, version] of patches) {
    const manifest = JSON.parse(readFileSync(path.join(root, "node_modules", name, "package.json"), "utf8"));
    if (manifest.version !== version) {
      throw new Error(`Review the Zod patch for ${name}: expected ${version}, found ${manifest.version}.`);
    }
    const patch = path.join(root, "patches", `${name.replace("/", "+")}+${version}.patch`);
    const check = gitApply(["--check"], patch);
    if (check.status === 0) {
      const applied = gitApply([], patch);
      if (applied.status !== 0) {
        throw new Error(`Failed to apply ${name} Zod patch:\n${applied.stderr}`);
      }
      console.log(`Applied ${name}@${version} Zod patch.`);
    } else {
      const reverse = gitApply(["--reverse", "--check"], patch);
      if (reverse.status !== 0) {
        throw new Error(`Zod patch for ${name} neither applies nor is already applied:\n${check.stderr}\n${reverse.stderr}`);
      }
      console.log(`${name}@${version} Zod patch already applied.`);
    }
  }
}
