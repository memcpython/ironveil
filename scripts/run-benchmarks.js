const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { IronVeilObfuscator } = require("../dist");

const root = path.resolve(__dirname, "..");
const benchmarkDir = path.join(root, "benchmarks");
const outputDir = path.join(root, ".bench-out");
const luaExe = "lua";

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function runLua(file) {
  const started = Date.now();
  const result = spawnSync(luaExe, [file], {
    cwd: root,
    encoding: "utf8",
  });
  return {
    status: result.status,
    stdout: result.stdout.replace(/\r\n/g, "\n"),
    stderr: result.stderr.replace(/\r\n/g, "\n"),
    ms: Date.now() - started,
  };
}

function listBenchmarks() {
  const files = fs.readdirSync(benchmarkDir)
    .filter((file) => file.endsWith(".lua"))
    .sort();
  return [
    path.join(root, "test.lua"),
    ...files.map((file) => path.join(benchmarkDir, file)),
  ];
}

function obfuscateFile(inputFile, seed) {
  const source = fs.readFileSync(inputFile, "utf8");
  const obfuscator = new IronVeilObfuscator({ seed });
  const output = obfuscator.obfuscate(source);
  const outputFile = path.join(outputDir, path.basename(inputFile, ".lua") + ".obf.lua");
  fs.writeFileSync(outputFile, output, "utf8");
  return outputFile;
}

function formatResult(label, result) {
  return `${label} status=${result.status} time=${result.ms}ms stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`;
}

function main() {
  ensureDir(outputDir);
  const files = listBenchmarks();
  let failures = 0;

  for (let index = 0; index < files.length; index += 1) {
    const inputFile = files[index];
    const obfuscatedFile = obfuscateFile(inputFile, 0x13572468 + index);
    const original = runLua(inputFile);
    const obfuscated = runLua(obfuscatedFile);
    const same = original.status === obfuscated.status
      && original.stdout === obfuscated.stdout
      && original.stderr === obfuscated.stderr;

    console.log(`\n[${path.basename(inputFile)}]`);
    console.log(formatResult("original", original));
    console.log(formatResult("obfuscated", obfuscated));

    if (!same) {
      failures += 1;
      console.log("mismatch detected");
    }
  }

  if (failures > 0) {
    console.error(`\nbenchmark failures: ${failures}`);
    process.exit(1);
  }

  console.log(`\nall benchmarks passed: ${files.length}`);
}

main();
