import * as fs from "fs";
import * as path from "path";
import { IronVeilObfuscator } from "./obfuscator";

function main(): void {
  const [, , inputFile, outputFile] = process.argv;
  if (!inputFile) {
    console.error("Usage: node dist/cli.js <input.lua|input.luau> [output.lua]");
    process.exit(1);
  }

  const source = fs.readFileSync(inputFile, "utf8");
  const obfuscator = new IronVeilObfuscator();
  const output = obfuscator.obfuscate(source);
  const resolvedOutput = outputFile ?? defaultOutputPath(inputFile);
  fs.writeFileSync(resolvedOutput, output, "utf8");
  console.log(`IronVeil wrote ${resolvedOutput}`);
}

function defaultOutputPath(inputFile: string): string {
  const extension = path.extname(inputFile);
  const base = inputFile.slice(0, extension.length > 0 ? -extension.length : undefined);
  return `${base}.ironveil.lua`;
}

main();
