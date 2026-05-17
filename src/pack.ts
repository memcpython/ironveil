import type { IRValue } from "./types";
import { utf8ToHex } from "./util";

export function serializePayload(value: IRValue): string {
  if (value === null) {
    return "Z";
  }

  if (typeof value === "boolean") {
    return value ? "T" : "F";
  }

  if (typeof value === "number") {
    return `N${value};`;
  }

  if (typeof value === "string") {
    const hex = utf8ToHex(value);
    return `S${hex.length}:${hex}`;
  }

  if (Array.isArray(value)) {
    return `A${value.length}[${value.map((entry) => serializePayload(entry as IRValue)).join("")}]`;
  }

  const keys = Object.keys(value).sort();
  let out = `O${keys.length}{`;
  for (const key of keys) {
    out += serializePayload(key);
    out += serializePayload((value as Record<string, IRValue>)[key]);
  }
  out += "}";
  return out;
}

export function compressToEncryptedBase64(input: string, seed: number): string {
  const codes = compressLzw(input);
  const bytes = encodeCodes(codes);
  const encrypted = xorPayload(bytes, seed);
  return Buffer.from(encrypted).toString("base64");
}

export function hashPayload(input: string, seed: number): number {
  let hash = (seed ^ 0xa5a5a5a5) >>> 0;

  for (let index = 0; index < input.length; index += 1) {
    hash = (hash + (input.charCodeAt(index) & 0xff) + (((index + 1) * 97) >>> 0)) >>> 0;
    hash ^= (hash << 13) >>> 0;
    hash ^= hash >>> 7;
    hash ^= (hash << 17) >>> 0;
    hash >>>= 0;
  }

  return hash >>> 0;
}

function compressLzw(input: string): number[] {
  const clearCode = 256;
  const endCode = 257;
  let nextCode = 258;
  let dictionary = createInitialDictionary();
  const codes: number[] = [clearCode];
  let phrase = "";

  for (let index = 0; index < input.length; index += 1) {
    const char = input.charAt(index);
    const combined = phrase + char;
    if (dictionary.has(combined)) {
      phrase = combined;
      continue;
    }

    if (phrase.length > 0) {
      codes.push(dictionary.get(phrase)!);
    }

    dictionary.set(combined, nextCode);
    nextCode += 1;

    if (nextCode >= 4095) {
      codes.push(clearCode);
      dictionary = createInitialDictionary();
      nextCode = 258;
    }

    phrase = char;
  }

  if (phrase.length > 0) {
    codes.push(dictionary.get(phrase)!);
  }

  codes.push(endCode);
  return codes;
}

function encodeCodes(codes: number[]): Uint8Array {
  const bytes = new Uint8Array(codes.length * 2);
  for (let index = 0; index < codes.length; index += 1) {
    const code = codes[index];
    bytes[index * 2] = (code >>> 8) & 0xff;
    bytes[(index * 2) + 1] = code & 0xff;
  }
  return bytes;
}

function xorPayload(bytes: Uint8Array, seed: number): Uint8Array {
  let state = ((seed ^ 0x13579bdf) >>> 0) || 0x9e3779b9;
  const output = new Uint8Array(bytes.length);

  for (let index = 0; index < bytes.length; index += 1) {
    state = nextXorShift32(state);
    const mask = ((state & 0xff) + ((seed + ((index + 1) * 29)) & 0xff)) & 0xff;
    output[index] = bytes[index] ^ mask;
  }

  return output;
}

function nextXorShift32(state: number): number {
  let x = state >>> 0;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  return x >>> 0;
}

function createInitialDictionary(): Map<string, number> {
  const dictionary = new Map<string, number>();
  for (let index = 0; index < 256; index += 1) {
    dictionary.set(String.fromCharCode(index), index);
  }
  return dictionary;
}
