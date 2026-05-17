const BASE54_HEAD = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
const BASE54_TAIL = `${BASE54_HEAD}0123456789`;
const LUA_RESERVED = new Set([
  "and", "break", "continue", "do", "else", "elseif", "end", "false", "for", "function",
  "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until",
  "while",
]);

export class XorShift32 {
  private state: number;
  private readonly head: string[];
  private readonly tail: string[];
  private identCounter = 0;

  constructor(seed: number) {
    this.state = seed >>> 0 || 0x9e3779b9;
    this.head = shuffleChars(BASE54_HEAD, this);
    this.tail = shuffleChars(BASE54_TAIL, this);
  }

  nextUint32(): number {
    let x = this.state >>> 0;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x >>> 0;
    return this.state;
  }

  nextInt(maxExclusive: number): number {
    if (maxExclusive <= 0) {
      return 0;
    }
    return this.nextUint32() % maxExclusive;
  }

  nextRange(minInclusive: number, maxInclusive: number): number {
    if (maxInclusive <= minInclusive) {
      return minInclusive;
    }
    return minInclusive + this.nextInt((maxInclusive - minInclusive) + 1);
  }

  nextIdentifier(prefix = ""): string {
    while (true) {
      const id = this.indexToIdentifier(this.identCounter);
      this.identCounter += 1;
      if (LUA_RESERVED.has(id)) {
        continue;
      }
      return prefix ? `${prefix}${id}` : id;
    }
  }

  private indexToIdentifier(index: number): string {
    let n = index;
    let out = this.head[n % this.head.length];
    n = Math.floor(n / this.head.length);
    while (n > 0) {
      n -= 1;
      out += this.tail[n % this.tail.length];
      n = Math.floor(n / this.tail.length);
    }
    return out;
  }
}

export function toBase54(value: number): string {
  let n = value >>> 0;
  let out = BASE54_HEAD[n % BASE54_HEAD.length];
  n = Math.floor(n / BASE54_HEAD.length);
  while (n > 0) {
    out += BASE54_TAIL[n % BASE54_TAIL.length];
    n = Math.floor(n / BASE54_TAIL.length);
  }
  return out;
}

export function escapeLuaString(value: string): string {
  return `"${value
    .replace(/\\/g, "\\\\")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t")
    .replace(/"/g, '\\"')}"`;
}

export function utf8ToHex(value: string): string {
  return Buffer.from(value, "utf8").toString("hex");
}

function shuffleChars(value: string, rng: XorShift32): string[] {
  const chars = value.split("");
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapIndex = rng.nextInt(index + 1);
    const temp = chars[index];
    chars[index] = chars[swapIndex];
    chars[swapIndex] = temp;
  }
  return chars;
}

export function minifyLua(source: string): string {
  let out = "";
  let index = 0;
  let inString = false;
  let stringQuote = "";
  let escape = false;
  let spacePending = false;

  const isWord = (char: string): boolean => /[A-Za-z0-9_]/.test(char);

  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1] ?? "";

    if (inString) {
      out += char;
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === stringQuote) {
        inString = false;
        stringQuote = "";
      }
      index += 1;
      continue;
    }

    if ((char === '"' || char === "'")) {
      if (spacePending && out.length > 0 && isWord(out[out.length - 1])) {
        out += " ";
      }
      spacePending = false;
      inString = true;
      stringQuote = char;
      out += char;
      index += 1;
      continue;
    }

    if (char === "-" && next === "-") {
      index += 2;
      while (index < source.length && source[index] !== "\n") {
        index += 1;
      }
      spacePending = true;
      continue;
    }

    if (/\s/.test(char)) {
      spacePending = true;
      index += 1;
      continue;
    }

    if (spacePending) {
      const prev = out[out.length - 1] ?? "";
      if (out.length > 0 && isWord(prev) && isWord(char)) {
        out += " ";
      }
      spacePending = false;
    }

    out += char;
    index += 1;
  }

  return out.trim();
}
