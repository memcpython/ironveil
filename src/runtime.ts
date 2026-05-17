import type { IRExpression, IRFunction, IRLValue, IRModule, IRStatement, IRValue } from "./types";
import type { VmProfile } from "./profile";
import { compressToEncryptedBase64, hashPayload, serializePayload } from "./pack";
import { escapeLuaString, minifyLua, XorShift32 } from "./util";

const OP_MASK = 0xffff;

const BINARY_DEF_NAMES = ["+", "-", "*", "/", "%", "^", "..", "==", "~=", "<", "<=", ">", ">=", "&", "|", "~", "<<", ">>"] as const;
const UNARY_DEF_NAMES = ["-", "not", "#", "~"] as const;
const EXPR_DEF_NAMES = ["id", "str", "num", "bool", "nil", "vararg", "binary", "unary", "member", "call", "table", "function", "mini"] as const;
const STMT_DEF_NAMES = ["local", "assign", "expr", "return", "if", "while", "repeat", "fornum", "forin", "break", "continue", "do", "func"] as const;
const LUA_RESERVED = new Set([
  "and", "break", "continue", "do", "else", "elseif", "end", "false", "for", "function",
  "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until",
  "while",
]);

interface RuntimeCodes {
  binary: Record<string, number>;
  unary: Record<string, number>;
  expr: Record<string, number>;
  stmt: Record<string, number>;
  lvalue: Record<string, number>;
  field: Record<string, number>;
}

type SpecKind = "binary" | "unary" | "expr" | "stmt";

interface MutationState {
  node: number;
  op: number;
  prevNode: number;
  prevOp: number;
  nodeHash: number;
  opHash: number;
}

interface RuntimeSaltSet {
  stmt: number;
  expr: number;
  lvalue: number;
  field: number;
  binary: number;
  unary: number;
  defBinary: number;
  defUnary: number;
  defExpr: number;
  defStmt: number;
}

interface RuntimeSecrets {
  salts: RuntimeSaltSet;
  payloadKey: number;
  payloadHashSeed: number;
}

export function emitLuaLoader(module: IRModule, profile: VmProfile): string {
  const secrets = deriveRuntimeSecrets(profile.nameSeed);
  const payload = preparePayload(module, profile, secrets.salts);
  const serialized = serializePayload(payload);
  const payloadHash = hashPayload(serialized, secrets.payloadHashSeed);
  const encoded = compressToEncryptedBase64(serialized, secrets.payloadKey);
  const chunks = splitEncoded(encoded, profile.chunkCount);
  const body = wrapLuaStatementsInVarargIife(runtimeTemplate(module, profile, chunks, secrets, payloadHash), 1);
  const watermark = "--[[\nObfuscated using ironveil v1 - https://discord.gg/qKyZKDWZRQ\n]]\n";

  const raw = [
    "return(function(...)",
    `return ${body}`,
    "end)(...)",
  ].join("\n");

  const minified = minifyLua(raw);
  const randomized = randomizeIdentifiers(minified, profile.nameSeed ^ 0x243f6a88);
  return `${watermark}${randomized}`;
}

function deriveRuntimeSecrets(seed: number): RuntimeSecrets {
  const rng = new XorShift32((seed ^ 0x7f4a7c15) >>> 0);
  const used = new Set<number>();
  const nextSalt = (): number => {
    let value = 0;
    while (value === 0 || used.has(value)) {
      value = (rng.nextUint32() & OP_MASK) || 1;
    }
    used.add(value);
    return value;
  };
  const nextWide = (): number => rng.nextUint32() >>> 0 || 0x9e3779b9;

  return {
    salts: {
      stmt: nextSalt(),
      expr: nextSalt(),
      lvalue: nextSalt(),
      field: nextSalt(),
      binary: nextSalt(),
      unary: nextSalt(),
      defBinary: nextSalt(),
      defUnary: nextSalt(),
      defExpr: nextSalt(),
      defStmt: nextSalt(),
    },
    payloadKey: nextWide(),
    payloadHashSeed: nextWide(),
  };
}

function preparePayload(module: IRModule, profile: VmProfile, salts: RuntimeSaltSet): IRValue {
  const codes = buildCodes(profile);
  const opcodeSeed = ((profile.nameSeed ^ 0x51f15e3d) >>> 0) & OP_MASK || 1;
  const defSeed = ((profile.nameSeed ^ 0x13579bdf) >>> 0) & OP_MASK || 1;

  return [
    1,
    module.entry,
    mutateFunctions(module.functions, codes, opcodeSeed, salts),
    [
      opcodeSeed,
      defSeed,
      buildSpecs("binary", BINARY_DEF_NAMES, codes.binary, defSeed, salts.defBinary),
      buildSpecs("unary", UNARY_DEF_NAMES, codes.unary, defSeed, salts.defUnary),
      buildSpecs("expr", EXPR_DEF_NAMES, codes.expr, defSeed, salts.defExpr),
      buildSpecs("stmt", STMT_DEF_NAMES, codes.stmt, defSeed, salts.defStmt),
    ],
  ];
}

function buildCodes(profile: VmProfile): RuntimeCodes {
  const binary: Record<string, number> = {};
  const unary: Record<string, number> = {};
  const expr: Record<string, number> = {};
  const stmt: Record<string, number> = {};
  const lvalue: Record<string, number> = {};
  const field: Record<string, number> = {};

  for (const key of Object.keys(profile.binaryOps)) {
    binary[key] = profile.binaryOps[key] ^ profile.binaryMask;
  }
  for (const key of Object.keys(profile.unaryOps)) {
    unary[key] = profile.unaryOps[key] ^ profile.unaryMask;
  }
  for (const key of Object.keys(profile.exprTags)) {
    expr[key] = profile.exprTags[key] ^ profile.exprMask;
  }
  for (const key of Object.keys(profile.stmtTags)) {
    stmt[key] = profile.stmtTags[key] ^ profile.stmtMask;
  }
  for (const key of Object.keys(profile.lvalueTags)) {
    lvalue[key] = profile.lvalueTags[key] ^ profile.lvalueMask;
  }
  for (const key of Object.keys(profile.fieldTags)) {
    field[key] = profile.fieldTags[key] ^ profile.fieldMask;
  }

  return { binary, unary, expr, stmt, lvalue, field };
}

function buildSpecs(kind: SpecKind, names: readonly string[], source: Record<string, number>, seed: number, salt: number): IRValue[] {
  return names.map((name, index) => [encodeOpcode(source[name], index + 1, seed, salt), buildSpecPayload(kind, name, index + 1)]);
}

function mutateFunctions(functions: IRFunction[], codes: RuntimeCodes, opcodeSeed: number, salts: RuntimeSaltSet): IRValue[] {
  return functions.map((fn, index) => {
    const state: MutationState = { node: 0, op: 0, prevNode: 0, prevOp: 0, nodeHash: 0, opHash: 0 };
    const key = deriveKey(opcodeSeed, index + 1);
    return [
      [...fn.params],
      mutateStatements(fn.body, codes, key, state, salts),
      fn.vararg ? 1 : 0,
    ];
  });
}

function mutateStatements(statements: IRStatement[], codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): IRStatement[] {
  return statements.map((statement) => mutateStatement(statement, codes, key, state, salts));
}

function mutateStatement(statement: IRStatement, codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): IRStatement {
  const raw = statement as unknown as any[];
  const out = raw.slice() as any[];
  const tag = raw[0] as number;
  out[0] = encodeNodeOpcode(tag, key, salts.stmt, state);

  if (tag === codes.stmt.local) {
    out[2] = mutateExpressions(raw[2] as IRExpression[], codes, key, state, salts);
  } else if (tag === codes.stmt.assign) {
    out[1] = (raw[1] as IRLValue[]).map((item) => mutateLValue(item, codes, key, state, salts));
    out[2] = mutateExpressions(raw[2] as IRExpression[], codes, key, state, salts);
  } else if (tag === codes.stmt.expr) {
    out[1] = mutateExpression(raw[1] as IRExpression, codes, key, state, salts);
  } else if (tag === codes.stmt.return) {
    out[1] = mutateExpressions(raw[1] as IRExpression[], codes, key, state, salts);
  } else if (tag === codes.stmt.if) {
    out[1] = (raw[1] as Array<[IRExpression, IRStatement[]]>).map(([condition, body]) => [
      mutateExpression(condition, codes, key, state, salts),
      mutateStatements(body, codes, key, state, salts),
    ]);
    out[2] = raw[2] ? mutateStatements(raw[2] as IRStatement[], codes, key, state, salts) : null;
  } else if (tag === codes.stmt.while) {
    out[1] = mutateExpression(raw[1] as IRExpression, codes, key, state, salts);
    out[2] = mutateStatements(raw[2] as IRStatement[], codes, key, state, salts);
  } else if (tag === codes.stmt.repeat) {
    out[1] = mutateStatements(raw[1] as IRStatement[], codes, key, state, salts);
    out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
  } else if (tag === codes.stmt.fornum) {
    out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
    out[3] = mutateExpression(raw[3] as IRExpression, codes, key, state, salts);
    out[4] = raw[4] ? mutateExpression(raw[4] as IRExpression, codes, key, state, salts) : null;
    out[5] = mutateStatements(raw[5] as IRStatement[], codes, key, state, salts);
  } else if (tag === codes.stmt.forin) {
    out[2] = mutateExpressions(raw[2] as IRExpression[], codes, key, state, salts);
    out[3] = mutateStatements(raw[3] as IRStatement[], codes, key, state, salts);
  } else if (tag === codes.stmt.do) {
    out[1] = mutateStatements(raw[1] as IRStatement[], codes, key, state, salts);
  } else if (tag === codes.stmt.func) {
    out[2] = mutateLValue(raw[2] as IRLValue, codes, key, state, salts);
  }

  return out as IRStatement;
}

function mutateExpressions(expressions: IRExpression[], codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): IRExpression[] {
  return expressions.map((expression) => mutateExpression(expression, codes, key, state, salts));
}

function mutateExpression(expression: IRExpression, codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): IRExpression {
  const raw = expression as unknown as any[];
  const out = raw.slice() as any[];
  const tag = raw[0] as number;
  out[0] = encodeNodeOpcode(tag, key, salts.expr, state);

  if (tag === codes.expr.binary) {
    out[1] = encodeOpOpcode(raw[1] as number, key, salts.binary, state);
    out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
    out[3] = mutateExpression(raw[3] as IRExpression, codes, key, state, salts);
  } else if (tag === codes.expr.unary) {
    out[1] = encodeOpOpcode(raw[1] as number, key, salts.unary, state);
    out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
  } else if (tag === codes.expr.member) {
    out[1] = mutateExpression(raw[1] as IRExpression, codes, key, state, salts);
    if (raw[3] === 1) {
      out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
    }
  } else if (tag === codes.expr.call) {
    out[1] = mutateExpression(raw[1] as IRExpression, codes, key, state, salts);
    out[2] = mutateExpressions(raw[2] as IRExpression[], codes, key, state, salts);
  } else if (tag === codes.expr.table) {
    out[1] = (raw[1] as any[]).map((field) => mutateField(field, codes, key, state, salts));
  }

  return out as IRExpression;
}

function mutateLValue(target: IRLValue, codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): IRLValue {
  const raw = target as unknown as any[];
  const out = raw.slice() as any[];
  const tag = raw[0] as number;
  out[0] = encodeNodeOpcode(tag, key, salts.lvalue, state);

  if (tag === codes.lvalue.member) {
    out[1] = mutateExpression(raw[1] as IRExpression, codes, key, state, salts);
    if (raw[3] === 1) {
      out[2] = mutateExpression(raw[2] as IRExpression, codes, key, state, salts);
    }
  }

  return out as IRLValue;
}

function mutateField(field: any[], codes: RuntimeCodes, key: number, state: MutationState, salts: RuntimeSaltSet): any[] {
  const out = field.slice();
  const tag = field[0] as number;
  out[0] = encodeNodeOpcode(tag, key, salts.field, state);

  if (tag === codes.field.array) {
    out[1] = mutateExpression(field[1] as IRExpression, codes, key, state, salts);
  } else if (tag === codes.field.record) {
    out[2] = mutateExpression(field[2] as IRExpression, codes, key, state, salts);
  } else {
    out[1] = mutateExpression(field[1] as IRExpression, codes, key, state, salts);
    out[2] = mutateExpression(field[2] as IRExpression, codes, key, state, salts);
  }

  return out;
}

function nextNode(state: MutationState): number {
  state.node += 1;
  return state.node;
}

function nextOp(state: MutationState): number {
  state.op += 1;
  return state.op;
}

function contextMask(previous: number, hash: number, slot: number, salt: number): number {
  return ((previous * 131) + (hash * 17) + salt + slot) & OP_MASK;
}

function nextHash(hash: number, decoded: number, slot: number, salt: number): number {
  return ((hash * 257) + decoded + salt + slot) & OP_MASK;
}

function encodeNodeOpcode(value: number, key: number, salt: number, state: MutationState): number {
  const slot = nextNode(state);
  const mask = contextMask(state.prevNode, state.nodeHash, slot, salt);
  const encoded = encodeOpcode((value ^ mask) & OP_MASK, slot, key, salt);
  state.prevNode = value;
  state.nodeHash = nextHash(state.nodeHash, value, slot, salt);
  return encoded;
}

function encodeOpOpcode(value: number, key: number, salt: number, state: MutationState): number {
  const slot = nextOp(state);
  const mask = contextMask(state.prevOp, state.opHash, slot, salt);
  const encoded = encodeOpcode((value ^ mask) & OP_MASK, slot, key, salt);
  state.prevOp = value;
  state.opHash = nextHash(state.opHash, value, slot, salt);
  return encoded;
}

function buildSpecPayload(kind: SpecKind, name: string, index: number): IRValue {
  if (kind === "binary") {
    return [index, buildBinaryProgram(name)];
  }
  if (kind === "unary") {
    return [index, buildUnaryProgram(name)];
  }
  return [index];
}

function buildBinaryProgram(name: string): number[] {
  switch (name) {
    case "+":
      return [1, 10];
    case "-":
      return [1, 11];
    case "*":
      return [1, 12];
    case "/":
      return [1, 13];
    case "%":
      return [1, 14];
    case "^":
      return [1, 15];
    case "..":
      return [1, 16];
    case "==":
      return [1, 20];
    case "~=":
      return [1, 21];
    case "<":
      return [1, 22];
    case "<=":
      return [1, 23];
    case ">":
      return [1, 24];
    case ">=":
      return [1, 25];
    case "&":
      return [1, 30];
    case "|":
      return [1, 31];
    case "~":
      return [1, 32];
    case "<<":
      return [1, 33];
    case ">>":
      return [1, 34];
    default:
      return [1];
  }
}

function buildUnaryProgram(name: string): number[] {
  switch (name) {
    case "-":
      return [1, 40];
    case "not":
      return [1, 41];
    case "#":
      return [1, 42];
    case "~":
      return [1, 43];
    default:
      return [1];
  }
}

function deriveKey(seed: number, index: number): number {
  const value = (seed + (index * 977) + (index * 131)) & OP_MASK;
  return value === 0 ? 1 : value;
}

function rotl16(value: number, shift: number): number {
  const amount = shift & 15;
  if (amount === 0) {
    return value & OP_MASK;
  }
  return (((value << amount) | (value >>> (16 - amount))) & OP_MASK) >>> 0;
}

function opcodeMix(slot: number, key: number, salt: number): { mix: number; shift: number; add: number; mask: number } {
  const seed = (key + (slot * 149) + (salt * 53)) & OP_MASK;
  const mix = (seed ^ (((slot * 17) + (salt * 29)) & OP_MASK)) & OP_MASK;
  const spread = ((key >>> (slot & 7)) ^ (((slot * 97) + (salt * 11)) & OP_MASK)) & OP_MASK;
  const shift = ((slot + salt + (key % 7)) % 15) + 1;
  const add = (spread + salt + (slot * 3)) & OP_MASK;
  const mask = (mix + spread + shift) & OP_MASK;
  return { mix, shift, add, mask };
}

function encodeOpcode(value: number, slot: number, key: number, salt: number): number {
  const { mix, shift, add, mask } = opcodeMix(slot, key, salt);
  let out = (value ^ mix) & OP_MASK;
  out = rotl16(out, shift);
  out = (out + add) & OP_MASK;
  out = (out ^ mask) & OP_MASK;
  return out >>> 0;
}

function encryptString(value: string, seed: number, index: number): IRValue {
  const bytes = Buffer.from(value, "utf8");
  const output = Buffer.allocUnsafe(bytes.length);
  const initialState = deriveStringCipherState(seed, index, bytes.length);
  let state = initialState;
  const key = deriveStringCipherKey(seed, index, bytes.length, state);
  let previous = key;

  for (let position = 0; position < bytes.length; position += 1) {
    const step = position + 1;
    const noise = deriveStringCipherNoise(state, previous, key, index, step);
    const encoded = (bytes[position] + state + noise) & 0xff;
    output[position] = encoded;
    previous = encoded;
    state = deriveNextStringCipherState(encoded, state, noise, key, index, step);
  }

  return [initialState, key, output.toString("hex")];
}

function deriveStringCipherState(seed: number, index: number, length: number): number {
  let state = (((seed ^ (index * 0x45d9f3b)) + (length * 0x9e37)) >>> 0) & 0xff;
  if (state === 0) {
    state = (((index * 73) + (length * 19) + 41) & 0xff) || 1;
  }
  return state;
}

function deriveStringCipherKey(seed: number, index: number, length: number, state: number): number {
  let key = ((((seed >>> 8) ^ (index * 193) ^ (length * 17) ^ (state * 29)) >>> 0) & 0xff);
  if (key === 0) {
    key = (((state * 3) + (index * 11) + 29) & 0xff) || 1;
  }
  return key;
}

function deriveStringCipherNoise(state: number, previous: number, key: number, index: number, step: number): number {
  const mix = ((state * 7) + (previous * 13) + (key * 11) + (index * 17) + (step * 19) + 3) & 0xff;
  return ((mix * 5) + 29) & 0xff;
}

function deriveNextStringCipherState(encoded: number, state: number, noise: number, key: number, index: number, step: number): number {
  return (encoded + ((noise * 3) + (state * 5) + key + index + step)) & 0xff;
}

function splitEncoded(encoded: string, chunkCount: number): string[] {
  const count = Math.max(1, Math.min(chunkCount, encoded.length));
  const chunks: string[] = [];
  const size = Math.ceil(encoded.length / count);

  for (let index = 0; index < encoded.length; index += size) {
    chunks.push(encoded.slice(index, index + size));
  }

  return chunks;
}

function quoteLuaBinaryString(value: string): string {
  let out = "\"";
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index) & 0xff;
    if (code === 34) {
      out += "\\\"";
    } else if (code === 92) {
      out += "\\\\";
    } else if (code >= 32 && code <= 126) {
      out += String.fromCharCode(code);
    } else {
      out += `\\${code.toString().padStart(3, "0")}`;
    }
  }
  out += "\"";
  return out;
}

function splitLuaStringLiteral(value: string, seed: number): string {
  if (!value.length) {
    return "\"\"";
  }

  const rng = new XorShift32((seed ^ 0x51f15eed) >>> 0);
  const chunks: string[] = [];
  let index = 0;
  while (index < value.length) {
    const width = Math.min(value.length - index, rng.nextRange(2, 6));
    chunks.push(value.slice(index, index + width));
    index += width;
  }

  if (chunks.length === 1) {
    return quoteLuaBinaryString(chunks[0]);
  }

  return chunks.map((chunk) => quoteLuaBinaryString(chunk)).join("..");
}

function wrapLuaStatementsInVarargIife(statements: string, iterations: number): string {
  let wrapped = statements.trim();
  for (let index = 0; index < iterations; index += 1) {
    wrapped = `(function(...) ${wrapped} end)(...)`;
  }
  return wrapped;
}

function buildBootstrapStringPool(strings: string[], seed: number, prefix: string): {
  bootstrap: string;
  access(index: number): string;
} {
  const rng = new XorShift32(seed ^ 0x6c8e9cf5);
  const tableName = `${prefix}0`;
  const cacheName = `${prefix}1`;
  const xorName = `${prefix}2`;
  const decodeName = `${prefix}3`;
  const pool = strings.map((value, index) => {
    const key = rng.nextRange(1, 255);
    const bytes = Buffer.from(value, "utf8");
    const encoded = Buffer.allocUnsafe(bytes.length);
    for (let position = 0; position < bytes.length; position += 1) {
      encoded[position] = bytes[position] ^ ((key + position + 1) & 0xff);
    }
    return {
      key,
      literal: splitLuaStringLiteral(encoded.toString("latin1"), seed ^ (index * 313)),
    };
  });

  const bootstrap =
    `local ${tableName}={} local ${cacheName}={} local ${xorName}=function(a0,a1)local a2,a3,a4,a5=0,1,math.floor(a0 or 0),math.floor(a1 or 0) while a4>0 or a5>0 do local a6=a4%2 local a7=a5%2 if a6~=a7 then a2=a2+a3 end a4=math.floor(a4/2) a5=math.floor(a5/2) a3=a3*2 end return a2 end ` +
    `local function ${decodeName}(a0,a1) local a2=${cacheName}[a0] if a2 then return a2 end local a3={} for a4=1,#a0 do a3[a4]=string.char(${xorName}(string.byte(a0,a4),((a1+a4)%256))%256) end a2=table.concat(a3) ${cacheName}[a0]=a2 return a2 end ` +
    `${tableName}=setmetatable({}, {__index=function(_,a0) return ${decodeName}(a0[1],a0[2]) end, __metatable=false})`;

  return {
    bootstrap,
    access(index: number): string {
      const entry = pool[index];
      return `${tableName}[{${entry.literal},${entry.key}}]`;
    },
  };
}

function emitNumericExpr(value: number, seed: number): string {
  const rng = new XorShift32((seed ^ (value * 1103515245)) >>> 0);
  if (value === 0) {
    const pad = rng.nextRange(2, 19);
    if (rng.nextInt(2) === 0) {
      return `(${pad}-${pad})`;
    }
    return `((function()return ${pad} end)()-${pad})`;
  }

  const mode = rng.nextInt(5);
  const pad1 = rng.nextRange(3, 97);
  const pad2 = rng.nextRange(5, 131);

  if (mode === 0) {
    return `((${value + pad1})-${pad1})`;
  }
  if (mode === 1) {
    return `((${value + pad1 + pad2})-(${pad1 + pad2}))`;
  }
  if (mode === 2) {
    return `((function()return ${value + pad1} end)()-${pad1})`;
  }
  if (mode === 3) {
    const factor = rng.nextRange(2, 6);
    return `(((((${value * factor})+${pad1})-${pad1})/${factor}))`;
  }
  return `((function()local a0=${value + pad1} local a1=${pad1 + pad2} return (a0+${pad2})-a1 end)())`;
}

function runtimeTemplate(module: IRModule, profile: VmProfile, fragments: string[], secrets: RuntimeSecrets, payloadHash: number): string {
  const codes = buildCodes(profile);
  const salts = secrets.salts;
  const sourceStringPool = buildBootstrapStringPool(module.strings.values, module.strings.seed, "f8");
  const sourceNamePool = buildBootstrapStringPool(module.names.values, module.names.seed, "g8");
  const sourceStringCount = module.strings.values.length;
  let sourceStringStride = 1;
  let sourceStringOffset = 0;
  const sourceStringLayout = new Array<string>(sourceStringCount);
  if (sourceStringCount > 0) {
    sourceStringStride = (((module.strings.seed * 5) + 3) % sourceStringCount) + 1;
    while (sourceStringCount > 1 && gcd(sourceStringStride, sourceStringCount) !== 1) {
      sourceStringStride += 1;
      if (sourceStringStride > sourceStringCount) {
        sourceStringStride = 1;
      }
    }
    sourceStringOffset = (module.strings.seed + sourceStringCount) % sourceStringCount;
    for (let index = 0; index < sourceStringCount; index += 1) {
      const slot = ((index * sourceStringStride) + sourceStringOffset) % sourceStringCount;
      sourceStringLayout[slot] = sourceStringPool.access(index);
    }
  }
  const sourceStringInit = sourceStringCount > 0 ? sourceStringLayout.join(",") : "";
  const sourceNameInit = module.names.values.length > 0
    ? module.names.values.map((_, index) => sourceNamePool.access(index)).join(",")
    : "";
  const sourceStringStrideExpr = emitNumericExpr(sourceStringStride, profile.nameSeed ^ 0x4511);
  const sourceStringOffsetExpr = emitNumericExpr(sourceStringOffset, profile.nameSeed ^ 0x4512);
  const alphabetLiteral = splitLuaStringLiteral(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    profile.nameSeed ^ 0x4541,
  );
  const failLiteral = splitLuaStringLiteral("iv", profile.nameSeed ^ 0x4542);
  const fragmentLayout = layoutFragments(fragments, profile.nameSeed ^ 0x55aa10f1);
  const fragmentAssignments = fragmentLayout.assignments.join(" ");
  const fragmentOrder = fragmentLayout.order
    .map((slot, index) => emitNumericExpr(slot, profile.nameSeed ^ 0x7000 ^ (index * 193)))
    .join(",");
  const stageCodes = createStageCodes(profile.nameSeed ^ 0x5055, 4);
  const stageList = stageCodes
    .map((code, index) => emitNumericExpr(code, profile.nameSeed ^ 0x7100 ^ (index * 389)))
    .join(",");
  const stageStateInit = emitNumericExpr(1, profile.nameSeed ^ 0x7201);
  const stageStateLeft = emitNumericExpr(2, profile.nameSeed ^ 0x7202);
  const stageStateRight = emitNumericExpr(3, profile.nameSeed ^ 0x7203);
  const stageStateNext = emitNumericExpr(4, profile.nameSeed ^ 0x7204);
  const bankBinaryKind = emitNumericExpr(1, profile.nameSeed ^ 0x7301);
  const bankUnaryKind = emitNumericExpr(2, profile.nameSeed ^ 0x7302);
  const bankExprKind = emitNumericExpr(3, profile.nameSeed ^ 0x7303);
  const bankStmtKind = emitNumericExpr(4, profile.nameSeed ^ 0x7304);
  const vmResolveSlot = emitNumericExpr(1, profile.nameSeed ^ 0x7401);
  const vmExecSlot = emitNumericExpr(2, profile.nameSeed ^ 0x7402);
  const vmBootSlot = emitNumericExpr(3, profile.nameSeed ^ 0x7403);
  const stringByteMod = emitNumericExpr(256, profile.nameSeed ^ 0x7501);
  const stringNoiseMulA = emitNumericExpr(7, profile.nameSeed ^ 0x7502);
  const stringNoiseMulB = emitNumericExpr(13, profile.nameSeed ^ 0x7503);
  const stringNoiseMulC = emitNumericExpr(11, profile.nameSeed ^ 0x7504);
  const stringNoiseMulD = emitNumericExpr(17, profile.nameSeed ^ 0x7505);
  const stringNoiseMulE = emitNumericExpr(19, profile.nameSeed ^ 0x7506);
  const stringNoiseAddA = emitNumericExpr(3, profile.nameSeed ^ 0x7507);
  const stringNoiseMulF = emitNumericExpr(5, profile.nameSeed ^ 0x7508);
  const stringNoiseAddB = emitNumericExpr(29, profile.nameSeed ^ 0x7509);
  const stringStateMul = emitNumericExpr(5, profile.nameSeed ^ 0x750a);
  const stringStateNoiseMul = emitNumericExpr(3, profile.nameSeed ^ 0x750b);
  const stringStepAdjust = emitNumericExpr(1, profile.nameSeed ^ 0x750c);
  const stringStepDivisor = emitNumericExpr(2, profile.nameSeed ^ 0x750d);
  const scopeLocalKey = `(${splitLuaStringLiteral("l", profile.nameSeed ^ 0x9161)}.."")`;
  const scopeParentKey = `(${splitLuaStringLiteral("p", profile.nameSeed ^ 0x9162)}.."")`;
  const scopeGlobalKey = `(${splitLuaStringLiteral("g", profile.nameSeed ^ 0x9163)}.."")`;
  const scopeVarargKey = `(${splitLuaStringLiteral("v", profile.nameSeed ^ 0x9164)}.."")`;
  const countKey = `(${splitLuaStringLiteral("n", profile.nameSeed ^ 0x9165)}.."")`;
  const testXKey = `(${splitLuaStringLiteral("x", profile.nameSeed ^ 0x9166)}.."")`;
  const testYKey = `(${splitLuaStringLiteral("y", profile.nameSeed ^ 0x9167)}.."")`;
  const stageBank = emitSlottedBank(
    [
      [stageCodes[0], `function()local a0={} ${fragmentAssignments} return a0 end`],
      [stageCodes[1], `function(a0)local a1={}local a2={${fragmentOrder}}for a3=1,#a2 do a1[#a1+1]=a0[a2[a3]]end return a(a1)end`],
      [stageCodes[2], `function(a0)local a1=ha(F(a0),${secrets.payloadKey >>> 0})local a2=H(a1)if ja(a2,${secrets.payloadHashSeed >>> 0})~=${payloadHash >>> 0} then error(${failLiteral})end return I(a2)end`],
      [stageCodes[3], `function(a0)ga=a0[3]z2=a0[4][1]z3=0 local a1=a0[4][2]for a2=1,#a0[4][3]do local a3=a0[4][3][a2]n[a2]={A(a3[1],a2,a1,${salts.defBinary}),ba(a3[2])}end for a2=1,#a0[4][4]do local a3=a0[4][4][a2]o[a2]={A(a3[1],a2,a1,${salts.defUnary}),ca(a3[2])}end for a2=1,#a0[4][5]do local a3=a0[4][5][a2]p[a2]={A(a3[1],a2,a1,${salts.defExpr}),da(a3[2])}end for a2=1,#a0[4][6]do local a3=a0[4][6][a2]q[a2]={A(a3[1],a2,a1,${salts.defStmt}),ea(a3[2])}end return a0 end`],
    ],
    profile.nameSeed ^ 0x6066,
    "fa",
    "fb",
  );
  const liftedFunctions = [
    "a", "b", "c", "e", "f", "g", "h", "i", "j", "x", "e1", "e2", "e4", "U", "X", "T", "Y", "N", "O", "P", "F", "G", "H", "I",
    "ha", "ja", "J", "K", "L", "M", "Z", "aa", "r", "s", "t", "u", "v", "w", "A", "A0",
    "B", "C", "D", "E", "R0", "S0", "ba", "ca", "da", "ea", "V", "W", "R", "c0", "c1", "c2", "d0", "d1", "d2", "d3", "d4", "d5", "d7",
  ];
  const liftedState = [
    "k", "l", "m", "n", "o", "p", "q", "y", "z", "z0", "z1", "z2", "z3", "d6", "e0", "e3", "e5", "ga", "Q",
  ];
  const liftedSet = new Set<string>([...liftedFunctions, ...liftedState]);
  const runtimeLocals = [
    "a", "b", "c", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "z0", "z1", "z2", "z3", "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "c0", "c1", "c2",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "e0", "e1", "e2", "e3", "e4", "e5", "ga",
  ].filter((name) => !liftedSet.has(name));
  runtimeLocals.push("f0", "g0");
  const runtimeLocalLine = `local ${runtimeLocals.join(",")}`;
  const runtimeInitLine = `f0={} g0={} a=table.concat b=table.insert c=table.unpack or unpack e=string.byte f=string.char g=string.sub h=tonumber i=type j=rawget k=nil l={} m={} n={} o={} p={} q={} y={} z={} z2=1 z3=0 b0={} b1=nil b2=nil e0={} e3=setmetatable({},{__mode=${splitLuaStringLiteral("k", profile.nameSeed ^ 0x9151)}}) e5={} ga=nil`;

  const raw = `
${runtimeLocalLine}
${runtimeInitLine}
x=function(a0,a1,a2)return{[${scopeLocalKey}]={},[${scopeParentKey}]=a0,[${scopeGlobalKey}]=a1,[${scopeVarargKey}]=a2 or{[${countKey}]=0}}end
e1=function(a0)local a1=e0[a0]if a1==nil then return a0 end return a1 end
e5={__len=function(a0)return e3[a0]or 0 end}
e4=function(a0,a1)e3[a0]=a1 return setmetatable(a0,e5)end
U=function(a0,a1,a2)local a3=e1(a1)a0[${scopeLocalKey}][a3]=a2==nil and l or a2 end
X=function(a0,a1)local a2=e1(a1)local a3=a0 while a3 do local a4=j(a3[${scopeLocalKey}],a2)if a4~=nil then if a4==l then return nil,true end return a4,true end a3=a3[${scopeParentKey}] end return nil,false end
T=function(a0,a1,a2)local a3=e1(a1)local a4=a0 while a4 do local a5=j(a4[${scopeLocalKey}],a3)if a5~=nil then a4[${scopeLocalKey}][a3]=a2==nil and l or a2 return end a4=a4[${scopeParentKey}] end a0[${scopeGlobalKey}][a3]=a2 end
Y=function(a0,a1)local a2=e1(a1)local a3,a4=X(a0,a1)if a4 then return a3 end return a0[${scopeGlobalKey}][a2]end
e2=function(a0,a1)local a2={}local a3=0 for a4=1,#a0 do local a5=a0[a4]local a6=a5[1]if a6==1 then a3=a3+1 local a7=Y(a1,a5[2])if a7==nil then a7=l end a2[a3]=a7 elseif a6==2 then a3=a3+1 a2[a3]=V(a5[2])elseif a6==3 then a3=a3+1 a2[a3]=a5[2]elseif a6==4 then a3=a3+1 a2[a3]=a5[2]==1 elseif a6==5 then a3=a3+1 a2[a3]=l elseif a6==6 then local a7=a2[a3]if a7==l then a7=nil end local b0=a7[e1(a5[2])]if b0==nil then b0=l end a2[a3]=b0 elseif a6==7 then local a7=a2[a3]if a7==l then a7=nil end local b0=a2[a3-1]if b0==l then b0=nil end local b1=b0[a7]if b1==nil then b1=l end a2[a3-1]=b1 a2[a3]=nil a3=a3-1 elseif a6==8 then local a7=a2[a3]if a7==l then a7=nil end local b0 if a5[2]==1 then b0=-a7 elseif a5[2]==2 then b0=not a7 elseif a5[2]==3 then b0=#a7 elseif a5[2]==4 then b0=R0(a7)else error(${failLiteral})end if b0==nil then b0=l end a2[a3]=b0 elseif a6==9 then local a7=a2[a3]if a7==l then a7=nil end local b0=a2[a3-1]if b0==l then b0=nil end local b1 if a5[2]==1 then b1=b0+a7 elseif a5[2]==2 then b1=b0-a7 elseif a5[2]==3 then b1=b0*a7 elseif a5[2]==4 then b1=b0/a7 elseif a5[2]==5 then b1=b0%a7 elseif a5[2]==6 then b1=b0^a7 elseif a5[2]==7 then b1=tostring(b0)..tostring(a7)elseif a5[2]==8 then b1=(b0==a7)elseif a5[2]==9 then b1=(b0~=a7)elseif a5[2]==10 then b1=(b0<a7)elseif a5[2]==11 then b1=(b0<=a7)elseif a5[2]==12 then b1=(b0>a7)elseif a5[2]==13 then b1=(b0>=a7)elseif a5[2]==14 then b1=J(b0,a7)elseif a5[2]==15 then b1=K(b0,a7)elseif a5[2]==16 then b1=L(b0,a7)elseif a5[2]==17 then b1=M(b0,a7)elseif a5[2]==18 then b1=Z(b0,a7)else error(${failLiteral})end if b1==nil then b1=l end a2[a3-1]=b1 a2[a3]=nil a3=a3-1 end end local a4=a2[a3]if a4==l then return nil end return a4 end
N=function(...)return{[${countKey}]=select("#",...),...}end
O=function(a0,a1,a2,a3)local a4={[${countKey}]=0}for a5=1,#a0 do local a6=a0[a5]if a5==#a0 then local a7=a2(a6,a1)for a8=1,a7[${countKey}] do a4[${countKey}]=a4[${countKey}]+1 a4[a4[${countKey}]]=a7[a8]end else a4[${countKey}]=a4[${countKey}]+1 a4[a4[${countKey}]]=a3(a6,a1)end end return a4 end
P=function(a0)local a1={[${countKey}]=a0[${countKey}]}for a2=1,a0[${countKey}] do a1[a2]=a0[a2]end return a1 end
b2=function()if i(a)~="function"or i(e)~="function"or i(g)~="function"or i(f)~="function"or i(j)~="function"then error(${failLiteral})end if g(${splitLuaStringLiteral("abc", profile.nameSeed ^ 0x1111)},2,3)~=${splitLuaStringLiteral("bc", profile.nameSeed ^ 0x2222)} then error(${failLiteral})end if e(${splitLuaStringLiteral("AZ", profile.nameSeed ^ 0x3333)},2)~=90 then error(${failLiteral})end if a({f(65),f(66)})~=${splitLuaStringLiteral("AB", profile.nameSeed ^ 0x4444)} then error(${failLiteral})end end
b3=function()local a0=_G or {} local a1=getfenv and (getfenv(0)or getfenv(1)) or a0 if not a1 then error(${failLiteral})end local a2={${splitLuaStringLiteral("getfenv", profile.nameSeed ^ 0x5001)},${splitLuaStringLiteral("setfenv", profile.nameSeed ^ 0x5002)},${splitLuaStringLiteral("debug", profile.nameSeed ^ 0x5003)},${splitLuaStringLiteral("newproxy", profile.nameSeed ^ 0x5004)}}for a3=1,#a2 do if a1[a2[a3]]~=nil then local a4=i(a1[a2[a3]])if a4~="function"and a4~="table"then error(${failLiteral})end end end local a5=rawget(a1,${splitLuaStringLiteral("string", profile.nameSeed ^ 0x5005)})if a5 and i(a5)=="table"then local a6=rawget(a5,${splitLuaStringLiteral("dump", profile.nameSeed ^ 0x5006)})if a6 and i(a6)=="function"then local a7,a8=pcall(a6,function()end)if a7 and i(a8)=="string"and #a8>0 then else error(${failLiteral})end end end local a9=rawget(a1,${splitLuaStringLiteral("math", profile.nameSeed ^ 0x5007)})if a9 and i(a9)=="table"then if rawget(a9,${splitLuaStringLiteral("random", profile.nameSeed ^ 0x5008)})and i(rawget(a9,${splitLuaStringLiteral("random", profile.nameSeed ^ 0x5009)}))~="function"then error(${failLiteral})end end local b0=rawget(a1,${splitLuaStringLiteral("table", profile.nameSeed ^ 0x500a)})if b0 and i(b0)=="table"then if rawget(b0,${splitLuaStringLiteral("concat", profile.nameSeed ^ 0x500b)})~=a then error(${failLiteral})end end local b1=rawget(a1,${splitLuaStringLiteral("_G", profile.nameSeed ^ 0x500c)})if b1 then if i(b1)~="table"then error(${failLiteral})end if rawget(b1,${splitLuaStringLiteral("_VERSION", profile.nameSeed ^ 0x500d)})then local b2=rawget(b1,${splitLuaStringLiteral("_VERSION", profile.nameSeed ^ 0x500e)})if i(b2)~="string"or #b2<3 then error(${failLiteral})end end end end
b4=function()local a0=pcall local a1,a2=a0(function()return(function()end)()end)if not a1 then error(${failLiteral})end local a3,a4=a0(function()local a5=0 for a6=1,1000000 do a5=a5+1 end return a5 end)if not a3 or a4~=1000000 then error(${failLiteral})end local a7,a8=a0(function()return 1+1 end)if not a7 or a8~=2 then error(${failLiteral})end local a9,b0=a0(function()return f(65)end)if not a9 or b0~=${splitLuaStringLiteral("A", profile.nameSeed ^ 0x6001)} then error(${failLiteral})end end
b5=function()if i(i)~="function"or i(pairs)~="function"or i(next)~="function"or i(tostring)~="function"or i(h)~="function"then error(${failLiteral})end local a0=math if a0 then if i(a0.floor)~="function"or i(a0.abs)~="function"then error(${failLiteral})end local a1=a0.floor(3.7)if a1~=3 then error(${failLiteral})end end local a2=string if a2 then if a2.sub~=g or a2.byte~=e then error(${failLiteral})end end end
b6=function()local a0={}local a1=setmetatable({},{__index=function()return 1 end})local a2=a1.test if a2~=1 then error(${failLiteral})end local a3=setmetatable({},{__newindex=function(a4,a5,a6)a0[a5]=a6*2 end})a3.val=5 if a0.val~=10 then error(${failLiteral})end local a7=setmetatable({},{__call=function()return 42 end})local a8=a7()if a8~=42 then error(${failLiteral})end end
b7=function()local a0=coroutine if not a0 or i(a0)~="table"then return end if not a0.create or i(a0.create)~="function"then error(${failLiteral})end if not a0.resume or i(a0.resume)~="function"then error(${failLiteral})end local a1=a0.create(function()return 123 end)local a2,a3=a0.resume(a1)if not a2 or a3~=123 then error(${failLiteral})end end
b8=function()local a0={1,2,3}local a1=0 for a2,a3 in pairs(a0)do a1=a1+a3 end if a1~=6 then error(${failLiteral})end local a4={[${testXKey}]=10,[${testYKey}]=20}local a5=0 for a6,a7 in pairs(a4)do a5=a5+a7 end if a5~=30 then error(${failLiteral})end end
b9=function()local a0={}for a1=1,100 do a0[a1]=a1*2 end local a2=0 for a3=1,100 do a2=a2+a0[a3]end if a2~=10100 then error(${failLiteral})end end
c0=function()local a0=function(a1)return a1*2 end local a2=a0(21)if a2~=42 then error(${failLiteral})end local a3=function(a4)return function(a5)return a4+a5 end end local a6=a3(10)local a7=a6(32)if a7~=42 then error(${failLiteral})end end
c1=function()if not pcall then error(${failLiteral})end local a0,a1=pcall(function()return 999 end)if not a0 or a1~=999 then error(${failLiteral})end local a2,a3=pcall(function()error(${splitLuaStringLiteral("test", profile.nameSeed ^ 0x8001)})end)if a2 then error(${failLiteral})end end
c2=function()local a0=rawget if not a0 or i(a0)~="function"then error(${failLiteral})end local a1={[${testXKey}]=5}local a2=a0(a1,${splitLuaStringLiteral("x", profile.nameSeed ^ 0x9001)})if a2~=5 then error(${failLiteral})end local a3=rawset if not a3 or i(a3)~="function"then error(${failLiteral})end a3(a1,${splitLuaStringLiteral("y", profile.nameSeed ^ 0x9002)},10)if a1[${testYKey}]~=10 then error(${failLiteral})end end
do local a0=${alphabetLiteral}for a1=1,#a0 do z[g(a0,a1,a1)]=a1-1 end end
F=function(a0)local a1,a2,a3={},0,0 for a4=1,#a0 do local a5=g(a0,a4,a4)if a5~="="then local a6=z[a5]if a6~=nil then a2=a2*64+a6 a3=a3+6 while a3>=8 do a3=a3-8 a1[#a1+1]=f(math.floor(a2/(2^a3))%256)a2=a2%(2^a3)end end end end return a(a1)end
G=function()local a0={}for a1=0,255 do a0[a1]=f(a1)end return a0,258 end
H=function(a0)local a1=a0 local a2={}for a3=1,#a1,2 do a2[#a2+1]=(e(a1,a3)or 0)*256+(e(a1,a3+1)or 0)end local a3,a4=G()local a5,a6,a7,a8=256,257,{},nil for a9=1,#a2 do local b0=a2[a9]if b0==a5 then a3,a4=G()a8=nil elseif b0==a6 then break else local b1=a3[b0]if not b1 and a8 then b1=a8..g(a8,1,1)end if not b1 then error(${failLiteral})end a7[#a7+1]=b1 if a8 then a3[a4]=a8..g(b1,1,1)a4=a4+1 end a8=b1 end end return a(a7)end
I=function(a0)local a1=1 local function a2(a3)local a4=a1 while g(a0,a1,a1)~=a3 do a1=a1+1 end local a5=g(a0,a4,a1-1)a1=a1+1 return a5 end local function a3()local a4=g(a0,a1,a1)a1=a1+1 if a4=="Z"then return nil end if a4=="T"then return true end if a4=="F"then return false end if a4=="N"then return h(a2(";"))end if a4=="S"then local a5=h(a2(":"))or 0 local a6=g(a0,a1,a1+a5-1)a1=a1+a5 local a7={}for a8=1,#a6,2 do a7[#a7+1]=f(h(g(a6,a8,a8+1),16)or 0)end return a(a7)end if a4=="A"then local a5=h(a2("["))or 0 local a6={}for a7=1,a5 do a6[a7]=a3()end a1=a1+1 return a6 end if a4=="O"then local a5=h(a2("{"))or 0 local a6={}for a7=1,a5 do local a8=a3()a6[a8]=a3()end a1=a1+1 return a6 end error(${failLiteral})end return a3()end
ha=function(a0,a1)local a2=L(a1,324508639)%4294967296 if a2==0 then a2=2654435769 end local a3={}for a4=1,#a0 do a2=L(a2,(M(a2,13)%4294967296))%4294967296 a2=L(a2,Z(a2,17))%4294967296 a2=L(a2,(M(a2,5)%4294967296))%4294967296 local a5=((a2%256)+((a1+a4*29)%256))%256 a3[a4]=f(L(e(a0,a4)or 0,a5)%256)end return a(a3)end
ja=function(a0,a1)local a2=L(a1,2779096485)%4294967296 for a3=1,#a0 do a2=(a2+(e(a0,a3)or 0)+((a3*97)%4294967296))%4294967296 a2=L(a2,(M(a2,13)%4294967296))%4294967296 a2=L(a2,Z(a2,7))%4294967296 a2=L(a2,(M(a2,17)%4294967296))%4294967296 end return a2 end
J=function(a0,a1)local a2,a3,a4,a5=0,1,math.floor(a0 or 0),math.floor(a1 or 0)while a4>0 or a5>0 do local a6=a4%2 local a7=a5%2 if a6==1 and a7==1 then a2=a2+a3 end a4=math.floor(a4/2)a5=math.floor(a5/2)a3=a3*2 end return a2 end
K=function(a0,a1)local a2,a3,a4,a5=0,1,math.floor(a0 or 0),math.floor(a1 or 0)while a4>0 or a5>0 do local a6=a4%2 local a7=a5%2 if a6==1 or a7==1 then a2=a2+a3 end a4=math.floor(a4/2)a5=math.floor(a5/2)a3=a3*2 end return a2 end
L=function(a0,a1)local a2,a3,a4,a5=0,1,math.floor(a0 or 0),math.floor(a1 or 0)while a4>0 or a5>0 do local a6=a4%2 local a7=a5%2 if a6~=a7 then a2=a2+a3 end a4=math.floor(a4/2)a5=math.floor(a5/2)a3=a3*2 end return a2 end
M=function(a0,a1)return math.floor((a0 or 0)*(2^(a1 or 0))) end
Z=function(a0,a1)return math.floor((a0 or 0)/(2^(a1 or 0))) end
aa=function(a0,a1)while a1~=0 do local a2=a0%a1 a0=a1 a1=a2 end return a0 end
Q=_G or{}do local a0={assert=assert,error=error,ipairs=ipairs,pairs=pairs,next=next,tonumber=tonumber,tostring=tostring,type=type,print=print,warn=warn,select=select,table=table,string=string,math=math,coroutine=coroutine,pcall=pcall,xpcall=xpcall,setmetatable=setmetatable,getmetatable=getmetatable,rawget=rawget,rawset=rawset}for a1,a2 in pairs(a0)do if Q[a1]==nil and a2~=nil then Q[a1]=a2 end end end
b2()b3()b4()b5()b6()b7()b8()b9()c0()c1()c2()
local function e8(a0,a1,a2)local a3=a0[1]or ${emitNumericExpr(1, profile.nameSeed ^ 0x7510)} local a4=a0[2]or ${emitNumericExpr(1, profile.nameSeed ^ 0x7511)} local a5=a0[3]or "" local a6={} local a7=a4 for a8=1,#a5,2 do local a9=((a8+${stringStepAdjust})/${stringStepDivisor}) local b0=h(g(a5,a8,a8+1),16)or ${emitNumericExpr(0, profile.nameSeed ^ 0x7512)} local b1=(((a3*${stringNoiseMulA})+(a7*${stringNoiseMulB})+(a4*${stringNoiseMulC})+(a1*${stringNoiseMulD})+(a9*${stringNoiseMulE})+${stringNoiseAddA})%${stringByteMod}) local b2=((b1*${stringNoiseMulF})+${stringNoiseAddB})%${stringByteMod} a6[#a6+1]=f((b0-a3-b2)%${stringByteMod}) a7=b0 a3=(b0+((b2*${stringStateNoiseMul})+(a3*${stringStateMul})+a4+a1+a9))%${stringByteMod} end return a(a6) end
r=function(a0)local a1=i(a0)if a1~="table"then return a0 end local a2={}for a3,a4 in pairs(a0)do a2[a3]=r(a4)end return a2 end
s=function(a0,a1,a2)local a3=((a1*97)+(a2*41))%65536 local a4=((a1*53)+(a2*29))%16 local a5=(L(a0,a3)+a1+a2*13)%65536 return J(K(Z(a5,a4),M(a5,16-a4)),65535) end
t=function(a0,a1,a2)local a3=#a0*3+5 local a4={}for a5=1,#a0 do local a6=a0[a5]local a7=s(a6[1],a1,a2)local a8=((L(a7,a1)+a2)%a3)+1 while a4[a8] do a8=a8%a3+1 end a4[a8]={a7,a6[2]} end return{a4,a3,a1,a2}end
u=function(a0,a1)local a2=((L(a1,a0[3])+a0[4])%a0[2])+1 while true do local a3=a0[1][a2]if not a3 then error(${failLiteral})end if a3[1]==a1 then return a3[2]end a2=a2%a0[2]+1 end end
v=function(a0,a1)local a2=(a0+a1*977+a1*131)%65536 if a2==0 then a2=1 end return a2 end
w=function(a0,a1,a2)local a3=(a1+a0*149+a2*53)%65536 local a4=L(a3,((a0*17)+(a2*29))%65536) local a5=L(Z(a1,a0%8),((a0*97)+(a2*11))%65536) local a6=((a0+a2+(a1%7))%15)+1 local a7=(a5+a2+a0*3)%65536 local a8=(a4+a5+a6)%65536 return a4,a6,a7,a8 end
A=function(a0,a1,a2,a3)local a4,a5,a6,a7=w(a1,a2,a3)local a8=L(a0,a7)a8=(a8-a6)%65536 if a8<0 then a8=a8+65536 end a8=J(K(Z(a8,a5),M(a8,16-a5)),65535) return L(a8,a4) end
A0=function(a0,a1,a2,a3,a4,a5)local a6=A(a0,a1,a2,a3)local a7=((a4*131)+(a5*17)+a3+a1)%65536 local a8=L(a6,a7)local a9=((a5*257)+a8+a3+a1)%65536 return a8,a9 end
B=function(a0,a1,a2,a3)a1[1]=a1[1]+1 local a4,a5=A0(a0[1],a1[1],a2,${salts.lvalue},a1[3],a1[5]) a1[3]=a4 a1[5]=a5 a0[1]=s(a4,a3,${salts.lvalue}) if a4~=${codes.lvalue.id} then D(a0[2],a1,a2,a3)if a0[4]==1 then D(a0[3],a1,a2,a3)end end end
C=function(a0,a1,a2,a3)a1[1]=a1[1]+1 local a4,a5=A0(a0[1],a1[1],a2,${salts.field},a1[3],a1[5]) a1[3]=a4 a1[5]=a5 a0[1]=s(a4,a3,${salts.field}) if a4==${codes.field.array} then D(a0[2],a1,a2,a3)elseif a4==${codes.field.record} then D(a0[3],a1,a2,a3)else D(a0[2],a1,a2,a3)D(a0[3],a1,a2,a3)end end
D=function(a0,a1,a2,a3)a1[1]=a1[1]+1 local a4,a5=A0(a0[1],a1[1],a2,${salts.expr},a1[3],a1[5]) a1[3]=a4 a1[5]=a5 a0[1]=s(a4,a3,${salts.expr}) if a4==${codes.expr.binary} then a1[2]=a1[2]+1 local a6,a7=A0(a0[2],a1[2],a2,${salts.binary},a1[4],a1[6]) a1[4]=a6 a1[6]=a7 a0[2]=s(a6,a3,${salts.binary}) D(a0[3],a1,a2,a3)D(a0[4],a1,a2,a3)elseif a4==${codes.expr.unary} then a1[2]=a1[2]+1 local a6,a7=A0(a0[2],a1[2],a2,${salts.unary},a1[4],a1[6]) a1[4]=a6 a1[6]=a7 a0[2]=s(a6,a3,${salts.unary}) D(a0[3],a1,a2,a3)elseif a4==${codes.expr.member} then D(a0[2],a1,a2,a3)if a0[4]==1 then D(a0[3],a1,a2,a3)end elseif a4==${codes.expr.call} then D(a0[2],a1,a2,a3)for a5=1,#a0[3]do D(a0[3][a5],a1,a2,a3)end elseif a4==${codes.expr.table} then for a5=1,#a0[2]do C(a0[2][a5],a1,a2,a3)end end end
E=function(a0,a1,a2,a3)a1[1]=a1[1]+1 local a4,a5=A0(a0[1],a1[1],a2,${salts.stmt},a1[3],a1[5]) a1[3]=a4 a1[5]=a5 a0[1]=s(a4,a3,${salts.stmt}) if a4==${codes.stmt.local} then for a5=1,#a0[3]do D(a0[3][a5],a1,a2,a3)end elseif a4==${codes.stmt.assign} then for a5=1,#a0[2]do B(a0[2][a5],a1,a2,a3)end for a5=1,#a0[3]do D(a0[3][a5],a1,a2,a3)end elseif a4==${codes.stmt.expr} then D(a0[2],a1,a2,a3)elseif a4==${codes.stmt.return} then for a5=1,#a0[2]do D(a0[2][a5],a1,a2,a3)end elseif a4==${codes.stmt.if} then for a5=1,#a0[2]do D(a0[2][a5][1],a1,a2,a3)for a6=1,#a0[2][a5][2]do E(a0[2][a5][2][a6],a1,a2,a3)end end if a0[3]then for a5=1,#a0[3]do E(a0[3][a5],a1,a2,a3)end end elseif a4==${codes.stmt.while} then D(a0[2],a1,a2,a3)for a5=1,#a0[3]do E(a0[3][a5],a1,a2,a3)end elseif a4==${codes.stmt.repeat} then for a5=1,#a0[2]do E(a0[2][a5],a1,a2,a3)end D(a0[3],a1,a2,a3)elseif a4==${codes.stmt.fornum} then D(a0[3],a1,a2,a3)D(a0[4],a1,a2,a3)if a0[5]then D(a0[5],a1,a2,a3)end for a5=1,#a0[6]do E(a0[6][a5],a1,a2,a3)end elseif a4==${codes.stmt.forin} then for a5=1,#a0[3]do D(a0[3][a5],a1,a2,a3)end for a5=1,#a0[4]do E(a0[4][a5],a1,a2,a3)end elseif a4==${codes.stmt.do} then for a5=1,#a0[2]do E(a0[2][a5],a1,a2,a3)end elseif a4==${codes.stmt.func} then B(a0[3],a1,a2,a3)end end
R0=function(a0)return 4294967295-(a0 or 0)end
S0=function(a0,a1,a2,a3)if a0[3]==nil and i(a0[2])=="number" then T(a1,a0[2],a2)return end local a4=a3(a0[2],a1)local a5=a0[4]==1 and a3(a0[3],a1)or e1(a0[3])a4[a5]=a2 end
b1=function(a0,a1,a2)return u(a2[a0],a1)end
ba=function(a0)local a1=a0[2] return function(a2,a3)local a4=a2 for a5=1,#a1 do local a6=a1[a5]if a6==10 then a4=a4+a3 elseif a6==11 then a4=a4-a3 elseif a6==12 then a4=a4*a3 elseif a6==13 then a4=a4/a3 elseif a6==14 then a4=a4%a3 elseif a6==15 then a4=a4^a3 elseif a6==16 then a4=tostring(a4)..tostring(a3) elseif a6==20 then a4=(a4==a3) elseif a6==21 then a4=(a4~=a3) elseif a6==22 then a4=(a4<a3) elseif a6==23 then a4=(a4<=a3) elseif a6==24 then a4=(a4>a3) elseif a6==25 then a4=(a4>=a3) elseif a6==30 then a4=J(a4,a3) elseif a6==31 then a4=K(a4,a3) elseif a6==32 then a4=L(a4,a3) elseif a6==33 then a4=M(a4,a3) elseif a6==34 then a4=Z(a4,a3) end end return a4 end end
ca=function(a0)local a1=a0[2] return function(a2)local a3=a2 for a4=1,#a1 do local a5=a1[a4]if a5==40 then a3=-a3 elseif a5==41 then a3=not a3 elseif a5==42 then a3=#a3 elseif a5==43 then a3=R0(a3) end end return a3 end end
da=function(a0)local a0=a0[1] if a0==1 then return function(a1,a2)return Y(a2,a1[2])end elseif a0==2 then return function(a1)return V(a1[2])end elseif a0==3 then return function(a1)return a1[2]end elseif a0==4 then return function(a1)return a1[2]==1 end elseif a0==5 then return function()return nil end elseif a0==6 then return function(a1,a2)return a2[${scopeVarargKey}][1]end elseif a0==7 then return function(a1,a2,a3,a4,a5,a6,a7)local a8=a1[2]if a8==a5[1] then local a9=a3(a1[3],a2)if not a9 then return a9 end return a3(a1[4],a2)end if a8==a5[2] then local a9=a3(a1[3],a2)if a9 then return a9 end return a3(a1[4],a2)end return a6(${bankBinaryKind},a8,a7)(a3(a1[3],a2),a3(a1[4],a2))end elseif a0==8 then return function(a1,a2,a3,a4,a5,a6,a7)return a6(${bankUnaryKind},a1[2],a7)(a3(a1[3],a2))end elseif a0==9 then return function(a1,a2,a3)local a4=a3(a1[2],a2)local a5=a1[4]==1 and a3(a1[3],a2)or e1(a1[3])return a4[a5]end elseif a0==10 then return function(a1,a2,a3,a4,a5)local a6=a1[2]local a7=O(a1[3],a2,a4,a3)local a8={}for a9=1,a7[${countKey}] do a8[a9]=a7[a9]end local b0 local b3=a7[${countKey}] if a1[4]==1 and i(a6)=="table"and a6[1]==a5[3] then local b1=a3(a6[2],a2)local b2=a6[4]==1 and a3(a6[3],a2)or e1(a6[3])b0=b1[b2]b(a8,1,b1)b3=b3+1 else b0=a3(a6,a2)end return b0(c(a8,1,b3))end elseif a0==11 then return function(a1,a2,a3,a4,a5)local a6={}local a7=1 local a8=false local a9=0 for b0,b1 in ipairs(a1[2])do if b1[1]==a5[6] then if b0==#a1[2] then local b2=a4(b1[2],a2)if b1[2][1]==a5[4]or b1[2][1]==a5[5]then a8=true end for b3=1,b2[${countKey}] do local b4=b2[b3]a6[a7]=b4 if b4~=nil then a9=a7 end a7=a7+1 end else local b2=a3(b1[2],a2)a6[a7]=b2 if b2~=nil then a9=a7 end a7=a7+1 end elseif b1[1]==a5[7] then a6[e1(b1[2])]=a3(b1[3],a2)else a6[a3(b1[2],a2)]=a3(b1[3],a2)end end if a8 then return e4(a6,a9)end return a6 end elseif a0==12 then return function(a1,a2)return W(a1[2],a2)end elseif a0==13 then return function(a1,a2)return e2(a1[2],a2)end end return function()error(${failLiteral})end end
ea=function(a0)local a0=a0[1] if a0==1 then return function(a1,a2,a3,a4)if a1[4]==1 then for a5=1,#a1[2]do U(a2,a1[2][a5],false)end end local a5=O(a1[3],a2,a4,a3)for a6=1,#a1[2]do U(a2,a1[2][a6],a5[a6])end end elseif a0==2 then return function(a1,a2,a3,a4)local a5=O(a1[3],a2,a4,a3)for a6=1,#a1[2]do S0(a1[2][a6],a2,a5[a6],a3)end end elseif a0==3 then return function(a1,a2,a3)a3(a1[2],a2)end elseif a0==4 then return function(a1,a2,a3,a4)return{0,O(a1[2],a2,a4,a3)}end elseif a0==5 then return function(a1,a2,a3,a4,a5,a6)for a7=1,#a1[2]do local a8=a1[2][a7]if a3(a8[1],a2)then local a9=a5(a8[2],x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}]),a3,a4,a5)if a9 then return a9 end return nil end end if a1[3]then local a7=a5(a1[3],x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}]),a3,a4,a5)if a7 then return a7 end end end elseif a0==6 then return function(a1,a2,a3,a4,a5,a6)while a3(a1[2],a2)do local a7=a5(a1[3],x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}]),a3,a4,a5)if a7==m then break end if a7~=l and a7~=nil then return a7 end end end elseif a0==7 then return function(a1,a2,a3,a4,a5,a6)repeat local a7=a5(a1[2],x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}]),a3,a4,a5)if a7==m then break end if a7~=l and a7~=nil then return a7 end until a3(a1[3],a2)end elseif a0==8 then return function(a1,a2,a3,a4,a5,a6)local a7=a3(a1[3],a2)local a8=a3(a1[4],a2)local a9=a1[5]and a3(a1[5],a2)or 1 for b0=a7,a8,a9 do local b1=x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}])U(b1,a1[2],b0)local b2=a5(a1[6],b1,a3,a4,a5)if b2==m then break end if b2~=l and b2~=nil then return b2 end end end elseif a0==9 then return function(a1,a2,a3,a4,a5,a6)local a7=O(a1[3],a2,a4,a3)local a8,a9,b0=a7[1],a7[2],a7[3]while true do local b1=N(a8(a9,b0))b0=b1[1]if b0==nil then break end local b2=x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}])for b3=1,#a1[2]do U(b2,a1[2][b3],b1[b3])end local b4=a5(a1[4],b2,a3,a4,a5)if b4==m then break end if b4~=l and b4~=nil then return b4 end end end elseif a0==10 then return function()return m end elseif a0==11 then return function()return l end elseif a0==12 then return function(a1,a2,a3,a4,a5,a6)local a7=a5(a1[2],x(a2,a2[${scopeGlobalKey}],a2[${scopeVarargKey}]),a3,a4,a5)if a7 then return a7 end end elseif a0==13 then return function(a1,a2,a3)if a1[2]==1 and a1[3][3]==nil and i(a1[3][2])=="number" then U(a2,a1[3][2],false)U(a2,a1[3][2],W(a1[4],a2))else S0(a1[3],a2,W(a1[4],a2),a3)end end end return function()error(${failLiteral})end end
V=function(a0)local a1=#y if a1==0 then return nil end return y[((a0-1)*z0+z1)%a1+1]end
W=function(a0,a1)return function(...)return R(a0,a1,...)end end
R=function(a0,a1,...)z3=(z3+1)%65535 if z3==0 then z3=1 end if z3%${emitNumericExpr(127, profile.nameSeed ^ 0xa006)}==0 then d7()end local a2=r(ga[a0])local a3=v(z2,a0)local a4=(a3+z3*193+a0*17)%65535 if a4==0 then a4=65535 end local a5={s(${codes.binary.and},a4,${salts.binary}),s(${codes.binary.or},a4,${salts.binary}),s(${codes.expr.member},a4,${salts.expr}),s(${codes.expr.call},a4,${salts.expr}),s(${codes.expr.vararg},a4,${salts.expr}),s(${codes.field.array},a4,${salts.field}),s(${codes.field.record},a4,${salts.field})}local a6={0,0,0,0,0,0}for a7=1,#a2[2]do E(a2[2][a7],a6,a3,a4)end local a7=t(n,a4,${salts.binary})local a8=t(o,a4,${salts.unary})local a9=t(p,a4,${salts.expr})local aA=t(q,a4,${salts.stmt})local aB={a7,a8,a9,aA}local aC=x(a1,Q,N(select(#a2[1]+1,...)))for aD=1,#a2[1]do U(aC,a2[1][aD],select(aD,...))end local aD local aE local aF aF=function(aG,aH)local aI=b1(${bankExprKind},aG[1],aB)return aI(aG,aH,aF,aE,a5,b1,aB)end aE=function(aG,aH)if aG[1]==a5[4] then return N(aF(aG,aH))end if aG[1]==a5[5] then return P(aH[${scopeVarargKey}])end return N(aF(aG,aH))end aD=function(aG,aH,aI,aJ,aK)local aL=1 local aM=1 local aN=nil local aO=nil while true do if aM==1 then aN=aG[aL]if not aN then return nil end aM=2+((aL+a0+z3)%2)elseif aM==2 then aO=b1(${bankStmtKind},aN[1],aB)aM=4 elseif aM==3 then a0=((a0*1664525)+1013904223+aL+z3)%2147483647 aM=2 else local aP=aO(aN,aH,aI,aJ,aK,a5)if aP~=nil then return aP end aL=aL+1 a0=((a0*1664525)+1013904223+aL+z3)%2147483647 aM=1 end end end local aG=aD(a2[2],aC,aF,aE,aD)if aG and aG[1]==0 then return c(aG[2],1,aG[2][${countKey}])end return nil end
${stageBank}
${sourceStringPool.bootstrap}
${sourceNamePool.bootstrap}
z0=${sourceStringStrideExpr}
z1=${sourceStringOffsetExpr}
y={${sourceStringInit}}
e0={${sourceNameInit}}
d0=function()if not b0 or i(b0)~="table"then error(${failLiteral})end if not b0[${vmResolveSlot}]or i(b0[${vmResolveSlot}])~="function"then error(${failLiteral})end if not b0[${vmExecSlot}]or i(b0[${vmExecSlot}])~="function"then error(${failLiteral})end if not b0[${vmBootSlot}]or i(b0[${vmBootSlot}])~="function"then error(${failLiteral})end end
d1=function()if not ga or i(ga)~="table"then error(${failLiteral})end if #ga<1 then error(${failLiteral})end local a0=0 for a1=1,math.min(#ga,10)do if ga[a1]and i(ga[a1])=="table"then a0=a0+1 end end if a0<1 then error(${failLiteral})end end
d2=function()if not y or i(y)~="table"then error(${failLiteral})end if z0<1 then error(${failLiteral})end if z2<1 then error(${failLiteral})end end
d3=function()if not n or i(n)~="table"or #n<1 then error(${failLiteral})end if not o or i(o)~="table"or #o<1 then error(${failLiteral})end if not p or i(p)~="table"or #p<1 then error(${failLiteral})end if not q or i(q)~="table"or #q<1 then error(${failLiteral})end end
d4=function()local a0=i(A)if a0~="function"then error(${failLiteral})end local a1=i(B)if a1~="function"then error(${failLiteral})end local a2=i(D)if a2~="function"then error(${failLiteral})end local a3=i(E)if a3~="function"then error(${failLiteral})end end
d5=function()if i(J)~="function"or i(K)~="function"or i(L)~="function"or i(M)~="function"or i(Z)~="function"then error(${failLiteral})end local a0=J(15,7)if a0~=7 then error(${failLiteral})end local a1=K(12,10)if a1~=14 then error(${failLiteral})end local a2=L(12,10)if a2~=6 then error(${failLiteral})end end
d6=0
d7=function()d6=d6+1 if d6%${emitNumericExpr(17, profile.nameSeed ^ 0xa001)}==0 then d1()end if d6%${emitNumericExpr(23, profile.nameSeed ^ 0xa002)}==0 then d2()end if d6%${emitNumericExpr(31, profile.nameSeed ^ 0xa003)}==0 then d3()end if d6%${emitNumericExpr(41, profile.nameSeed ^ 0xa004)}==0 then d4()end if d6%${emitNumericExpr(53, profile.nameSeed ^ 0xa005)}==0 then d5()end end
b0[${vmResolveSlot}]=b1
b0[${vmExecSlot}]=R
b0[${vmBootSlot}]=function(a0)local a1={${stageList}}local a2=${stageStateInit}local a3=${stageStateInit}while true do if a2==${stageStateInit} then if a3>#a1 then d0()d1()d2()d3()d4()d5()return a0 end a2=(((a3+z2)%2)==0)and ${stageStateLeft} or ${stageStateRight} elseif a2==${stageStateLeft} then a0=fb(a1[a3])(a0) a2=${stageStateNext} elseif a2==${stageStateRight} then a0=fb(a1[a3])(a0) a2=${stageStateNext} else a3=a3+1 a2=${stageStateInit} end end end
local a0=b0[${vmBootSlot}](nil)d7()return b0[${vmExecSlot}](a0[2],x(nil,Q,{[${countKey}]=0}))
`;
  return applyRuntimeRegisterIndirection(raw, liftedFunctions, liftedState);
}

function emitSlottedBank(
  entries: Array<[number, string]>,
  seed: number,
  tableName: string,
  resolverName: string,
): string {
  const rng = new XorShift32(seed);
  const fallback = "function()error(\"iv\")end";
  const items = [...entries];

  for (let index = items.length - 1; index > 0; index -= 1) {
    const swapIndex = rng.nextInt(index + 1);
    const temp = items[index];
    items[index] = items[swapIndex];
    items[swapIndex] = temp;
  }

  let modulus = (items.length * 3) + 7;
  if (modulus % 2 === 0) {
    modulus += 1;
  }

  let step = 1;
  let bias = 0;
  let slots = new Map<number, number>();

  while (true) {
    step = rng.nextRange(1, modulus - 1);
    while (gcd(step, modulus) !== 1) {
      step = (step % (modulus - 1)) + 1;
    }

    bias = rng.nextInt(modulus);
    slots = new Map<number, number>();
    let ok = true;

    for (const [code] of items) {
      const slot = ((code * step) + bias) % modulus;
      if (slots.has(slot)) {
        ok = false;
        break;
      }
      slots.set(slot, code);
    }

    if (ok) {
      break;
    }

    modulus += 2;
  }

  const used = new Set<number>(slots.keys());
  const lines = [`local ${tableName}={}`];
  const dummySlots: number[] = [];

  for (const [code, body] of items) {
    const slot = ((code * step) + bias) % modulus;
    lines.push(`${tableName}[${emitNumericExpr(slot + 1, seed ^ code ^ 0x11)}]=${body}`);
  }

  const dummyCount = Math.min(items.length, Math.max(2, Math.floor(modulus / 4)));
  while (dummySlots.length < dummyCount) {
    const slot = rng.nextInt(modulus);
    if (used.has(slot)) {
      continue;
    }
    used.add(slot);
    dummySlots.push(slot);
  }

  for (const slot of dummySlots) {
    lines.push(`${tableName}[${emitNumericExpr(slot + 1, seed ^ slot ^ 0x33)}]=function(...)return(...)end`);
  }

  lines.push(`local function ${resolverName}(a0)local a1=${tableName}[((a0*${emitNumericExpr(step, seed ^ 0x55)}+${emitNumericExpr(bias, seed ^ 0x77)})%${emitNumericExpr(modulus, seed ^ 0x99)})+1]if a1~=nil then return a1 end return ${fallback} end`);
  return lines.join(" ");
}

function layoutFragments(fragments: string[], seed: number): { assignments: string[]; order: number[] } {
  const rng = new XorShift32(seed);
  const width = fragments.length + rng.nextRange(3, 7);
  const slots = Array.from({ length: width }, (_, index) => index + 1);

  for (let index = slots.length - 1; index > 0; index -= 1) {
    const swapIndex = rng.nextInt(index + 1);
    const temp = slots[index];
    slots[index] = slots[swapIndex];
    slots[swapIndex] = temp;
  }

  const assignments: string[] = [];
  const order: number[] = [];

  for (let index = 0; index < fragments.length; index += 1) {
    const slot = slots[index];
    assignments.push(`a0[${emitNumericExpr(slot, seed ^ (index * 313) ^ 0x22)}]=${escapeLuaString(fragments[index])}`);
    order.push(slot);
  }

  for (let index = fragments.length; index < slots.length; index += 1) {
    assignments.push(`a0[${emitNumericExpr(slots[index], seed ^ (index * 571) ^ 0x44)}]=${escapeLuaString(randomNoise(rng, rng.nextRange(4, 12)))}`);
  }

  return { assignments, order };
}

function createStageCodes(seed: number, count = 4): number[] {
  const rng = new XorShift32(seed);
  const codes = new Set<number>();

  while (codes.size < count) {
    codes.add(rng.nextRange(41, 991));
  }

  return [...codes];
}

function applyRuntimeRegisterIndirection(source: string, functions: string[], state: string[]): string {
  const mapping = new Map<string, string>();
  for (let index = 0; index < functions.length; index += 1) {
    mapping.set(functions[index], `f0[${index + 1}]`);
  }
  for (let index = 0; index < state.length; index += 1) {
    mapping.set(state[index], `g0[${index + 1}]`);
  }
  return rewriteRuntimeRegisterIdentifiers(source, mapping);
}

function randomNoise(rng: XorShift32, size: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";

  for (let index = 0; index < size; index += 1) {
    out += alphabet[rng.nextInt(alphabet.length)];
  }

  return out;
}

function gcd(left: number, right: number): number {
  let a = Math.abs(left);
  let b = Math.abs(right);

  while (b !== 0) {
    const temp = a % b;
    a = b;
    b = temp;
  }

  return a || 1;
}

function randomizeIdentifiers(source: string, seed: number): string {
  const rng = new XorShift32(seed ^ 0x243f6a88);
  const tokens = collectRuntimeIdentifiers(source);
  const mapping = new Map<string, string>();
  const counts = countIdentifierOccurrences(source, tokens);
  const reserved = collectReservedIdentifiers(source, new Set(tokens));
  const used = new Set<string>(reserved);

  const nextName = (): string => {
    while (true) {
      const value = rng.nextIdentifier();
      if (used.has(value)) {
        continue;
      }
      used.add(value);
      return value;
    }
  };

  for (const token of [...tokens].sort((left, right) => {
    const delta = (counts.get(right) ?? 0) - (counts.get(left) ?? 0);
    if (delta !== 0) {
      return delta;
    }
    return left.localeCompare(right);
  })) {
    mapping.set(token, nextName());
  }

  return rewriteLuaIdentifiers(source, mapping);
}

function collectRuntimeIdentifiers(source: string): string[] {
  const literalStrings = collectStringLiterals(source);
  const identifiers = new Set<string>();
  let index = 0;
  let quote = "";
  let escape = false;

  const isIdent = (char: string): boolean => /[A-Za-z0-9_]/.test(char);
  const isIdentStart = (char: string): boolean => /[A-Za-z_]/.test(char);

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      index += 1;
      continue;
    }

    if (isIdentStart(char)) {
      let end = index + 1;
      while (end < source.length && isIdent(source[end])) {
        end += 1;
      }
      const token = source.slice(index, end);
      if (shouldRandomizeIdentifier(token, literalStrings)) {
        identifiers.add(token);
      }
      index = end;
      continue;
    }

    index += 1;
  }

  return [...identifiers];
}

function shouldRandomizeIdentifier(token: string, literalStrings: Set<string>): boolean {
  if (LUA_RESERVED.has(token)) {
    return false;
  }

  if (literalStrings.has(token)) {
    return false;
  }

  return /^[A-Za-z][A-Za-z0-9]?$/.test(token);
}

function collectStringLiterals(source: string): Set<string> {
  const literals = new Set<string>();
  let index = 0;
  let quote = "";
  let escape = false;
  let start = 0;

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        literals.add(source.slice(start + 1, index));
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      start = index;
    }

    index += 1;
  }

  return literals;
}

function collectReservedIdentifiers(source: string, renamed: Set<string>): Set<string> {
  const reserved = new Set<string>();
  let index = 0;
  let quote = "";
  let escape = false;

  const isIdent = (char: string): boolean => /[A-Za-z0-9_]/.test(char);
  const isIdentStart = (char: string): boolean => /[A-Za-z_]/.test(char);

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      index += 1;
      continue;
    }

    if (isIdentStart(char)) {
      let end = index + 1;
      while (end < source.length && isIdent(source[end])) {
        end += 1;
      }
      const token = source.slice(index, end);
      if (!renamed.has(token)) {
        reserved.add(token);
      }
      index = end;
      continue;
    }

    index += 1;
  }

  return reserved;
}

function rewriteLuaIdentifiers(source: string, mapping: Map<string, string>): string {
  let out = "";
  let index = 0;
  let quote = "";
  let escape = false;

  const isIdent = (char: string): boolean => /[A-Za-z0-9_]/.test(char);
  const isIdentStart = (char: string): boolean => /[A-Za-z_]/.test(char);

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      out += char;
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      out += char;
      index += 1;
      continue;
    }

    if (isIdentStart(char)) {
      let end = index + 1;
      while (end < source.length && isIdent(source[end])) {
        end += 1;
      }
      const token = source.slice(index, end);
      out += mapping.get(token) ?? token;
      index = end;
      continue;
    }

    out += char;
    index += 1;
  }

  return out;
}

function rewriteRuntimeRegisterIdentifiers(source: string, mapping: Map<string, string>): string {
  let out = "";
  let index = 0;
  let quote = "";
  let escape = false;

  const isIdent = (char: string): boolean => /[A-Za-z0-9_]/.test(char);
  const isIdentStart = (char: string): boolean => /[A-Za-z_]/.test(char);
  const prevNonSpace = (position: number): string => {
    let cursor = position - 1;
    while (cursor >= 0 && /\s/.test(source[cursor])) {
      cursor -= 1;
    }
    return cursor >= 0 ? source[cursor] : "";
  };
  const nextNonSpace = (position: number): string => {
    let cursor = position;
    while (cursor < source.length && /\s/.test(source[cursor])) {
      cursor += 1;
    }
    return cursor < source.length ? source[cursor] : "";
  };

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      out += char;
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      out += char;
      index += 1;
      continue;
    }

    if (isIdentStart(char)) {
      let end = index + 1;
      while (end < source.length && isIdent(source[end])) {
        end += 1;
      }
      const token = source.slice(index, end);
      const isBareTableKey = nextNonSpace(end) === "=" && /[,{]/.test(prevNonSpace(index));
      out += isBareTableKey ? token : (mapping.get(token) ?? token);
      index = end;
      continue;
    }

    out += char;
    index += 1;
  }

  return out;
}

function countIdentifierOccurrences(source: string, tokens: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  const tokenSet = new Set(tokens);
  let index = 0;
  let quote = "";
  let escape = false;

  const isIdent = (char: string): boolean => /[A-Za-z0-9_]/.test(char);
  const isIdentStart = (char: string): boolean => /[A-Za-z_]/.test(char);

  while (index < source.length) {
    const char = source[index];

    if (quote.length > 0) {
      if (escape) {
        escape = false;
      } else if (char === "\\") {
        escape = true;
      } else if (char === quote) {
        quote = "";
      }
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      quote = char;
      index += 1;
      continue;
    }

    if (isIdentStart(char)) {
      let end = index + 1;
      while (end < source.length && isIdent(source[end])) {
        end += 1;
      }
      const token = source.slice(index, end);
      if (tokenSet.has(token)) {
        counts.set(token, (counts.get(token) ?? 0) + 1);
      }
      index = end;
      continue;
    }

    index += 1;
  }

  return counts;
}
