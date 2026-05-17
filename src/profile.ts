import { XorShift32 } from "./util";

export interface VmProfile {
  binaryOps: Record<string, number>;
  unaryOps: Record<string, number>;
  exprTags: Record<string, number>;
  stmtTags: Record<string, number>;
  lvalueTags: Record<string, number>;
  fieldTags: Record<string, number>;
  binaryMask: number;
  unaryMask: number;
  exprMask: number;
  stmtMask: number;
  lvalueMask: number;
  fieldMask: number;
  chunkCount: number;
  nameSeed: number;
}

const BINARY_OPS = ["and", "or", "+", "-", "*", "/", "%", "^", "..", "==", "~=", "<", "<=", ">", ">=", "&", "|", "~", "<<", ">>"];
const UNARY_OPS = ["-", "not", "#", "~"];
const EXPR_TAGS = ["id", "str", "num", "bool", "nil", "vararg", "binary", "unary", "member", "call", "table", "function", "mini"];
const STMT_TAGS = ["local", "assign", "expr", "return", "if", "while", "repeat", "fornum", "forin", "break", "continue", "do", "func"];
const LVALUE_TAGS = ["id", "member"];
const FIELD_TAGS = ["array", "record", "general"];

export function createVmProfile(seed: number): VmProfile {
  const rng = new XorShift32(seed ^ 0x6a09e667);
  return {
    binaryOps: assignCodes(BINARY_OPS, rng, 11),
    unaryOps: assignCodes(UNARY_OPS, rng, 201),
    exprTags: assignCodes(EXPR_TAGS, rng, 401),
    stmtTags: assignCodes(STMT_TAGS, rng, 701),
    lvalueTags: assignCodes(LVALUE_TAGS, rng, 901),
    fieldTags: assignCodes(FIELD_TAGS, rng, 951),
    binaryMask: nonZeroMask(rng),
    unaryMask: nonZeroMask(rng),
    exprMask: nonZeroMask(rng),
    stmtMask: nonZeroMask(rng),
    lvalueMask: nonZeroMask(rng),
    fieldMask: nonZeroMask(rng),
    chunkCount: rng.nextRange(4, 9),
    nameSeed: rng.nextUint32(),
  };
}

function assignCodes(items: string[], rng: XorShift32, start: number): Record<string, number> {
  const codes: number[] = [];
  for (let index = 0; index < items.length; index += 1) {
    codes.push(start + index);
  }
  shuffle(codes, rng);
  const out: Record<string, number> = {};
  for (let index = 0; index < items.length; index += 1) {
    out[items[index]] = codes[index];
  }
  return out;
}

function shuffle<T>(values: T[], rng: XorShift32): void {
  for (let index = values.length - 1; index > 0; index -= 1) {
    const swapIndex = rng.nextInt(index + 1);
    const temp = values[index];
    values[index] = values[swapIndex];
    values[swapIndex] = temp;
  }
}

function nonZeroMask(rng: XorShift32): number {
  let value = 0;
  while (value === 0) {
    value = rng.nextUint32() & 0xffff;
  }
  return value;
}
