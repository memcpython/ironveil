import type { Expression } from "./shared";
import type { IRMiniProgram } from "./types";

const MINI_PUSH_NAME = 1;
const MINI_PUSH_STRING = 2;
const MINI_PUSH_NUMBER = 3;
const MINI_PUSH_BOOL = 4;
const MINI_PUSH_NIL = 5;
const MINI_MEMBER_NAME = 6;
const MINI_MEMBER_COMPUTED = 7;
const MINI_UNARY = 8;
const MINI_BINARY = 9;

const MINI_UNARY_OPS: Record<string, number> = {
  "-": 1,
  not: 2,
  "#": 3,
  "~": 4,
};

const MINI_BINARY_OPS: Record<string, number> = {
  "+": 1,
  "-": 2,
  "*": 3,
  "/": 4,
  "%": 5,
  "^": 6,
  "..": 7,
  "==": 8,
  "~=": 9,
  "<": 10,
  "<=": 11,
  ">": 12,
  ">=": 13,
  "&": 14,
  "|": 15,
  "~": 16,
  "<<": 17,
  ">>": 18,
};

export function vmifyCondition(
  expression: Expression,
  internString: (value: string) => number,
  internName: (value: string) => number,
): IRMiniProgram | null {
  const program: IRMiniProgram = [];
  if (!emitMiniExpression(program, expression, internString, internName)) {
    return null;
  }
  return program;
}

function emitMiniExpression(
  program: IRMiniProgram,
  expression: Expression,
  internString: (value: string) => number,
  internName: (value: string) => number,
): boolean {
  switch (expression.type) {
    case "Identifier":
      program.push([MINI_PUSH_NAME, internName(expression.name)]);
      return true;
    case "StringLiteral":
      program.push([MINI_PUSH_STRING, internString(expression.value)]);
      return true;
    case "NumberLiteral":
      program.push([MINI_PUSH_NUMBER, expression.value]);
      return true;
    case "BooleanLiteral":
      program.push([MINI_PUSH_BOOL, expression.value ? 1 : 0]);
      return true;
    case "NilLiteral":
      program.push([MINI_PUSH_NIL]);
      return true;
    case "UnaryExpression": {
      const opcode = MINI_UNARY_OPS[expression.operator];
      if (!opcode) {
        return false;
      }
      if (!emitMiniExpression(program, expression.argument, internString, internName)) {
        return false;
      }
      program.push([MINI_UNARY, opcode]);
      return true;
    }
    case "BinaryExpression": {
      if (expression.operator === "and" || expression.operator === "or") {
        return false;
      }
      const opcode = MINI_BINARY_OPS[expression.operator];
      if (!opcode) {
        return false;
      }
      if (!emitMiniExpression(program, expression.left, internString, internName)) {
        return false;
      }
      if (!emitMiniExpression(program, expression.right, internString, internName)) {
        return false;
      }
      program.push([MINI_BINARY, opcode]);
      return true;
    }
    case "MemberExpression":
      if (!emitMiniExpression(program, expression.base, internString, internName)) {
        return false;
      }
      if (expression.computed) {
        if (!emitMiniExpression(program, expression.indexer as Expression, internString, internName)) {
          return false;
        }
        program.push([MINI_MEMBER_COMPUTED]);
      } else {
        program.push([MINI_MEMBER_NAME, internName(expression.identifier.name)]);
      }
      return true;
    default:
      return false;
  }
}
