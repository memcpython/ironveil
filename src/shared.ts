import { Lexer } from "../../dist/lexer";
import { Parser } from "../../dist/parser";
import { ScopeAnalyzer } from "../../dist/scope";

import type {
  AssignmentStatement,
  BinaryExpression,
  Block,
  BooleanLiteral,
  CallExpression,
  CallStatement,
  ContinueStatement,
  DoStatement,
  Expression,
  ForInStatement,
  ForStatement,
  FunctionDeclaration,
  FunctionExpression,
  Identifier,
  IfStatement,
  LocalStatement,
  MemberExpression,
  NilLiteral,
  NumberLiteral,
  Program,
  RepeatStatement,
  ReturnStatement,
  Statement,
  StringLiteral,
  TableConstructor,
  UnaryExpression,
  VarargLiteral,
  WhileStatement,
} from "../../dist/ast";

export type {
  AssignmentStatement,
  BinaryExpression,
  Block,
  BooleanLiteral,
  CallExpression,
  CallStatement,
  ContinueStatement,
  DoStatement,
  Expression,
  ForInStatement,
  ForStatement,
  FunctionDeclaration,
  FunctionExpression,
  Identifier,
  IfStatement,
  LocalStatement,
  MemberExpression,
  NilLiteral,
  NumberLiteral,
  Program,
  RepeatStatement,
  ReturnStatement,
  Statement,
  StringLiteral,
  TableConstructor,
  UnaryExpression,
  VarargLiteral,
  WhileStatement,
};

export function parseLuau(source: string): Program {
  const lexer = new Lexer(source);
  const parser = new Parser(lexer.tokenize());
  const analyzer = new ScopeAnalyzer();
  return analyzer.analyze(parser.parse());
}
