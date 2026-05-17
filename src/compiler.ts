import type {
  AssignmentStatement,
  Block,
  Expression,
  FunctionDeclaration,
  Identifier,
  MemberExpression,
  Program,
  Statement,
  TableConstructor,
} from "./shared";
import { desugarAssignment } from "./transforms";
import type {
  IRExpression,
  IRFunction,
  IRLValue,
  IRModule,
  IRNameRef,
  IRStatement,
} from "./types";
import type { VmProfile } from "./profile";
import { vmifyCondition } from "./vmify";

export function compileProgram(program: Program, profile: VmProfile, seed: number): IRModule {
  const compiler = new IronVeilCompiler(profile, seed);
  const entry = compiler.compileRoot(program.body);
  return compiler.finish(entry);
}

class IronVeilCompiler {
  private readonly functions: IRFunction[] = [];
  private readonly stringPool = new Map<string, number>();
  private readonly strings: string[] = [];
  private readonly namePool = new Map<string, number>();
  private readonly names: string[] = [];

  constructor(private readonly profile: VmProfile, private readonly seed: number) {}

  compileRoot(body: Statement[]): number {
    return this.pushFunction([], body, false);
  }

  finish(entry: number): IRModule {
    return {
      version: 1,
      entry,
      strings: {
        seed: this.seed,
        values: this.strings,
      },
      names: {
        seed: this.seed ^ 0x5a17c3e1,
        values: this.names,
      },
      functions: this.functions,
    };
  }

  private encExpr(name: keyof VmProfile["exprTags"]): number {
    return this.profile.exprTags[name] ^ this.profile.exprMask;
  }

  private encStmt(name: keyof VmProfile["stmtTags"]): number {
    return this.profile.stmtTags[name] ^ this.profile.stmtMask;
  }

  private encLValue(name: keyof VmProfile["lvalueTags"]): number {
    return this.profile.lvalueTags[name] ^ this.profile.lvalueMask;
  }

  private encField(name: keyof VmProfile["fieldTags"]): number {
    return this.profile.fieldTags[name] ^ this.profile.fieldMask;
  }

  private encBinary(operator: string): number {
    return this.profile.binaryOps[operator] ^ this.profile.binaryMask;
  }

  private encUnary(operator: string): number {
    return this.profile.unaryOps[operator] ^ this.profile.unaryMask;
  }

  private pushFunction(parameters: Identifier[], body: Statement[], fallbackVararg: boolean): number {
    const params: IRNameRef[] = [];
    let vararg = fallbackVararg;

    for (const parameter of parameters) {
      if (parameter.name === "...") {
        vararg = true;
      } else {
        params.push(this.internName(parameter.name));
      }
    }

    const fn: IRFunction = {
      params,
      body: body.map((statement) => this.compileStatement(statement)),
      vararg,
    };

    this.functions.push(fn);
    return this.functions.length;
  }

  private compileBlock(block: Block): IRStatement[] {
    return block.body.map((statement) => this.compileStatement(statement));
  }

  private compileStatement(statement: Statement): IRStatement {
    switch (statement.type) {
      case "LocalStatement":
        return [
          this.encStmt("local"),
          statement.variables.map((variable) => this.internName(variable.name)),
          statement.init.map((expr) => this.compileExpression(expr)),
          this.needsPendingLocals(statement.init, new Set(statement.variables.map((variable) => variable.name))) ? 1 : 0,
        ];
      case "AssignmentStatement": {
        const rewritten = desugarAssignment(statement as AssignmentStatement);
        return [this.encStmt("assign"), rewritten.left.map((item) => this.compileLValue(item)), rewritten.right.map((expr) => this.compileExpression(expr))];
      }
      case "CallStatement":
        return [this.encStmt("expr"), this.compileExpression(statement.expression)];
      case "FunctionDeclaration":
        return this.compileFunctionDeclaration(statement);
      case "ReturnStatement":
        return [this.encStmt("return"), statement.arguments.map((expr) => this.compileExpression(expr))];
      case "IfStatement":
        return [
          this.encStmt("if"),
          statement.clauses.map((clause) => [this.compileConditionExpression(clause.condition), this.compileBlock(clause.body)]),
          statement.elseBody ? this.compileBlock(statement.elseBody) : null,
        ];
      case "WhileStatement":
        return [this.encStmt("while"), this.compileConditionExpression(statement.condition), this.compileBlock(statement.body)];
      case "RepeatStatement":
        return [this.encStmt("repeat"), this.compileBlock(statement.body), this.compileConditionExpression(statement.condition)];
      case "ForStatement":
        return [
          this.encStmt("fornum"),
          this.internName(statement.variable.name),
          this.compileExpression(statement.start),
          this.compileExpression(statement.end),
          statement.step ? this.compileExpression(statement.step) : null,
          this.compileBlock(statement.body),
        ];
      case "ForInStatement":
        return [
          this.encStmt("forin"),
          statement.variables.map((variable) => this.internName(variable.name)),
          statement.iterator.map((expr) => this.compileExpression(expr)),
          this.compileBlock(statement.body),
        ];
      case "BreakStatement":
        return [this.encStmt("break")];
      case "ContinueStatement":
        return [this.encStmt("continue")];
      case "DoStatement":
        return [this.encStmt("do"), this.compileBlock(statement.body)];
      case "Block":
        return [this.encStmt("do"), this.compileBlock(statement)];
      default:
        throw new Error(`Unsupported statement type: ${(statement as Statement).type}`);
    }
  }

  private compileFunctionDeclaration(statement: FunctionDeclaration): IRStatement {
    if (!statement.identifier) {
      throw new Error("Function declarations must have an identifier.");
    }

    const functionIndex = this.pushFunction(statement.parameters, statement.body.body, false);
    return [
      this.encStmt("func"),
      statement.isLocal ? 1 : 0,
      this.compileLValue(statement.identifier.type === "Identifier" ? statement.identifier : statement.identifier),
      functionIndex,
    ];
  }

  private compileLValue(target: Identifier | MemberExpression): IRLValue {
    if (target.type === "Identifier") {
      return [this.encLValue("id"), this.internName(target.name)];
    }

    return [
      this.encLValue("member"),
      this.compileExpression(target.base),
      target.computed ? this.compileExpression(target.indexer as Expression) : this.internName(target.identifier.name),
      target.computed ? 1 : 0,
    ];
  }

  private compileExpression(expression: Expression): IRExpression {
    switch (expression.type) {
      case "Identifier":
        return [this.encExpr("id"), this.internName(expression.name)];
      case "StringLiteral":
        return [this.encExpr("str"), this.internString(expression.value)];
      case "NumberLiteral":
        return [this.encExpr("num"), expression.value];
      case "BooleanLiteral":
        return [this.encExpr("bool"), expression.value ? 1 : 0];
      case "NilLiteral":
        return [this.encExpr("nil")];
      case "VarargLiteral":
        return [this.encExpr("vararg")];
      case "UnaryExpression":
        return [this.encExpr("unary"), this.encUnary(expression.operator), this.compileExpression(expression.argument)];
      case "BinaryExpression":
        return [this.encExpr("binary"), this.encBinary(expression.operator), this.compileExpression(expression.left), this.compileExpression(expression.right)];
      case "MemberExpression":
        return [
          this.encExpr("member"),
          this.compileExpression(expression.base),
          expression.computed ? this.compileExpression(expression.indexer as Expression) : this.internName(expression.identifier.name),
          expression.computed ? 1 : 0,
        ];
      case "CallExpression":
        return [
          this.encExpr("call"),
          this.compileExpression(expression.base),
          expression.arguments.map((arg) => this.compileExpression(arg)),
          expression.selfCall ? 1 : 0,
        ];
      case "TableConstructor":
        return [this.encExpr("table"), this.compileTableFields(expression)];
      case "FunctionExpression":
        return [this.encExpr("function"), this.pushFunction(expression.parameters, expression.body.body, false)];
      default:
        throw new Error(`Unsupported expression type: ${(expression as Expression).type}`);
    }
  }

  private compileConditionExpression(expression: Expression): IRExpression {
    const mini = vmifyCondition(
      expression,
      (value) => this.internString(value),
      (value) => this.internName(value),
    );
    if (mini) {
      return [this.encExpr("mini"), mini];
    }
    return this.compileExpression(expression);
  }

  private compileTableFields(table: TableConstructor): Array<[number, IRExpression] | [number, IRNameRef, IRExpression] | [number, IRExpression, IRExpression]> {
    return table.fields.map((field) => {
      if (field.type === "Array") {
        return [this.encField("array"), this.compileExpression(field.value)];
      }
      if (field.type === "Record" && field.key && field.key.type === "Identifier") {
        return [this.encField("record"), this.internName(field.key.name), this.compileExpression(field.value)];
      }
      return [this.encField("general"), this.compileExpression(field.key as Expression), this.compileExpression(field.value)];
    });
  }

  private internString(value: string): number {
    const existing = this.stringPool.get(value);
    if (existing) {
      return existing;
    }
    const index = this.strings.length + 1;
    this.stringPool.set(value, index);
    this.strings.push(value);
    return index;
  }

  private internName(value: string): IRNameRef {
    const existing = this.namePool.get(value);
    if (existing) {
      return existing;
    }
    const index = this.names.length + 1;
    this.namePool.set(value, index);
    this.names.push(value);
    return index;
  }

  private needsPendingLocals(expressions: Expression[], locals: Set<string>): boolean {
    return expressions.some((expression) => this.expressionNeedsPendingLocals(expression, locals, false));
  }

  private expressionNeedsPendingLocals(expression: Expression, locals: Set<string>, nestedFunction: boolean): boolean {
    switch (expression.type) {
      case "Identifier":
        return nestedFunction && locals.has(expression.name);
      case "UnaryExpression":
        return this.expressionNeedsPendingLocals(expression.argument, locals, nestedFunction);
      case "BinaryExpression":
        return this.expressionNeedsPendingLocals(expression.left, locals, nestedFunction)
          || this.expressionNeedsPendingLocals(expression.right, locals, nestedFunction);
      case "MemberExpression":
        return this.expressionNeedsPendingLocals(expression.base, locals, nestedFunction)
          || (expression.computed ? this.expressionNeedsPendingLocals(expression.indexer as Expression, locals, nestedFunction) : false);
      case "CallExpression":
        return this.expressionNeedsPendingLocals(expression.base, locals, nestedFunction)
          || expression.arguments.some((arg) => this.expressionNeedsPendingLocals(arg, locals, nestedFunction));
      case "TableConstructor":
        return expression.fields.some((field) => {
          if (field.type === "Array") {
            return this.expressionNeedsPendingLocals(field.value, locals, nestedFunction);
          }
          if (field.type === "Record") {
            return this.expressionNeedsPendingLocals(field.value, locals, nestedFunction);
          }
          return this.expressionNeedsPendingLocals(field.key as Expression, locals, nestedFunction)
            || this.expressionNeedsPendingLocals(field.value, locals, nestedFunction);
        });
      case "FunctionExpression":
        return this.blockNeedsPendingLocals(expression.body, locals);
      default:
        return false;
    }
  }

  private blockNeedsPendingLocals(block: Block, locals: Set<string>): boolean {
    return block.body.some((statement) => this.statementNeedsPendingLocals(statement, locals));
  }

  private statementNeedsPendingLocals(statement: Statement, locals: Set<string>): boolean {
    switch (statement.type) {
      case "LocalStatement":
        return statement.init.some((expr) => this.expressionNeedsPendingLocals(expr, locals, true));
      case "AssignmentStatement":
        return statement.right.some((expr) => this.expressionNeedsPendingLocals(expr, locals, true));
      case "CallStatement":
        return this.expressionNeedsPendingLocals(statement.expression, locals, true);
      case "ReturnStatement":
        return statement.arguments.some((expr) => this.expressionNeedsPendingLocals(expr, locals, true));
      case "IfStatement":
        return statement.clauses.some((clause) =>
          this.expressionNeedsPendingLocals(clause.condition, locals, true) || this.blockNeedsPendingLocals(clause.body, locals))
          || (statement.elseBody ? this.blockNeedsPendingLocals(statement.elseBody, locals) : false);
      case "WhileStatement":
        return this.expressionNeedsPendingLocals(statement.condition, locals, true)
          || this.blockNeedsPendingLocals(statement.body, locals);
      case "RepeatStatement":
        return this.blockNeedsPendingLocals(statement.body, locals)
          || this.expressionNeedsPendingLocals(statement.condition, locals, true);
      case "ForStatement":
        return this.expressionNeedsPendingLocals(statement.start, locals, true)
          || this.expressionNeedsPendingLocals(statement.end, locals, true)
          || (statement.step ? this.expressionNeedsPendingLocals(statement.step, locals, true) : false)
          || this.blockNeedsPendingLocals(statement.body, locals);
      case "ForInStatement":
        return statement.iterator.some((expr) => this.expressionNeedsPendingLocals(expr, locals, true))
          || this.blockNeedsPendingLocals(statement.body, locals);
      case "DoStatement":
        return this.blockNeedsPendingLocals(statement.body, locals);
      case "Block":
        return this.blockNeedsPendingLocals(statement, locals);
      case "FunctionDeclaration":
        return false;
      default:
        return false;
    }
  }
}
