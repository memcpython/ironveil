import type {
  AssignmentStatement,
  BinaryExpression,
  Block,
  BooleanLiteral,
  DoStatement,
  Expression,
  Identifier,
  IfStatement,
  MemberExpression,
  NumberLiteral,
  Program,
  Statement,
  StringLiteral,
  UnaryExpression,
} from "./shared";
import { XorShift32 } from "./util";

const COMPOUND_TO_BINARY: Record<string, string> = {
  "+=": "+",
  "-=": "-",
  "*=": "*",
  "/=": "/",
  "%=": "%",
  "^=": "^",
  "..=": "..",
};

export function applyTransforms(program: Program, rng: XorShift32): Program {
  insertDeadCode(program, rng);
  flattenEligibleBlocks(program, rng);
  fractureExpressions(program, rng);
  renameLocals(program, rng);
  return program;
}

function fractureExpressions(program: Program, rng: XorShift32): void {
  const rewriteBlock = (block: Block): void => {
    for (const statement of block.body) {
      rewriteStatement(statement);
    }
  };

  const rewriteStatement = (statement: Statement): void => {
    switch (statement.type) {
      case "LocalStatement":
        statement.init = statement.init.map((expression) => rewriteExpression(expression));
        break;
      case "AssignmentStatement":
        statement.left = statement.left.map((expression) => rewriteExpression(expression) as Identifier | MemberExpression);
        statement.right = statement.right.map((expression) => rewriteExpression(expression));
        break;
      case "CallStatement":
        statement.expression = rewriteExpression(statement.expression) as any;
        break;
      case "FunctionDeclaration":
        if (statement.identifier && statement.identifier.type === "MemberExpression") {
          statement.identifier.base = rewriteExpression(statement.identifier.base);
          if (statement.identifier.computed && typeof statement.identifier.indexer !== "string") {
            statement.identifier.indexer = rewriteExpression(statement.identifier.indexer);
          }
        }
        rewriteBlock(statement.body);
        break;
      case "ReturnStatement":
        statement.arguments = statement.arguments.map((expression) => rewriteExpression(expression));
        break;
      case "IfStatement":
        for (const clause of statement.clauses) {
          clause.condition = rewriteCondition(clause.condition);
          rewriteBlock(clause.body);
        }
        if (statement.elseBody) {
          rewriteBlock(statement.elseBody);
        }
        break;
      case "WhileStatement":
        statement.condition = rewriteCondition(statement.condition);
        rewriteBlock(statement.body);
        break;
      case "RepeatStatement":
        rewriteBlock(statement.body);
        statement.condition = rewriteCondition(statement.condition);
        break;
      case "ForStatement":
        statement.start = rewriteExpression(statement.start);
        statement.end = rewriteExpression(statement.end);
        if (statement.step) {
          statement.step = rewriteExpression(statement.step);
        }
        rewriteBlock(statement.body);
        break;
      case "ForInStatement":
        statement.iterator = statement.iterator.map((expression) => rewriteExpression(expression));
        rewriteBlock(statement.body);
        break;
      case "DoStatement":
        rewriteBlock(statement.body);
        break;
      case "Block":
        rewriteBlock(statement);
        break;
      case "BreakStatement":
      case "ContinueStatement":
        break;
    }
  };

  const rewriteCondition = (expression: Expression): Expression => {
    const next = rewriteExpression(expression);
    if (next.type !== "BinaryExpression") {
      return next;
    }

    if (next.operator === ">" && rng.nextInt(3) === 0) {
      return unaryExpression("not", binaryExpression("<=", next.left, next.right));
    }
    if (next.operator === ">=" && rng.nextInt(3) === 0) {
      return unaryExpression("not", binaryExpression("<", next.left, next.right));
    }
    if (next.operator === "<" && rng.nextInt(3) === 0) {
      return unaryExpression("not", binaryExpression(">=", next.left, next.right));
    }
    if (next.operator === "<=" && rng.nextInt(3) === 0) {
      return unaryExpression("not", binaryExpression(">", next.left, next.right));
    }
    if (next.operator === "==" && rng.nextInt(4) === 0) {
      return unaryExpression("not", binaryExpression("~=", next.left, next.right));
    }
    if (next.operator === "~=" && rng.nextInt(4) === 0) {
      return unaryExpression("not", binaryExpression("==", next.left, next.right));
    }
    return next;
  };

  const rewriteExpression = (expression: Expression): Expression => {
    switch (expression.type) {
      case "BinaryExpression": {
        expression.left = rewriteExpression(expression.left);
        expression.right = rewriteExpression(expression.right);
        return fractureBinary(expression, rng);
      }
      case "UnaryExpression":
        expression.argument = rewriteExpression(expression.argument);
        return expression;
      case "MemberExpression":
        expression.base = rewriteExpression(expression.base);
        if (expression.computed && typeof expression.indexer !== "string") {
          expression.indexer = rewriteExpression(expression.indexer);
        }
        return expression;
      case "CallExpression":
        expression.base = rewriteExpression(expression.base);
        expression.arguments = expression.arguments.map((argument) => rewriteExpression(argument));
        return expression;
      case "TableConstructor":
        for (const field of expression.fields) {
          if (field.type === "General" && field.key && field.key.type !== "Identifier") {
            field.key = rewriteExpression(field.key);
          }
          field.value = rewriteExpression(field.value);
        }
        return expression;
      case "FunctionExpression":
        rewriteBlock(expression.body);
        return expression;
      default:
        return expression;
    }
  };

  rewriteBlock({ type: "Block", body: program.body });
}

function renameLocals(program: Program, rng: XorShift32): void {
  const renameMap = new Map<Identifier, string>();

  const declare = (identifier: Identifier): void => {
    if (!identifier.scope || identifier.scope.type === "global") {
      return;
    }
    if (identifier.name === "..." || identifier.name === "_") {
      return;
    }
    if (!renameMap.has(identifier)) {
      renameMap.set(identifier, rng.nextIdentifier());
    }
  };

  const collectDeclarationBlock = (block: Block): void => {
    for (const statement of block.body) {
      collectDeclarationStatement(statement);
    }
  };

  const collectDeclarationStatement = (statement: Statement): void => {
    switch (statement.type) {
      case "LocalStatement":
        for (const variable of statement.variables) {
          declare(variable);
        }
        for (const init of statement.init) {
          collectDeclarationExpression(init);
        }
        break;
      case "FunctionDeclaration":
        if (statement.isLocal && statement.identifier && statement.identifier.type === "Identifier") {
          declare(statement.identifier);
        }
        for (const parameter of statement.parameters) {
          if (parameter.name !== "...") {
            declare(parameter);
          }
        }
        collectDeclarationBlock(statement.body);
        break;
      case "IfStatement":
        for (const clause of statement.clauses) {
          collectDeclarationExpression(clause.condition);
          collectDeclarationBlock(clause.body);
        }
        if (statement.elseBody) {
          collectDeclarationBlock(statement.elseBody);
        }
        break;
      case "WhileStatement":
        collectDeclarationExpression(statement.condition);
        collectDeclarationBlock(statement.body);
        break;
      case "RepeatStatement":
        collectDeclarationBlock(statement.body);
        collectDeclarationExpression(statement.condition);
        break;
      case "ForStatement":
        declare(statement.variable);
        collectDeclarationExpression(statement.start);
        collectDeclarationExpression(statement.end);
        if (statement.step) {
          collectDeclarationExpression(statement.step);
        }
        collectDeclarationBlock(statement.body);
        break;
      case "ForInStatement":
        for (const variable of statement.variables) {
          declare(variable);
        }
        for (const iterator of statement.iterator) {
          collectDeclarationExpression(iterator);
        }
        collectDeclarationBlock(statement.body);
        break;
      case "DoStatement":
        collectDeclarationBlock(statement.body);
        break;
      case "Block":
        collectDeclarationBlock(statement);
        break;
      case "AssignmentStatement":
        for (const left of statement.left) {
          collectDeclarationExpression(left);
        }
        for (const right of statement.right) {
          collectDeclarationExpression(right);
        }
        break;
      case "CallStatement":
        collectDeclarationExpression(statement.expression);
        break;
      case "ReturnStatement":
        for (const arg of statement.arguments) {
          collectDeclarationExpression(arg);
        }
        break;
      case "BreakStatement":
      case "ContinueStatement":
        break;
    }
  };

  const collectDeclarationExpression = (expression: Expression): void => {
    switch (expression.type) {
      case "BinaryExpression":
        collectDeclarationExpression(expression.left);
        collectDeclarationExpression(expression.right);
        break;
      case "UnaryExpression":
        collectDeclarationExpression(expression.argument);
        break;
      case "MemberExpression":
        collectDeclarationExpression(expression.base);
        if (expression.computed && typeof expression.indexer !== "string") {
          collectDeclarationExpression(expression.indexer);
        }
        break;
      case "CallExpression":
        collectDeclarationExpression(expression.base);
        for (const arg of expression.arguments) {
          collectDeclarationExpression(arg);
        }
        break;
      case "TableConstructor":
        for (const field of expression.fields) {
          if (field.type === "General" && field.key && field.key.type !== "Identifier") {
            collectDeclarationExpression(field.key);
          }
          collectDeclarationExpression(field.value);
        }
        break;
      case "FunctionExpression":
        for (const parameter of expression.parameters) {
          if (parameter.name !== "...") {
            declare(parameter);
          }
        }
        collectDeclarationBlock(expression.body);
        break;
      default:
        break;
    }
  };

  const renameIdentifier = (identifier: Identifier): void => {
    if (!identifier.scope || identifier.scope.type === "global") {
      return;
    }
    const declaration = identifier.scope.declaration ?? identifier;
    const renamed = renameMap.get(declaration);
    if (renamed) {
      identifier.name = renamed;
    }
  };

  const renameBlock = (block: Block): void => {
    for (const statement of block.body) {
      renameStatement(statement);
    }
  };

  const renameStatement = (statement: Statement): void => {
    switch (statement.type) {
      case "LocalStatement":
        for (const variable of statement.variables) {
          renameIdentifier(variable);
        }
        for (const init of statement.init) {
          renameExpression(init);
        }
        break;
      case "AssignmentStatement":
        for (const left of statement.left) {
          renameExpression(left);
        }
        for (const right of statement.right) {
          renameExpression(right);
        }
        break;
      case "CallStatement":
        renameExpression(statement.expression);
        break;
      case "FunctionDeclaration":
        if (statement.identifier && statement.identifier.type === "Identifier") {
          renameIdentifier(statement.identifier);
        } else if (statement.identifier) {
          renameExpression(statement.identifier.base);
          if (statement.identifier.computed && typeof statement.identifier.indexer !== "string") {
            renameExpression(statement.identifier.indexer);
          }
        }
        for (const parameter of statement.parameters) {
          renameIdentifier(parameter);
        }
        renameBlock(statement.body);
        break;
      case "ReturnStatement":
        for (const arg of statement.arguments) {
          renameExpression(arg);
        }
        break;
      case "IfStatement":
        for (const clause of statement.clauses) {
          renameExpression(clause.condition);
          renameBlock(clause.body);
        }
        if (statement.elseBody) {
          renameBlock(statement.elseBody);
        }
        break;
      case "WhileStatement":
        renameExpression(statement.condition);
        renameBlock(statement.body);
        break;
      case "RepeatStatement":
        renameBlock(statement.body);
        renameExpression(statement.condition);
        break;
      case "ForStatement":
        renameIdentifier(statement.variable);
        renameExpression(statement.start);
        renameExpression(statement.end);
        if (statement.step) {
          renameExpression(statement.step);
        }
        renameBlock(statement.body);
        break;
      case "ForInStatement":
        for (const variable of statement.variables) {
          renameIdentifier(variable);
        }
        for (const iterator of statement.iterator) {
          renameExpression(iterator);
        }
        renameBlock(statement.body);
        break;
      case "DoStatement":
        renameBlock(statement.body);
        break;
      case "Block":
        renameBlock(statement);
        break;
      case "BreakStatement":
      case "ContinueStatement":
        break;
    }
  };

  const renameExpression = (expression: Expression): void => {
    switch (expression.type) {
      case "Identifier":
        renameIdentifier(expression);
        break;
      case "BinaryExpression":
        renameExpression(expression.left);
        renameExpression(expression.right);
        break;
      case "UnaryExpression":
        renameExpression(expression.argument);
        break;
      case "MemberExpression":
        renameExpression(expression.base);
        if (expression.computed && typeof expression.indexer !== "string") {
          renameExpression(expression.indexer);
        }
        break;
      case "CallExpression":
        renameExpression(expression.base);
        for (const arg of expression.arguments) {
          renameExpression(arg);
        }
        break;
      case "TableConstructor":
        for (const field of expression.fields) {
          if (field.type === "General" && field.key && field.key.type !== "Identifier") {
            renameExpression(field.key);
          }
          renameExpression(field.value);
        }
        break;
      case "FunctionExpression":
        for (const parameter of expression.parameters) {
          renameIdentifier(parameter);
        }
        renameBlock(expression.body);
        break;
      default:
        break;
    }
  };

  collectDeclarationBlock({ type: "Block", body: program.body });
  renameBlock({ type: "Block", body: program.body });
}

function insertDeadCode(program: Program, rng: XorShift32): void {
  const decorateBlock = (block: Block): void => {
    let startIndex = 0;
    if (block.body.length > 0) {
      block.body.unshift(createDeadStatement(rng));
      startIndex = 1;
    }
    for (let index = startIndex; index < block.body.length; index += 1) {
      const statement = block.body[index];
      switch (statement.type) {
        case "FunctionDeclaration":
        case "WhileStatement":
        case "RepeatStatement":
        case "ForStatement":
        case "ForInStatement":
        case "DoStatement":
          decorateBlock(statement.body);
          break;
        case "Block":
          decorateBlock(statement);
          break;
        case "IfStatement":
          for (const clause of statement.clauses) {
            decorateBlock(clause.body);
          }
          if (statement.elseBody) {
            decorateBlock(statement.elseBody);
          }
          break;
        default:
          break;
      }
    }
  };

  decorateBlock({ type: "Block", body: program.body });
}

function flattenEligibleBlocks(program: Program, rng: XorShift32): void {
  const rewriteBlock = (block: Block): void => {
    for (const statement of block.body) {
      switch (statement.type) {
        case "FunctionDeclaration":
        case "WhileStatement":
        case "RepeatStatement":
        case "ForStatement":
        case "ForInStatement":
        case "DoStatement":
          rewriteBlock(statement.body);
          break;
        case "Block":
          rewriteBlock(statement);
          break;
        case "IfStatement":
          for (const clause of statement.clauses) {
            rewriteBlock(clause.body);
          }
          if (statement.elseBody) {
            rewriteBlock(statement.elseBody);
          }
          break;
        default:
          break;
      }
    }

    if (!isFlattenable(block.body)) {
      return;
    }

    const stateName = rng.nextIdentifier();
    const clauses = block.body.map((statement, index) => {
      const body: Block = {
        type: "Block",
        body: [statement],
      };

      if (!(statement.type === "ReturnStatement" || statement.type === "BreakStatement" || statement.type === "ContinueStatement")) {
        body.body.push(assignStatement(identifier(stateName), numberLiteral(index + 1)));
      }

      return {
        condition: binaryExpression("==", identifier(stateName), numberLiteral(index)),
        body,
      };
    });

    const flattened: DoStatement = {
      type: "DoStatement",
      body: {
        type: "Block",
        body: [
          {
            type: "LocalStatement",
            variables: [identifier(stateName)],
            init: [numberLiteral(0)],
          },
          {
            type: "WhileStatement",
            condition: booleanLiteral(true),
            body: {
              type: "Block",
              body: [
                {
                  type: "IfStatement",
                  clauses,
                  elseBody: {
                    type: "Block",
                    body: [{ type: "BreakStatement" }],
                  },
                },
              ],
            },
          },
        ],
      },
    };

    block.body = [flattened];
  };

  rewriteBlock({ type: "Block", body: program.body });
}

function isFlattenable(statements: Statement[]): boolean {
  if (statements.length < 3 || statements.length > 8) {
    return false;
  }

  for (let index = 0; index < statements.length; index += 1) {
    const statement = statements[index];
    const isLast = index === statements.length - 1;
    if (
      statement.type !== "LocalStatement" &&
      statement.type !== "AssignmentStatement" &&
      statement.type !== "CallStatement" &&
      !(isLast && statement.type === "ReturnStatement")
    ) {
      return false;
    }
  }

  return true;
}

function createDeadStatement(rng: XorShift32): IfStatement {
  const leftName = rng.nextIdentifier();
  const rightName = rng.nextIdentifier();
  const seed = rng.nextRange(2000, 9000);
  const delta = rng.nextRange(4, 29);

  return {
    type: "IfStatement",
    clauses: [
      {
        condition: booleanLiteral(false),
        body: {
          type: "Block",
          body: [
            {
              type: "LocalStatement",
              variables: [identifier(leftName), identifier(rightName)],
              init: [numberLiteral(seed), numberLiteral(seed - delta)],
            },
            assignStatement(identifier(leftName), binaryExpression("+", identifier(leftName), identifier(rightName))),
            assignStatement(identifier(rightName), binaryExpression("..", stringLiteral("_"), stringLiteral("_"))),
          ],
        },
      },
    ],
  };
}

export function desugarAssignment(statement: AssignmentStatement): AssignmentStatement {
  const binary = COMPOUND_TO_BINARY[statement.operator];
  if (!binary || statement.left.length !== 1 || statement.right.length !== 1) {
    return statement;
  }

  return {
    type: "AssignmentStatement",
    operator: "=",
    left: statement.left,
    right: [
      {
        type: "BinaryExpression",
        operator: binary,
        left: lvalueToExpression(statement.left[0]),
        right: statement.right[0],
      },
    ],
  };
}

function fractureBinary(expression: BinaryExpression, rng: XorShift32): Expression {
  if (rng.nextInt(3) !== 0) {
    return expression;
  }

  const pad = rng.nextRange(2, 17);

  switch (expression.operator) {
    case "+":
      return binaryExpression(
        "+",
        binaryExpression("+", expression.left, numberLiteral(pad)),
        binaryExpression("-", expression.right, numberLiteral(pad)),
      );
    case "-":
      return binaryExpression(
        "-",
        binaryExpression("+", expression.left, numberLiteral(pad)),
        binaryExpression("+", expression.right, numberLiteral(pad)),
      );
    default:
      return expression;
  }
}

function lvalueToExpression(expression: Identifier | MemberExpression): Expression {
  if (expression.type === "Identifier") {
    return expression;
  }
  return {
    type: "MemberExpression",
    base: expression.base,
    indexer: expression.indexer,
    identifier: expression.identifier,
    computed: expression.computed,
  };
}

function identifier(name: string): Identifier {
  return { type: "Identifier", name };
}

function numberLiteral(value: number): NumberLiteral {
  return { type: "NumberLiteral", value, raw: String(value) };
}

function stringLiteral(value: string): StringLiteral {
  return { type: "StringLiteral", value, raw: JSON.stringify(value) };
}

function booleanLiteral(value: boolean): BooleanLiteral {
  return { type: "BooleanLiteral", value };
}

function binaryExpression(operator: string, left: Expression, right: Expression): BinaryExpression {
  return { type: "BinaryExpression", operator, left, right };
}

function unaryExpression(operator: string, argument: Expression): UnaryExpression {
  return { type: "UnaryExpression", operator, argument };
}

function assignStatement(left: Identifier, right: Expression): AssignmentStatement {
  return {
    type: "AssignmentStatement",
    operator: "=",
    left: [left],
    right: [right],
  };
}
