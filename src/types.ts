export type IRScalar = null | boolean | number | string;
export type IRValue = IRScalar | IRArray | IRObject;
export interface IRArray extends Array<IRValue> {}
export interface IRObject {
  [key: string]: IRValue;
}

export type IRNameRef = number;

export type IRMiniInstruction =
  | [number]
  | [number, number]
  | [number, number, number];

export interface IRMiniProgram extends Array<IRMiniInstruction> {}

export type IRLValue =
  | [number, IRNameRef]
  | [number, IRExpression, IRNameRef | IRExpression, number];

export type IRExpression =
  | [number, IRNameRef]
  | [number, number]
  | [number]
  | [number, number, IRExpression, IRExpression]
  | [number, number, IRExpression]
  | [number, IRExpression, IRNameRef | IRExpression, number]
  | [number, IRExpression, IRExpression[], number]
  | [number, Array<[number, IRExpression] | [number, IRNameRef, IRExpression] | [number, IRExpression, IRExpression]>]
  | [number, IRMiniProgram];

export type IRStatement =
  | [number, IRNameRef[], IRExpression[], number]
  | [number, IRLValue[], IRExpression[]]
  | [number, IRExpression]
  | [number, IRExpression[]]
  | [number, Array<[IRExpression, IRStatement[]]>, IRStatement[] | null]
  | [number, IRExpression, IRStatement[]]
  | [number, IRStatement[], IRExpression]
  | [number, IRNameRef, IRExpression, IRExpression, IRExpression | null, IRStatement[]]
  | [number, IRNameRef[], IRExpression[], IRStatement[]]
  | [number]
  | [number, IRStatement[]]
  | [number, number, IRLValue, number];

export interface IRFunction {
  params: IRNameRef[];
  body: IRStatement[];
  vararg: boolean;
}

export interface StringPool {
  seed: number;
  values: string[];
}

export interface NamePool {
  seed: number;
  values: string[];
}

export interface IRModule {
  version: number;
  entry: number;
  strings: StringPool;
  names: NamePool;
  functions: IRFunction[];
}
