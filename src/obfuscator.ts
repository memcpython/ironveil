import { compileProgram } from "./compiler";
import { createVmProfile } from "./profile";
import { emitLuaLoader } from "./runtime";
import { parseLuau } from "./shared";
import { applyTransforms } from "./transforms";
import { XorShift32 } from "./util";

export interface IronVeilOptions {
  seed?: number;
}

export class IronVeilObfuscator {
  private readonly seed: number;
  private static readonly CORE_SEED = 0x45ab12cd;
  private static readonly PROFILE_SEED_MASK = 0x735a2d19;
  private static readonly PAYLOAD_SEED_MASK = 0x6c8e9cf5;

  constructor(options: IronVeilOptions = {}) {
    this.seed = options.seed ?? this.makeSeed();
  }

  obfuscate(source: string): string {
    const rng = new XorShift32(this.seed);
    const ast = parseLuau(source);
    applyTransforms(ast, rng);
    const profile = createVmProfile((this.seed ^ IronVeilObfuscator.PROFILE_SEED_MASK ^ IronVeilObfuscator.CORE_SEED) >>> 0);
    profile.nameSeed = (profile.nameSeed ^ this.seed ^ IronVeilObfuscator.PROFILE_SEED_MASK) >>> 0;
    const module = compileProgram(ast, profile, (this.seed ^ IronVeilObfuscator.PAYLOAD_SEED_MASK ^ IronVeilObfuscator.CORE_SEED) >>> 0);
    return emitLuaLoader(module, profile);
  }

  private makeSeed(): number {
    const now = Date.now() >>> 0;
    const noise = Math.floor(Math.random() * 0xffffffff) >>> 0;
    return (now ^ noise ^ 0x1d872b41) >>> 0;
  }
}
