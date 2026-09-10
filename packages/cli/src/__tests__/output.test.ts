import { describe, it, expect, vi, afterEach } from 'vitest';
import { emit } from '../output.js';

describe('emit (--json shape)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('writes exactly one JSON line and skips the human renderer in json mode', () => {
    const write = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const human = vi.fn();
    emit({ a: 1, b: 'x' }, { json: true }, human);
    expect(human).not.toHaveBeenCalled();
    expect(write).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledWith('{"a":1,"b":"x"}\n');
  });

  it('invokes the human renderer and emits no JSON in human mode', () => {
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const human = vi.fn();
    emit({ a: 1 }, { json: false }, human);
    expect(human).toHaveBeenCalledWith({ a: 1 });
  });
});
