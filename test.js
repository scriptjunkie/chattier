import { pack } from './src/bits.js';
import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('pack function', () => {
  it('should match known packed values', () => {
    assert.strictEqual(
      JSON.stringify(pack(0)),
      JSON.stringify(new Uint8Array([0]))
    );
    assert.strictEqual(
      JSON.stringify(pack(1)),
      JSON.stringify(new Uint8Array([1]))
    );
    assert.strictEqual(
      JSON.stringify(pack(127)),
      JSON.stringify(new Uint8Array([127]))
    );
    assert.strictEqual(
      JSON.stringify(pack(128)),
      JSON.stringify(new Uint8Array([128, 1]))
    );
    assert.strictEqual(
      JSON.stringify(pack(129)),
      JSON.stringify(new Uint8Array([129, 1]))
    );
  });
});
