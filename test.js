import { pack } from './src/bits.js';
import { find_route_of_length, shortest_path } from './src/algorithms.js';
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

//test function
// 0 <-> {3,5}   1 <-> {2,4}   2 <-> {1,3}
describe('test frol', () => {
	let idx_links = [new Set([3,5]), new Set([2,4]), new Set([1,3]), new Set([0,2]), new Set([1]), new Set([0])];
	find_route_of_length(0, 3, 3, idx_links); // <- should not throw an error, should not always return the same thing either
});

//test function
// 0 <-> {3,5}   1 <-> {2,4}   2 <-> {1,3}
describe('test fsr', () => {
	let idx_links = [new Set([3,5]), new Set([2,4]), new Set([1,3]), new Set([0,2]), new Set([1]), new Set([0])];
	assert.strictEqual(shortest_path(0, 3, idx_links).length, 2);
	assert.strictEqual(shortest_path(4, 0, idx_links).length, 5);
	assert.strictEqual(shortest_path(0, 2, idx_links).length, 3);
});
