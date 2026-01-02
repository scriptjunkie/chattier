import { pack } from './src/bits.js';
import { find_route_of_length, random_choice, shortest_path, update_depths_added, update_depths_removed } from './src/algorithms.js';
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

//test function
// 0 <-> {3,5}   1 <-> {2,4}   2 <-> {1,3}
describe('test upd', () => {
  let idx_links = [new Set([3,5]), new Set([2,4]), new Set([1,3]), new Set([0,2]), new Set([1]), new Set([0])];
  let idx_depths = [null,null,null,null,null,null];
  update_depths_added(idx_links, idx_depths, 0, 1);
  assert.strictEqual(idx_depths, [1,4,3,2,5,2]);
  idx_links[2].delete(3);
  idx_links[3].delete(2);
  assert.strictEqual(update_depths_removed(idx_links, idx_depths, 2, 3) !== null, true);
  assert.strictEqual(idx_depths, [1, null, null, 2, null, 2]);

  idx_links = [new Set([1,2]), new Set([0,3,4]), new Set([0,5]), new Set([1,4,6]), new Set([1,3,5]), new Set([2,4,6]), new Set([3,5])];
  idx_depths = [null,null,null,null,null,null,null];
  update_depths_added(idx_links, idx_depths, 0, 1);
  assert.strictEqual(idx_depths,[1,2,2,3,3,3,4]);
  idx_links[0].delete(1);
  idx_links[1].delete(0);
  assert.strictEqual(null,update_depths_removed(idx_links, idx_depths, 0,1));
  assert.strictEqual(idx_depths,[1, 5, 2, 5, 4, 3, 4]);

  idx_links = [new Set([1,2]), new Set([2,0]), new Set([1,0])];
  idx_depths = [null, null, null];
  update_depths_added(idx_links, idx_depths, 0, 1);
  console.log(JSON.stringify(idx_depths));
  idx_links[0].delete(1);
  idx_links[1].delete(0);
  update_depths_removed(idx_links, idx_depths, 0,1);
  console.log(JSON.stringify(idx_depths));

  //randomly generate graphs of up to 16 nodes, randomly delete a link,
  //then compare on-the-fly depths calculation with a from-fresh depth calculation
  for(let i = 0; i < 2000; i++){
    const size = crypto.getRandomValues(new Uint32Array(1))[0] % 15 + 1;
    let idx_links = [];
    let idx_depths = [];
    for(let j = 0; j < size; j++){
      idx_depths.push(null);
      idx_links.push(new Set());
    }
    all_links = [];
    for(let j = 0; j < size; j++){
      const rank = Math.min(size - 1, crypto.getRandomValues(new Uint32Array(1))[0] % 4);
      for(let k = 0; k < rank; k++){
        const other = ((crypto.getRandomValues(new Uint32Array(1))[0] % (size - 1)) + j + 1) % size;
        idx_links[j].add(other);
        idx_links[other].add(j);
        all_links.push([j,other]);
      }
    }
    if(all_links.length === 0) continue;
    update_depths_added(idx_links, idx_depths, 0, 1);
//    const orig_idx_links = idx_links.map(s=>'new Set(['+Array.from(s)+'])').join(',');
//    const orig_idx_depths = JSON.stringify(idx_depths);
    //now our initial graph is set up. Let's rm a random link
    let linksrc,linkdst;
    [linksrc, linkdst] = random_choice(all_links);
    idx_links[linksrc].delete(linkdst);
    idx_links[linkdst].delete(linksrc);
    const udr = update_depths_removed(idx_links, idx_depths, linksrc, linkdst);
    const calc1 = JSON.stringify(idx_depths);
    idx_depths = idx_depths.map(()=>null);
    update_depths_added(idx_links, idx_depths, 0, 1);
    const calc2 = JSON.stringify(idx_depths);
    assert.strictEqual(calc1,calc2);
//    if(calc1 !== calc2){
//      console.log("UH OH",calc1,"!=",calc2);
//      console.log('linksrc = '+linksrc+';linkdst = '+linkdst+';idx_links = ['+orig_idx_links+'];idx_depths='+orig_idx_depths+';idx_links[linksrc].delete(linkdst);idx_links[linkdst].delete(linksrc);update_depths_removed(idx_links, idx_depths, linksrc, linkdst);');
//    }
  }
});
