//Pick a random (securish) out of a list or throw an exception
function random_choice(disarray){
	if(disarray.length === 0){
		console.log('NO OPTIONS');
		throw 'NO OPTIONS';
	}
	const idx = crypto.getRandomValues(new Uint32Array(1))[0] % disarray.length;
	if(idx < 4294967296 - (4294967296 % disarray.length)) //fix bias for 4294967296 % disrray.length != 0
		return disarray[idx];
	return random_choice(disarray);
}

//Updates depths for when a link is added
function update_depths_added(idx_links, idx_depths, start_idx, start_depth){
	if(idx_depths[start_idx] && idx_depths[start_idx] <= start_depth) //Did we already have as good of a link?
		return; //then skip it. it changes nothing
	idx_depths[start_idx] = start_depth; //set this new depth and continue recalculation
	for(let next of idx_links[start_idx]) //did we just add a closer link to this neighbor?
		update_depths_added(idx_links, idx_depths, next, idx_depths[start_idx] + 1); //let's find out
}

//Same, but wrapped to figure out initial/continuing depth automatically
function update_depths_link(idx_links, idx_depths, alice_idx, bob_idx){
	if(alice_idx === 0) update_depths_added(idx_links, idx_depths, alice_idx, 1);
	else if(bob_idx === 0) update_depths_added(idx_links, idx_depths, bob_idx, 1);
	//New node cases
	else if(idx_depths[alice_idx] === null) update_depths_added(idx_links, idx_depths, alice_idx, idx_depths[bob_idx] + 1);
	else if(idx_depths[bob_idx] === null) update_depths_added(idx_links, idx_depths, bob_idx, idx_depths[alice_idx] + 1);
	//New link, existing node cases
	else if(idx_depths[alice_idx] > idx_depths[bob_idx]) update_depths_added(idx_links, idx_depths, alice_idx, idx_depths[bob_idx] + 1);
	else update_depths_added(idx_links, idx_depths, bob_idx, idx_depths[alice_idx] + 1);
}

//Updates depths for when a link is removed
function update_depths_removed(idx_links, idx_depths, to_idx, from_idx){
	if(idx_depths[from_idx] > idx_depths[to_idx])
		return update_depths_removed(idx_links, idx_depths, from_idx, to_idx); // src/dest swapped

	if(idx_depths[from_idx] === idx_depths[to_idx]) return null; //this link was not the shortest path here

	//is there another fast route of the same depth?
	for(let next of idx_links[to_idx])
		if(idx_depths[next] === idx_depths[to_idx] - 1) return null; //Yes, no depth updating needed

	//Ok, now we have a problem. We know we need to recalculate depths for > 0 nodes and might have a partition
	//iterate along graph BFS marking nodes that might be relying on me erasing depth. (me, everyone I link to at depth + 1, etc.)
	//If I find anyone at lower or equal depth I haven't added to queue yet, then it wasn't a bridge.
	let queue = [to_idx];
	let entrants = new Set(); //these will need to be re-calculated for updated depths
	let outbound = new Set([to_idx]);
	let potential_entrants = new Set();
	let starting_depth = idx_depths[to_idx];
	while(queue.length > 0){
		const current = queue.shift();
		const old_depth = idx_depths[current];
		if(starting_depth < old_depth){
			starting_depth = old_depth; //we bumped up a rank!
			entrants = entrants.union(potential_entrants); //any remaining potential entrants are real entrants now.
			potential_entrants.clear();
		}
		idx_depths[current] = null; //Clear it
		for(let next of idx_links[current]){
			//console.log('Checking',current,'old_depth',old_depth,'next',next,'depth',idx_depths[next]);
			if(idx_depths[next] === null) {
				continue; //we already hit this
			}else if(idx_depths[next] === old_depth + 1) {
				outbound.add(next); //mark that this is one we found outbound but didn't visit yet
				potential_entrants.delete(next); //we found a path from the cut so it's not a potential entrant
				queue.push(next); //we will need to recurse here
			} else if(idx_depths[next] < old_depth){
				entrants.add(next); //another path from 0 can reach here! But different depth. Will need to recalculate.
			}else if(!outbound.has(next)) { //this probably means there's another path that can reach here. But maybe we just haven't gotten there yet
				potential_entrants.add(next);
			}
		}
	}
	entrants = entrants.union(potential_entrants); //any remaining potential entrants are real entrants now.
	if(entrants.size === 0)
		return to_idx; //No other paths! We cut a bridge. Parent must remove all nodes/links connected to to_idx
	for(let entrant of entrants)
		for(let next of idx_links[entrant]) //let's recurse on each entrant's links and update depths
			update_depths_added(idx_links, idx_depths, next, idx_depths[entrant] + 1);
	return null;
}

//Pick a random path to a node with a reachset (an array where each element at index I is a set of all nodes I hops away from the start)
function random_path(starting_choice, reachset, idx_links){
	let choices_back_to_src = [starting_choice];
	for(let i = reachset.length - 2; i >= 0; i--){
		let options = []; //find all options in reachset[i]
		for(let candidate of reachset[i]){
			if(idx_links[candidate].has(choices_back_to_src[choices_back_to_src.length - 1])){
				options.push(candidate);
			}
		}
		choices_back_to_src.push(random_choice(options)); //pick a random one for next choice
	}
	return choices_back_to_src;
}

//Find a random route of a given length between two nodes, given a link index
function find_route_of_length(src, length, dst, idx_links){
	let hops_from_src = [new Set().add(src)]; //sets of what's reachable at X hops from src
	let hops_from_dst = [new Set().add(dst)]; //sets of what's reachable at X hops from dst
	for(let cur_len = 0; cur_len < length; cur_len++){
		let current_iterating_list = (hops_from_dst.length < hops_from_src.length ? hops_from_dst : hops_from_src); //alternate expanding from src and dst
		let nexts = new Set();
		for(let s of current_iterating_list[current_iterating_list.length - 1])
			for(let next of idx_links[s])
				nexts.add(next);
		current_iterating_list.push(nexts);
	}
	//Ok, now we have sets of everything up to n/2 hops from both src and dst. Pick a random of intersection
	let options = [];
	for(let candidate of hops_from_src[hops_from_src.length - 1]){
		if(hops_from_dst[hops_from_dst.length - 1].has(candidate)){
			options.push(candidate);
		}
	}
	let choice = random_choice(options);
	//now random path to src and dest and merge the two lists
	return random_path(choice, hops_from_src, idx_links).reverse().concat(random_path(choice, hops_from_dst, idx_links).slice(1));
}

// finds a single path from an existing path through a hops set list to the end and append to path
function simple_walk_through(hops_list, idx_links, path){
	for(let i = hops_list.length - 1; i >= 0; i--){
		let found = false;
		for(let lnk of idx_links[path[path.length - 1]]){
			if(hops_list[i].has(lnk)){
				path.push(lnk);
				found = true;
				break;
			}
		}
		if(!found) throw "ERROR - No link between "+path[path.length - 1]+" and hlset "+i;
	}
}

//Find a shortest path from src to dst and return
function shortest_path(src, dst, idx_links){
	let hops_from_src = [new Set().add(src)]; //sets of what's reachable at X hops from src
	let hops_from_dst = [new Set().add(dst)]; //sets of what's reachable at X hops from dst
	let visited = new Set([src]);
	while(true){
		let current_iterating_list = hops_from_src;
		let comparison_set = hops_from_dst[hops_from_dst.length - 1];
		if(hops_from_dst.length < hops_from_src.length){
			current_iterating_list = hops_from_dst;
			comparison_set = hops_from_src[hops_from_src.length - 1]; //alternate expanding from src and dst
		}
		let nexts = new Set();
		for(let s of current_iterating_list[current_iterating_list.length - 1]){
			for(let next of idx_links[s]){
				if(comparison_set.has(next)){ //we have a first hit on shortest path. Back out here.
					let total_array = [next];
					(current_iterating_list === hops_from_src ? hops_from_dst : hops_from_src).pop();
					//find path to next from hops_from_src
					simple_walk_through(hops_from_src, idx_links, total_array);
					total_array.reverse(); //then flip direction to walk back to dst
					simple_walk_through(hops_from_dst, idx_links, total_array);
					return total_array;
				}
				if(visited.has(next)) continue; //probably a backlink
				visited.add(next);
				nexts.add(next);
			}
		}
		if(nexts.size === 0) throw "No path found for "+src+" -> "+dst;
		current_iterating_list.push(nexts);
	}
}

export { random_choice, random_path, find_route_of_length, shortest_path, update_depths_link, update_depths_added, update_depths_removed };
