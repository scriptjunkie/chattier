//Pick a random (securish) out of a list or throw an exception
function random_choice(disarray){
	if(disarray.length === 0){
		clog('NO OPTIONS');
		throw 'NO OPTIONS';
	}
	return disarray[crypto.getRandomValues(new Uint32Array(1))[0] % disarray.length];
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

export { random_choice, random_path, find_route_of_length, shortest_path };
