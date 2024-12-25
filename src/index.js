import { pack, unpack, b64encode, b64decode, splice, concat } from './bits.js';
import { RtcBroker } from './rtcbroker.js';
import { generate, encrypt_keys_with_password, decrypt_keys_with_password, wrap_to, seal_to, unseal, sign, verify } from './crypto.js';

const LOCAL_STORAGE_ENC_KEY_NAME = "chattier_encrypted_hidden_key";
const LOCAL_STORAGE_KNOWN_SERVERS_NAME = "chattier_known_servers";

const MESSAGE_SELF_ANNOUNCE = 0x11; //announce your pubkey and ID's
const MESSAGE_KNOWN_KEYS_AND_LINKS = 0x12;
const MESSAGE_PING = 0x14;
const MESSAGE_FWD = 0x15; //scheduled forward
const MESSAGE_PADDED = 0x16;
const MESSAGE_SETUP_FORWARD = 0x17; //set up or tear down forward
const MESSAGE_SEALED = 0x18; //encrypted

const PING_LENGTH = 1400; //length of a ping
const PING_INTERVAL_MS = 2000;
const SIG_LENGTH = 64;
const KEY_LENGTH = 65;

//Note class
class Note{
	#idx_links;
	#known_keys;
	#known_aliases;
	#known_key_idxs;
	#nodes;
	#known_forwards;
	#my_forwards;
	#my_forward_chain;
	#screen_names;
	#known_servers;
	#server_ids;
	#my_ids;
	#realms;
	#my_keys;
	#my_hidden_keys;
	#my_peers;
	#timeout;

	constructor(){
		this.#idx_links = []; //idx -> Set(nodeidx)
		this.#known_keys = []; //idx -> pubkey64
		this.#known_aliases = []; //idx -> Set(node_id)
		this.#known_key_idxs = {}; //pubkey64 -> idx
		this.#nodes = {}; //node_id -> pubkey64
		this.#known_forwards = {}; //key -> next_hop_id
		this.#my_forwards = {}; //key -> next_hop_key, next_wrapping_key
		this.#my_forward_chain = []; //{node, {host: host_key, keys: keyset}
		this.#screen_names = {name_to_key: {}, key_to_name: {}};
		this.#server_ids = {}; //server_id -> url
		this.#my_ids = {}; //server_id -> client_id
		this.#realms = {}; //server_id -> {rtc, [our stuff]}
		this.#my_keys = null;
		this.#my_hidden_keys = null;
		this.#my_peers = {}; //idx -> Set(server_id)
		const server_cache_string = localStorage.getItem(LOCAL_STORAGE_KNOWN_SERVERS_NAME);
		this.#known_servers = (server_cache_string === null ? {} : JSON.parse(server_cache_string)); //url -> id
		this.#timeout = setTimeout(() => this.#dosends(), PING_INTERVAL_MS); //send polls regularly
		console.log('timeout ', this.#timeout);
	}

	async init(){
		this.#my_keys = await generate();
		this.#nodeidx_for_pubkey(this.#my_keys.pub64); //set us as idx 0.
		console.log('my node key ', this.#my_keys.pub64);
		const offset = crypto.getRandomValues(new Uint32Array(1))[0] % seedservers.length;
		for(let wsurl in this.#known_servers){
			this.#get_or_set_server_id(wsurl); //will connect if it should
		}
		for(let i = 0; i < seedservers.length; i++){
			const offsetIndex = (i + offset) % seedservers.length;
			const wsurl = seedservers[offsetIndex];
			this.#get_or_set_server_id(wsurl); //will connect if it should
		}
	}

	async generate_keys(){
		this.#my_hidden_keys = await generate();
	}

	async set_keys_from_password(password, encrypted){
		if(typeof encrypted === "undefined" || encrypted === null)
			encrypted = localStorage.getItem(LOCAL_STORAGE_ENC_KEY_NAME);
		this.#my_hidden_keys = await decrypt_keys_with_password(encrypted, password);
		console.log('my keys loaded', this.#my_hidden_keys.pub64);
	}

	async export_keys_with_password(password){
		console.log('storing and exporting keys');
		const encd = await encrypt_keys_with_password(this.#my_hidden_keys.ecdh.privateKey, password);
		localStorage.setItem(LOCAL_STORAGE_ENC_KEY_NAME, encd);
		return encd;
	}

	getlinks(){
		return [this.#known_aliases, this.#idx_links];
	}

	#dosends(){
		this.#timeout = setTimeout(() => this.#dosends(), PING_INTERVAL_MS);
		for(let server_id in this.#realms){
			let realm = this.#realms[server_id];
			realm.rtc.peers().forEach(peer_id => {
				if((peer_id in realm.queued) && realm.queued[peer_id].length > 0){
					console.log('sending forward to ', server_id,' ',peer_id);
					let to_send = realm.queued[peer_id].splice(0,1)[0];
					let packed_inner_length = pack(to_send.length);
					let buf = concat(new Uint8Array[MESSAGE_PADDED], packed_inner_length, to_send, new Uint8Array(PING_LENGTH - 1 - to_send.length));
					realm.rtc.send(peer_id, buf); // do send of queued, padded to PING_LENGTH
				} else { //send junk
					let ping = new Uint8Array(PING_LENGTH);
					ping[0] = MESSAGE_PING;
					realm.rtc.send(peer_id, ping);
				}
			});
		}
	}

	#connect_to_server(wsurl, server_id){
		if(Object.keys(this.#realms).length >= 10 || (server_id in this.#realms)){
			return; //too many servers or alreay connected? Don't connect to it!
		}
		console.log('connecting to ',wsurl, ' ',server_id, ' ', JSON.stringify(this.#server_ids));
		//Set up RTC manager with callbacks to us
		let broker = new RtcBroker(wsurl, null,
			()=>{console.log('yucky');}, // onclose
			()=>{console.log('ducky');}, // onerror
			(client_id)=>{ // onstarted
				console.log('MY ID on ', server_id, ' IS ', client_id);
				this.#set_node_pubkey(make_id(server_id, client_id), this.#my_keys.pub64);
				this.#my_ids[server_id] = client_id;
				localStorage.setItem(LOCAL_STORAGE_KNOWN_SERVERS_NAME, JSON.stringify(this.#known_servers));
			},
			(peer_int)=>{ // onnewconn
				this.#newconn(peer_int, server_id);
			},
			(node_id)=>{ // onnode
				//don't really do anything here
			},
			(node_id)=>{ // onnodeexit
				console.log('TODO: propagate handle node exit');
				//clear node aliases
				const full_node_id = make_id(server_id, node_id);
				if(full_node_id in this.#nodes){
					const idx = this.#known_key_idxs[this.#nodes[full_node_id]];
					if(idx in this.#known_aliases){
						this.#known_aliases[idx].delete(full_node_id);
					}
					//Now close peer conn
					if(idx in this.#my_peers && this.#my_peers[idx].has(server_id)){
						this.#my_peers[idx].delete(server_id);
						console.log("lost link idx now num ",this.#my_peers[idx].size);
						if(this.#my_peers[idx].size === 0){ // no longer link to that pkey
							this.#forget_known_link(0, idx);
						}
					}else console.log("how did we lose link",their_node_id,"(",idx,") and not have it?");
					delete this.#nodes[full_node_id];
				}
				//if(our_node_id in this.#known_links)
				//	//TODO: alert peers not on this server node is now gone
				//	Object.keys(this.#known_links[our_node_id]).forEach(peer=>this.#forget_known_link(our_node_id, peer));
				//	delete this.#known_links[our_node_id];
			},
			(message, peer_int)=>this.#handle_msg(message, server_id, peer_int), //onmessage
		);
		this.#realms[server_id] = {rtc: broker, their_server_id_to_ours: {}, their_nodeid_to_ours: {}, queued: {}};
	}

	#set_node_pubkey(server_peer_id, pub64){
		this.#nodes[server_peer_id] = pub64;
		let their_idx = this.#nodeidx_for_pubkey(pub64);
		this.#known_aliases[their_idx].add(server_peer_id); //nodeid -> server/peer ints id
		return their_idx;
	}

	#nodeidx_for_pubkey(pub64) {
		if(!(pub64 in this.#known_key_idxs)){ //newly known node!
			this.#known_key_idxs[pub64] = this.#known_keys.length; //key64 -> nodeid
			this.#known_keys.push(pub64); // nodeid -> key64
			this.#known_aliases.push(new Set());
			this.#idx_links.push(new Set());
		}
		return this.#known_key_idxs[pub64];
	}

	#note_known_link(alice_idx, bob_idx){
		if(!this.#idx_links[alice_idx].has(bob_idx)){
			console.log('Adding new link '+alice_idx+' <-> '+bob_idx);
			//TODO update peers about link change
		}
		this.#idx_links[alice_idx].add(bob_idx);
		this.#idx_links[bob_idx].add(alice_idx);
	}

	#forget_known_link(alice_idx, bob_idx){
		if(this.#idx_links[alice_idx].has(bob_idx)){
			console.log('FORGETTING lost link '+alice_idx+' <-> '+bob_idx);
			//TODO update peers about link change
		}else console.log('NOT forgetting lost link '+alice_idx+' <-> '+bob_idx+'?');
		this.#idx_links[alice_idx].delete(bob_idx);
		this.#idx_links[bob_idx].delete(alice_idx);
	}

	//what to do when a new peer connection happens
	async #newconn(peer_id, server_id){
		// Prep mapping translation table
		this.#realms[server_id].their_server_id_to_ours[peer_id] = {};
		this.#realms[server_id].their_nodeid_to_ours[peer_id] = {};
		// send MESSAGE_SELF_ANNOUNCE (code, pubraw, [known servers], 0, [my aliases]...
		let messagechunks = [new Uint8Array([MESSAGE_SELF_ANNOUNCE]), this.#my_keys.pubraw];
		for(let server_j in this.#server_ids){
			console.log('sending server ID ', server_j);
			const serverurl = new TextEncoder().encode(this.#server_ids[server_j]);
			messagechunks = messagechunks.concat([pack(server_j), pack(serverurl.length), serverurl]);
		}
		console.log('done sending server IDs ' + JSON.stringify(this.#server_ids));
		messagechunks.push(new Uint8Array([0]));
		for(let server_j in this.#my_ids){
			messagechunks.push(pack(server_j));
			messagechunks.push(pack(this.#my_ids[server_j]));
		}
		const announce = await (new Blob(messagechunks).arrayBuffer());
		console.log('sending self announcement to ', peer_id,' length ',announce.byteLength);
		this.#realms[server_id].rtc.send(peer_id,announce);

		// Send known keys and links by nodeid
		let known_keys_and_links_chunks = [new Uint8Array([MESSAGE_KNOWN_KEYS_AND_LINKS])];
		known_keys_and_links_chunks.push(pack(this.#known_keys.length));
		for(let key of this.#known_keys){
			known_keys_and_links_chunks.push(b64decode(key));
		}
		for(let src = 0; src < this.#idx_links.length; src++){
			for(let dst of this.#idx_links[src]){
				if(src < dst){ // only do one direction, a->b, not b->a
					known_keys_and_links_chunks.push(pack(src));
					known_keys_and_links_chunks.push(pack(dst));
				}
			}
		}
		const keys_and_links = await (new Blob(known_keys_and_links_chunks).arrayBuffer());
		console.log('sending keys and links to ', peer_id,' length ',keys_and_links.byteLength);
		this.#realms[server_id].rtc.send(peer_id, keys_and_links);
	}

	//handles a peer message
	async #handle_msg(message_data, server_id, peer_int){
		if(message_data instanceof Blob){
			message_data = await message_data.arrayBuffer(); //firefox gives you blobs, chrome arraybuffers
		}
		let message = new Uint8Array(message_data);
		//console.log('Inbound message from '+server_id+'_'+peer_int+' len '+message.length);
		let code;
		[code, message] = unpack(message);
		if(code === MESSAGE_SELF_ANNOUNCE){
			let pubk;
			[pubk, message] = splice(message, KEY_LENGTH);
			const peer_b64 = b64encode(pubk);
			const their_idx = this.#set_node_pubkey(make_id(server_id, peer_int), peer_b64); //this makes them a new node if not known before
			console.log('self announce from '+server_id+'_'+peer_int+' which is now ID '+their_idx);
			this.#note_known_link(0, their_idx); //save the link. We're always 0
			if(!(their_idx in this.#my_peers))
				this.#my_peers[their_idx] = new Set();
			this.#my_peers[their_idx].add(server_id);
			while(message.length > 0){
				let their_server_id, server_url_length, server_url_bin;
				[their_server_id, message] = unpack(message);
				if(their_server_id === 0) break;
				[server_url_length, message] = unpack(message);
				[server_url_bin, message] = splice(message, server_url_length);
				const server_url = new TextDecoder().decode(server_url_bin);
				const our_server_id = this.#get_or_set_server_id(server_url);
				this.#realms[server_id].their_server_id_to_ours[peer_int][their_server_id] = our_server_id;
				console.log('their server_url ', server_url, ' at ', their_server_id, ' ours ', our_server_id);
			}
			while(message.length > 0){
				let their_server_id, their_client_id;
				[their_server_id, message] = unpack(message);
				[their_client_id, message] = unpack(message);
				console.log("peer's alias ", their_server_id, ' (',this.#realms[server_id].their_server_id_to_ours[peer_int][their_server_id],') ', their_client_id);
				this.#set_node_pubkey(make_id(this.#realms[server_id].their_server_id_to_ours[peer_int][their_server_id], their_client_id), peer_b64);
			}
		}else if(code === MESSAGE_KNOWN_KEYS_AND_LINKS){
			let num_keys;
			[num_keys, message] = unpack(message);
			for(let i = 0; i < num_keys; i++){
				let pubk;
				[pubk, message] = splice(message, KEY_LENGTH);
				const pubk64 = b64encode(pubk);
				this.#realms[server_id].their_nodeid_to_ours[peer_int][i] = this.#nodeidx_for_pubkey(pubk64);
				console.log('received note of key ',pubk64,' - node ', this.#nodeidx_for_pubkey(pubk64));
			}
			while(message.length > 0){
				let src_their_nodeid, dst_their_nodeid;
				[src_their_nodeid, message] = unpack(message);
				[dst_their_nodeid, message] = unpack(message); //TODO: validate?
				//TODO: fix bug where our_src_id/our_dst_id get undefined since we haven't put together a mapping yet since MESSAGE_KNOWN_KEYS hasn't arrived yet
				const our_src_id = this.#realms[server_id].their_nodeid_to_ours[peer_int][src_their_nodeid];
				const our_dst_id = this.#realms[server_id].their_nodeid_to_ours[peer_int][dst_their_nodeid];
				console.log('received note of link ',our_src_id,' -> ', our_dst_id);
				this.#note_known_link(our_src_id, our_dst_id); //save the link
			}
		}else if(code === MESSAGE_FWD){
			let next_key, next_wrap;
			[next_key, message] = splice(message, KEY_LENGTH);
			let next_b64 = b64encode(next_key);
			if(next_b64 in this.#my_forwards){ //wrapping forward
				[next_b64, next_wrap] = this.#my_forwards[next_b64]; //next destination, next wrapping key
				message = concat(new Uint8Array([MESSAGE_FWD]), next_wrap, await seal_to(message, next_wrap)); //and wrap to the wrap key
			}
			if(!(next_b64 in this.#known_key_idxs)){
				console.log("WARNING: next hop "+next_b64+" unknown - dropping message");
				return;
			}
			let next_nodeid = this.#known_key_idxs[next_b64];
			for(let server_peer_id of this.#known_aliases[next_nodeid]){ //alias e.g. "1_4"
				let [server_id, peer_id] = server_peer_id.split('_').map(f=>parseInt(f));
				let realm = this.#realms[server_id]; //TODO: make this faster by caching next hops
				const peers = realm.peers();
				for(let i = 0; i < peers.length; i++){
					const candidate_peer_id = peers[i];
					if(candidate_peer_id === peer_id){
						console.log('Queueing forward to ', next_b64, ' (',server_id,'_',peer_id,')'); //here's our stop!
						if(!(peer_id in realm.queued)) realm.queued[peer_id] = [];
						realm.queued[peer_id].push(message);
						return;
					}
				}
			}
			console.log('WARNING: next hop '+next_b64+' not direct link - dropping message');
		}else if(code === MESSAGE_PADDED){
			let inner_length;
			[inner_length, message] = unpack(message);
			return this.#handle_msg(message.subarray(0,inner_length), server_id, peer_int); //unpad and recurse
		}else if(code === MESSAGE_SEALED){
			return this.#handle_msg(unseal(message, this.#my_keys.ecdh.privateKey), server_id, peer_int); //unseal and recurse
		}else if(code === MESSAGE_SETUP_FORWARD){
			let next_hop, next_keyraw, sig, next_wrap;
			[next_keyraw, message] = splice(message, KEY_LENGTH);
			let next_key = await crypto.subtle.importKey('raw', next_keyraw, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
			[sig, message] = splice(message, SIG_LENGTH);
			if(await verify(message, sig, next_key) && message[0] === MESSAGE_SETUP_FORWARD){
				[next_hop, message] = splice(message, KEY_LENGTH);
				[next_wrap, message] = splice(message, KEY_LENGTH);
				this.#my_forwards[b64encode(next_keyraw)] = [next_hop, next_wrap]; //key -> next_hop_key, next_wrapping_key
			}else{
				console.log('WARNING: bad forward setup?');
			}
		}else if(code !== MESSAGE_PING){
			console.log('unknown message ', message);
		}
	}

	#pick_random_neighbor(host_pk) {
		return random_choice(Array.from(this.#idx_links[this.#known_key_idxs[host_pk]]));
	}

	async #setup_my_forwards(){
		if(this.#idx_links.length < 3 || this.#idx_links[this.#known_key_idxs[this.#my_keys.pubraw]].size < 2){
			console.log('not enough nodes to setup forwards');
			return false;
		}
		//pick several hops (2 for now, if we can find them) and generate a key for each.
		const num_hops = 2;
		this.#my_forward_chain = [];
		let host = this.#my_keys.pubraw; //us
		for(let i = 0; i < num_hops; i++){
			const keys = generate(); //make some intermediate keys
			const key_raw = await crypto.subtle.exportKey('raw', keys.publicKey);
			if(i > 0){ //every hop except the last one (us), set up the forward
				//tell host when they get a message for key_raw, wrap it to key_raw and send to previous host addressed to previous key_raw
				const inner = concat(new Uint8Array([MESSAGE_SETUP_FORWARD]), this.#my_forward_chain[i - 1].host, this.#my_forward_chain[i - 1].key_raw);
				const signature = sign(inner, keys.privateKey);
				this.#send_wrapped_routed(host, concat(new Uint8Array([MESSAGE_SETUP_FORWARD]), key_raw, signature, inner));
			}
			this.#my_forward_chain.push({host, keys, key_raw});
			host = this.#pick_random_neighbor(host); //pick a host
		}
		return true;
	}

	//Sends a message over the network in a metadata-hiding wrapped way by selecting one or more intermediate hops
	async #send_wrapped_routed(host, messagebuffer){
		let host64 = b64encode(host);
		const my_idx = this.#nodeidx_for_pubkey(this.#my_keys.pub64);
		const their_idx = this.#nodeidx_for_pubkey(host64);
		//First find random route as indexed array
		const ROUTE_LENGTH = 3;
		const rand_route_indexed = find_route_of_length(my_idx, ROUTE_LENGTH, their_idx, this.#idx_links);
		
		//Successively wrap messages to target
		for(let i = rand_route_indexed.length - 1; i > 0; i--){
			const hop = this.#known_keys[rand_route_indexed[i]];
			const sealed_to_last = concat(new Uint8Array([MESSAGE_SEALED]), seal_to(messagebuffer, hop));
			messagebuffer = concat(new Uint8Array([MESSAGE_FWD]), hop, sealed_to_last);
		}

		//find server_id and peer_id that go to next hop and queue it to send
		for(let server_peer_id of this.#known_aliases[rand_route_indexed[1]]){ //e.g. server_peer_id = "1_4"
			let [server_id, peer_id] = server_peer_id.split('_').map(f=>parseInt(f));
			if(server_id in this.#realms && peer_id in this.#realms[server_id].queued){
				console.log('queuing relayed send to '+server_peer_id);
				this.#realms[server_id].queued[peer_id].push(sealed_to_hop);
				break;
			}
		}
	}

	//look up or get and store server ID
	#get_or_set_server_id(wsurl){
		let id = 1;
		if(wsurl in this.#known_servers){
			id = this.#known_servers[wsurl];
		}else{
			while(id in this.#server_ids) id++;
			this.#known_servers[wsurl] = id;
		}
		this.#server_ids[id] = wsurl;
		this.#connect_to_server(wsurl, id);
		return id;
	}
}


//Pick a random (securish) out of a list or throw an exception
function random_choice(disarray){
	if(disarray.length === 0){
		console.log('NO OPTIONS');
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
		let nexts = new Set()
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

//test function
// 0 <-> {3,5}   1 <-> {2,4}   2 <-> {1,3}
//#test_frol(){
//	let idx_links = [new Set([3,5]), new Set([2,4]), new Set([1,3]), new Set([0,2]), new Set([1]), new Set([0])];
//	find_route_of_length(0, 3, 3, idx_links); // <- should not throw an error, should not always return the same thing either
//}

function make_id(server_id, client_id) {
	return server_id + '_' + client_id;
}

function idstr_to_bin(idstr){
	const chunks = idstr.split('_').map(f=>pack(parseInt(f)));
	let retval = new Uint8Array(chunks[0].length + chunks[1].length);
	retval.set(chunks[0], 0);
	retval.set(chunks[1], chunks[0].length);
	return retval;
}

let context = new Note();

//Start loading
context.init();

//save dummy encrypted key with random PW even if never used
if(localStorage.getItem(LOCAL_STORAGE_ENC_KEY_NAME) === null){
	context.generate_keys().then(()=>context.export_keys_with_password(b64encode(crypto.getRandomValues(new Uint8Array(16)))));
}

export { context };
