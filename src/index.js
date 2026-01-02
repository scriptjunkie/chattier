import { pack, unpack, b64encode, b64decode, splice, concat } from './bits.js';
import { random_choice, random_path, find_route_of_length, shortest_path, update_depths_link, update_depths_removed } from './algorithms.js';
import { RtcBroker } from './rtcbroker.js';
import { generate, encrypt_keys_with_password, decrypt_keys_with_password, wrap_to, seal_to, unseal, sign, verify } from './crypto.js';

const LOCAL_STORAGE_ENC_KEY_NAME = "chattier_encrypted_hidden_key";
const LOCAL_STORAGE_KNOWN_SERVERS_NAME = "chattier_known_servers";

const MIN_CONNECTIONS = 2; //try to always ensure this many connections

const MESSAGE_SELF_ANNOUNCE = 0x11; //announce your pubkey and ID's
const MESSAGE_KNOWN_KEYS_AND_LINKS = 0x12;
const MESSAGE_NEW_LINK = 0x13;
const MESSAGE_PING = 0x14;
const MESSAGE_FWD = 0x15; //scheduled forward
const MESSAGE_PADDED = 0x16;
const MESSAGE_SETUP_FORWARD = 0x17; //set up or tear down forward
const MESSAGE_SEALED = 0x18; //encrypted
const MESSAGE_LOST_LINK = 0x19;
const MESSAGE_ANNOUNCE = 0x1A; //announce another host
const MESSAGE_DIR_QUERY = 0x1B;
const MESSAGE_DIR_ANSWER = 0x1C;
const MESSAGE_CHAT = 0x1D;

const MESSAGE_DEBUG_CON_LOG_REQUEST = 0x20;
const MESSAGE_DEBUG_CON_LOG = 0x21;

const SETUP_FORWARD_INNER = 0xA1;

const ROUTE_LENGTH = 3; //default hops to a node
const PING_LENGTH = 1400; //length of a ping
const PING_INTERVAL_MS = 2000;
const SIG_LENGTH = 64;
const KEY_LENGTH = 65;
const HASH_LENGTH = 32;

//console log replacement so we can debug
let myconlog = [];
const basetime = (new Date()).getTime();
function clog() {
	let argz = [((new Date()).getTime() - basetime) / 1000].concat(Array.from(arguments));
	try {
		console.log.apply(console, argz);
		myconlog.push(argz);
	} catch (e) {
		console.log(e, argz);
	}
}

//Note class
class Note {
	#idx_links;
	#idx_depths;
	#known_keys;
	#known_aliases;
	#known_key_idxs;
	#nodes;
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
	#con_log_listener;
	#debug_mode;
	#recheck_timer;
	#directory;
	#received_chat;

	constructor() {
		this.#idx_links = []; //idx -> Set(nodeidx)
		this.#known_keys = []; //idx -> pubkeyraw
		this.#idx_depths = []; //idx -> least hops from me
		this.#known_aliases = []; //idx -> Set(node_id)
		this.#my_peers = {}; //idx -> {server_id -> peer_int}
		this.#known_key_idxs = {}; //pubkey64 -> idx
		this.#nodes = {}; //node_id -> pubkey64
		this.#my_forwards = {}; //key -> next_hop_key, next_wrapping_key
		this.#my_forward_chain = []; //{node, {host: host_key, keys: keyset}
		this.#screen_names = { name_to_key: {}, key_to_name: {} }; //TODO: this
		this.#server_ids = {}; //server_id -> url
		this.#my_ids = {}; //server_id -> client_id
		this.#realms = {}; //server_id -> {rtc, [our stuff]}
		this.#my_keys = null;
		this.#my_hidden_keys = null;
		this.#con_log_listener = null;
		this.#debug_mode = false;
		this.#recheck_timer = null;
		const server_cache_string = localStorage.getItem(LOCAL_STORAGE_KNOWN_SERVERS_NAME);
		this.#known_servers = (server_cache_string === null ? {} : JSON.parse(server_cache_string)); //url -> id
		this.#timeout = setTimeout(() => this.#dosends(), PING_INTERVAL_MS); //send polls regularly
		this.#directory = {}; //announce_hash -> {key: pubkey64, last: unixtime}
		clog('timeout ', this.#timeout);
	}

	set_debug_mode(enabled) {
		this.#debug_mode = enabled;
	}

	async init() {
		this.#my_keys = await generate();
		this.#nodeidx_for_pubkey(this.#my_keys.pubraw); //set us as idx 0.
		clog('my node key ', this.#my_keys.pub64);
		const offset = crypto.getRandomValues(new Uint32Array(1))[0] % seedservers.length;
		for (let wsurl in this.#known_servers) {
			this.#get_or_set_server_id(wsurl); //will connect if it should
		}
		for (let i = 0; i < seedservers.length; i++) {
			const offsetIndex = (i + offset) % seedservers.length;
			const wsurl = seedservers[offsetIndex];
			this.#get_or_set_server_id(wsurl); //will connect if it should
		}
		this.#recheck_timer = setInterval(() => { //but if they don't in a little bit, connect to one
			const total_pending = Object.entries(this.#realms).map(a => a[1].rtc.num_pending()).reduce((e, v) => e + v); //sum all num_pending
			if (total_pending + Object.keys(this.#my_peers).length < MIN_CONNECTIONS) {
				let validids = [];
				for (let srvid in this.#realms) {
					for (let peer_int of this.#realms[srvid].rtc.known_clients()) {
						if (!this.#realms[srvid].rtc.has_link(peer_int) && peer_int != this.#my_ids[srvid]) {
							validids.push([srvid, peer_int]);
						}
					}
				}
				if (validids.length > 0) {
					clog("Few open connections - attempting to force new connection");
					const choice = random_choice(validids);
					this.#realms[choice[0]].rtc.connectto(choice[1]);
				}
			}
		}, 5000 + Math.random() * 1000);
	}

	get_con_logs(idx) {
		const peer_server_id = Object.keys(this.#my_peers[idx])[0];
		const peer_int = this.#my_peers[idx][peer_server_id];
		this.#realms[peer_server_id].rtc.send(peer_int, new Uint8Array([MESSAGE_DEBUG_CON_LOG_REQUEST]));
		return new Promise((cb) => { this.#con_log_listener = cb; });
	}

	//Brand new start method, generating new keys and initializing callback for new chats
	async generate_keys(received_chat) {
		this.#my_hidden_keys = await generate();
		this.#received_chat = received_chat;
	}

	//load stored keys with password, starting a functional chat client with a callback for new chats
	async set_keys_from_password(password, received_chat, encrypted) {
		if (typeof encrypted === "undefined" || encrypted === null)
			encrypted = localStorage.getItem(LOCAL_STORAGE_ENC_KEY_NAME);
		this.#my_hidden_keys = await decrypt_keys_with_password(encrypted, password);
		this.#received_chat = received_chat;
		clog('my keys loaded', this.#my_hidden_keys.pub64);
	}

	async export_keys_with_password(password) {
		clog('storing and exporting keys');
		const encd = await encrypt_keys_with_password(this.#my_hidden_keys.ecdh.privateKey, password);
		localStorage.setItem(LOCAL_STORAGE_ENC_KEY_NAME, encd);
		return encd;
	}

	getlinks() {
		return [this.#known_aliases, this.#idx_links];
	}

	#dosends() {
		this.#timeout = setTimeout(() => this.#dosends(), PING_INTERVAL_MS);
		for (let server_id in this.#realms) {
			let realm = this.#realms[server_id];
			realm.rtc.peers().forEach(peer_id => {
				if ((peer_id in realm.queued) && realm.queued[peer_id].length > 0) {
					clog('sending forward to ', server_id +'_'+ peer_id);
					let to_send = realm.queued[peer_id].splice(0, 1)[0];
					let packed_inner_length = pack(to_send.length);
					let buf = concat(new Uint8Array([MESSAGE_PADDED]), packed_inner_length, to_send, new Uint8Array(PING_LENGTH - 1 - to_send.length));
					realm.rtc.send(peer_id, buf); // do send of queued, padded to PING_LENGTH
				} else { //send junk
					let ping = new Uint8Array(PING_LENGTH);
					ping[0] = MESSAGE_PING;
					realm.rtc.send(peer_id, ping);
				}
			});
		}
	}

	#connect_to_server(wsurl, server_id) {
		if (Object.keys(this.#realms).length >= 10 || (server_id in this.#realms)) {
			return; //too many servers or alreay connected? Don't connect to it!
		}
		clog('connecting to ', wsurl, ' ', server_id, ' ', JSON.stringify(this.#server_ids));
		//Set up RTC manager with callbacks to us
		let broker = new RtcBroker(wsurl, null,
			() => { clog('yucky'); }, // onclose
			() => { clog('ducky'); }, // onerror
			(client_id) => { // onstarted
				clog('MY ID on ', server_id, ' IS ', client_id);
				this.#set_node_pubkey(make_id(server_id, client_id), this.#my_keys.pubraw);
				this.#my_ids[server_id] = client_id;
				localStorage.setItem(LOCAL_STORAGE_KNOWN_SERVERS_NAME, JSON.stringify(this.#known_servers));
			},
			(peer_int) => { // onnewconn
				this.#newconn(peer_int, server_id);
			},
			(peer_int) => { // onnodeexit
				clog('onnodeexit', server_id, peer_int);
				const full_node_id = make_id(server_id, peer_int);
				if (full_node_id in this.#nodes) {
					const idx = this.#known_key_idxs[this.#nodes[full_node_id]];
					if (idx in this.#known_aliases) {
						this.#known_aliases[idx].delete(full_node_id);
					}
					this.#handle_peer_close(server_id, peer_int);
					delete this.#nodes[full_node_id];
				}
			},
			(message, peer_int) => this.#wrapped_handle_msg(message, server_id, peer_int), //onmessage
			(peer_int) => this.#handle_peer_close(server_id, peer_int), //onconnclose
			(peer_int) => { //onnewclient
				if (Math.random() < 2 / (1 + Object.keys(this.#my_peers).length)) { //new peer - connect with decreasing probability
					clog("Trying to connect to", server_id, peer_int);
					this.#realms[server_id].rtc.connectto(peer_int);
				} else {
					clog('Not trying to connect to new peer ', peer_int, '. We already have ', Object.keys(this.#my_peers).length);
				}
			},
		);
		this.#realms[server_id] = { rtc: broker, peer_int_to_idx: {}, queued: {} };
	}

	#handle_peer_close(server_id, peer_int) {
		if (peer_int in this.#realms[server_id]) delete this.#realms[server_id].queued[peer_int];
		//clear node aliases
		const full_node_id = make_id(server_id, peer_int);
		if (full_node_id in this.#nodes) {
			const idx = this.#known_key_idxs[this.#nodes[full_node_id]];
			//Now close peer conn
			if (idx in this.#my_peers && server_id in this.#my_peers[idx]) {
				delete this.#my_peers[idx][server_id];
				clog("lost link idx now num ", Object.keys(this.#my_peers[idx]).length);
				if (Object.keys(this.#my_peers[idx]).length === 0) { // no longer link to that pkey
					delete this.#my_peers[idx];
					this.#forget_known_link(0, idx);
				}
			} else clog("how did we lose link", their_node_id, "(", idx, ") and not have it?");
		}
	}

	//Notes a server/peer ID is a given pubkey and returns the idx
	#set_node_pubkey(server_peer_id, pubkeyraw) {
		this.#nodes[server_peer_id] = b64encode(pubkeyraw);
		let their_idx = this.#nodeidx_for_pubkey(pubkeyraw);
		if (!(their_idx in this.#known_aliases)) this.#known_aliases[their_idx] = new Set();
		this.#known_aliases[their_idx].add(server_peer_id); //nodeid -> server/peer ints id
		return their_idx;
	}

	#nodeidx_for_pubkey(pubkeyraw) {
		const pub64 = b64encode(pubkeyraw);
		//TODO: use old unused slot? maybe randomly try a few if we've removed nodes?
		if (!(pub64 in this.#known_key_idxs)) { //newly known node!
			this.#known_key_idxs[pub64] = this.#known_keys.length;
			this.#known_keys.push(pubkeyraw); // nodeid -> key64
			this.#idx_depths.push(null);
			this.#known_aliases.push(new Set());
			this.#idx_links.push(new Set());
		}
		return this.#known_key_idxs[pub64];
	}

	//Sends a message immediately to all direct peers except for the listed idx's.
	#send_all_peers(message, idx1, idx2, idx3) {
		for (let idx in this.#my_peers) {
			if (idx === idx1 || idx === idx2 || idx === idx3) continue; // don't report back to who reported it to us
			const peer_server_id = Object.keys(this.#my_peers[idx])[0];
			const peer_int = this.#my_peers[idx][peer_server_id];
			this.#realms[peer_server_id].rtc.send(peer_int, message);
		}
	}

	#note_known_link(alice_idx, bob_idx, reporter_idx) {
		if (this.#idx_links[alice_idx].has(bob_idx)) return;
		clog('Adding new link ' + alice_idx + ' <-> ' + bob_idx, reporter_idx);
		let message = concat(new Uint8Array([MESSAGE_NEW_LINK]), this.#known_keys[alice_idx], this.#known_keys[bob_idx]);
		this.#send_all_peers(message, reporter_idx, alice_idx, bob_idx); //send announcement to all peers
		this.#idx_links[alice_idx].add(bob_idx);
		this.#idx_links[bob_idx].add(alice_idx);
		update_depths_link(this.#idx_links, this.#idx_depths, alice_idx, bob_idx); //Update new depths
	}

	#forget_known_link(alice_idx, bob_idx, reporter_idx) {
		if (!this.#idx_links[alice_idx].has(bob_idx)) return; //exit early if we already forgot this link
		clog('FORGETTING lost link ' + alice_idx + ' <-> ' + bob_idx);
		let message = concat(new Uint8Array([MESSAGE_LOST_LINK]), this.#known_keys[alice_idx], this.#known_keys[bob_idx]);
		this.#send_all_peers(message, reporter_idx, alice_idx, bob_idx); //send announcement to all peers
		this.#idx_links[alice_idx].delete(bob_idx);
		this.#idx_links[bob_idx].delete(alice_idx);
		const id = update_depths_removed(this.#idx_links, this.#idx_depths, alice_idx, bob_idx);
		if(id !== null){
			clog("PARTITION ", id);
			for(let chain_el of this.#my_forward_chain){
				if(this.#idx_depths[chain_el.host_idx] === null){
					clog("LOST CHAIN");
					this.setup_my_forwards(true); //re-set-up forwards
					break;
				}
			}
			//TODO: remove unreachable network partition elements? Or naw? Maybe on timeout to give chance for reconnection?
		}
	}

	//what to do when a new peer connection happens
	async #newconn(peer_id, server_id) {
		// send MESSAGE_SELF_ANNOUNCE (code, pubraw, [known servers], 0, [my aliases]...
		let messagechunks = [new Uint8Array([MESSAGE_SELF_ANNOUNCE]), this.#my_keys.pubraw];
		for (let server_j in this.#server_ids) {
			clog('sending server ID ', server_j);
			const serverurl = new TextEncoder().encode(this.#server_ids[server_j]);
			messagechunks = messagechunks.concat([pack(server_j), pack(serverurl.length), serverurl]);
		}
		clog('done sending server IDs ' + JSON.stringify(this.#server_ids));
		messagechunks.push(new Uint8Array([0]));
		for (let server_j in this.#my_ids) {
			messagechunks.push(pack(server_j));
			messagechunks.push(pack(this.#my_ids[server_j]));
		}
		const announce = await (new Blob(messagechunks).arrayBuffer());
		clog('sending self announcement to ', peer_id, ' length ', announce.byteLength);
		this.#realms[server_id].rtc.send(peer_id, announce);

		// Send known keys and links by nodeid
		let known_keys_and_links_chunks = [new Uint8Array([MESSAGE_KNOWN_KEYS_AND_LINKS])];
		known_keys_and_links_chunks.push(pack(this.#known_keys.length));
		this.#known_keys.forEach(key => known_keys_and_links_chunks.push(key));
		for (let src = 0; src < this.#idx_links.length; src++) {
			for (let dst of this.#idx_links[src]) {
				if (src < dst) { // only do one direction, a->b, not b->a
					known_keys_and_links_chunks.push(pack(src));
					known_keys_and_links_chunks.push(pack(dst));
				}
			}
		}
		const keys_and_links = await (new Blob(known_keys_and_links_chunks).arrayBuffer());
		clog('sending keys and links to ', peer_id, ' length ', keys_and_links.byteLength);
		this.#realms[server_id].rtc.send(peer_id, keys_and_links);
	}

	//handles a peer message with error loggin
	async #wrapped_handle_msg(message_data, server_id, peer_int) {
		try {
			return this.#handle_msg(message_data, server_id, peer_int);
		} catch (e) {
			clog('ERROR line', e.lineNumber, 'message', e.message, 'fileName', e.fileName, 'stack', e.stack);
		}
	}

	//handles a peer message
	async #handle_msg(message_data, server_id, peer_int) {
		if (message_data instanceof Blob) {
			message_data = await message_data.arrayBuffer(); //firefox gives you blobs, chrome arraybuffers
		}
		let message = new Uint8Array(message_data);
		let code;
		[code, message] = unpack(message);
		if (code === MESSAGE_SELF_ANNOUNCE) {
			let pubk;
			[pubk, message] = splice(message, KEY_LENGTH);
			const their_idx = this.#set_node_pubkey(make_id(server_id, peer_int), pubk); //this makes them a new node if not known before
			clog('self announce from ' + server_id + '_' + peer_int + ' which is now ID ' + their_idx);
			this.#note_known_link(0, their_idx, their_idx); //save the link. We're always 0
			if (!(their_idx in this.#my_peers)) {
				this.#my_peers[their_idx] = {};
			}
			this.#my_peers[their_idx][server_id] = peer_int;
			if (!(peer_int in this.#realms[server_id].queued)) this.#realms[server_id].queued[peer_int] = [];
			this.#realms[server_id].peer_int_to_idx[peer_int] = their_idx;
			let their_server_id_to_ours = {};
			while (message.length > 0) {
				let their_server_id, server_url_length, server_url_bin;
				[their_server_id, message] = unpack(message);
				if (their_server_id === 0) break;
				[server_url_length, message] = unpack(message);
				[server_url_bin, message] = splice(message, server_url_length);
				const server_url = new TextDecoder().decode(server_url_bin);
				const our_server_id = this.#get_or_set_server_id(server_url);
				their_server_id_to_ours[their_server_id] = our_server_id;
				clog('their server_url ', server_url, ' at ', their_server_id, ' ours ', our_server_id);
			}
			while (message.length > 0) {
				let their_server_id, their_client_id;
				[their_server_id, message] = unpack(message);
				[their_client_id, message] = unpack(message);
				clog("peer's alias ", their_server_id, ' (', their_server_id_to_ours[their_server_id], ') ', their_client_id);
				this.#set_node_pubkey(make_id(their_server_id_to_ours[their_server_id], their_client_id), pubk);
			}
		} else if (code === MESSAGE_DEBUG_CON_LOG) {
			if (this.#con_log_listener) {
				this.#con_log_listener(JSON.parse(new TextDecoder().decode(message)));
				this.#con_log_listener = null;
			}
		} else if (code === MESSAGE_DEBUG_CON_LOG_REQUEST) {
			if (this.#debug_mode) {
				this.#realms[server_id].rtc.send(peer_int, concat(new Uint8Array([MESSAGE_DEBUG_CON_LOG]), new TextEncoder().encode(JSON.stringify(myconlog))));
			}
		} else if (code === MESSAGE_KNOWN_KEYS_AND_LINKS) {
			let num_keys;
			[num_keys, message] = unpack(message);
			let their_nodeid_to_ours = {};
			for (let i = 0; i < num_keys; i++) {
				let pubk;
				[pubk, message] = splice(message, KEY_LENGTH);
				their_nodeid_to_ours[i] = this.#nodeidx_for_pubkey(pubk);
				clog('received note of key ', b64encode(pubk), ' - node ', this.#nodeidx_for_pubkey(pubk), 'from', their_nodeid_to_ours[0]);
			}
			const their_idx = their_nodeid_to_ours[0]; //Get their idx
			while (message.length > 0) {
				let src_their_nodeid, dst_their_nodeid;
				[src_their_nodeid, message] = unpack(message);
				[dst_their_nodeid, message] = unpack(message); //TODO: validate?
				const our_src_id = their_nodeid_to_ours[src_their_nodeid];
				const our_dst_id = their_nodeid_to_ours[dst_their_nodeid];
				clog('received note of link ', our_src_id, ' -> ', our_dst_id);
				if (our_src_id !== 0 && our_dst_id !== 0) this.#note_known_link(our_src_id, our_dst_id, their_idx); //save the link. But don't trust our links
			}
		} else if (code === MESSAGE_NEW_LINK) { //Just src, dst keys
			const arr = splice(message, KEY_LENGTH).map(a => this.#nodeidx_for_pubkey(a));
			clog("MESSAGE_NEW_LINK", arr[0], arr[1], 'from', server_id + '_' + peer_int);
			const their_idx = this.#realms[server_id].peer_int_to_idx[peer_int]; // this should be set by now
			this.#note_known_link(arr[0], arr[1], their_idx);
		} else if (code === MESSAGE_LOST_LINK) { //Just src, dst keys. TODO: sign this
			const arr = splice(message, KEY_LENGTH).map(a => this.#nodeidx_for_pubkey(a));
			clog("MESSAGE_LOST_LINK", arr[0], arr[1], 'from', server_id + '_' + peer_int);
			const their_idx = this.#realms[server_id].peer_int_to_idx[peer_int]; // this should be set by now
			this.#forget_known_link(arr[0], arr[1], their_idx);
		} else if (code === MESSAGE_FWD) {
			let next_key, next_wrap;
			[next_key, message] = splice(message, KEY_LENGTH);
			let next_b64 = b64encode(next_key);
			if (next_b64 in this.#my_forwards) { //wrapping forward
				const orig_next_b64 = next_b64;
				[next_key, next_wrap] = this.#my_forwards[next_b64]; //next destination, next wrapping key
				next_b64 = b64encode(next_key);
				clog("Wrapping forward "+orig_next_b64+" -> "+next_b64);
				message = concat(new Uint8Array([MESSAGE_FWD]), next_wrap, new Uint8Array([MESSAGE_SEALED]), await seal_to(message, next_wrap)); //and wrap to the wrap key
			}
			const mfcl = this.#my_forward_chain.length;
			if(mfcl > 0 && this.#my_forward_chain[mfcl - 2].link_pubkey === next_b64){
				for(let i = mfcl - 2; i >= 0; i--){
					[code, message] = splice(message, 1);
					clog("DECODING WRAPPED INBOUND MESSAGE "+i+" "+code+" msealed "+MESSAGE_SEALED+" len "+message.length);
					message = await unseal(message, this.#my_forward_chain[i].keys.ecdh.privateKey);
				}
				clog("DECODING FINAL STEP");
				[code, message] = splice(message, 1);
				clog("sealed? "+code === MESSAGE_SEALED);
				message = await unseal(message, this.#my_forward_chain[mfcl - 1].keys.ecdh.privateKey);
				return this.#handle_msg(message, server_id, peer_int);
			}
			if (!(next_b64 in this.#known_key_idxs)) {
				clog("WARNING: next hop " + next_b64 + " unknown - dropping message len " + message.length);
				return;
			}
			let next_nodeid = this.#known_key_idxs[next_b64];
			if (next_nodeid === 0){
				clog("Forward for me?! len " + message.length); //it's for me? Somebody probably screwed up.
				return this.#handle_msg(message, server_id, peer_int);
			} else if (next_nodeid in this.#my_peers) {
				for (let myp_server_id in this.#my_peers[next_nodeid]) {
					if (this.#my_peers[next_nodeid][myp_server_id] in this.#realms[server_id].queued) {
						clog('Queueing forward to ', next_b64, ' (', myp_server_id, '_', this.#my_peers[next_nodeid][myp_server_id], ')'); //here's our stop!
						this.#realms[server_id].queued[this.#my_peers[next_nodeid][myp_server_id]].push(message);
						return;
					}else{
						clog("WARN: peer not in realms? server id "+myp_server_id+" mypeer item "+this.#my_peers[next_nodeid][myp_server_id]+" realms "+Object.keys(this.#realms[server_id].queued));
					}
				}
				clog("WARNING: Peer without valid queue?", next_nodeid);
			}
			clog('WARNING: next hop ' + next_b64 + ' nodeid ' + next_nodeid + ' not direct link - dropping message');
		} else if (code === MESSAGE_PADDED) {
			let inner_length;
			[inner_length, message] = unpack(message);
			return this.#handle_msg(message.subarray(0, inner_length), server_id, peer_int); //unpad and recurse
		} else if (code === MESSAGE_SEALED) {
			clog("Unsealing", code, 'len', message.length);
			//try {
				return this.#handle_msg(await unseal(message, this.#my_keys.ecdh.privateKey), server_id, peer_int); //unseal and recurse
			//} catch (e) {
			//	if (this.#my_hidden_keys) {
			//		try {
			//			return this.#handle_msg(await unseal(message, this.#my_hidden_keys.ecdh.privateKey), server_id, peer_int);
			//		} catch (e2) {
			//			clog("Failed to unseal with hidden key too");
			//		}
			//	}
			//	throw e;
			//}
		} else if (code === MESSAGE_SETUP_FORWARD) {
			let next_hop, next_keyraw, sig, next_wrap;
			[next_keyraw, message] = splice(message, KEY_LENGTH);
			let next_key = await crypto.subtle.importKey('raw', next_keyraw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
			[sig, message] = splice(message, SIG_LENGTH);
			if (await verify(message, sig, next_key) && message.length > 0 && message[0] === SETUP_FORWARD_INNER) {
				[code, message] = splice(message, 1);
				[next_hop, message] = splice(message, KEY_LENGTH);
				[next_wrap, message] = splice(message, KEY_LENGTH);
				const next_keyb64 = b64encode(next_keyraw);
				this.#my_forwards[next_keyb64] = [next_hop, next_wrap]; //key -> next_hop_key, next_wrapping_key
				clog('Set up forward for messages addressed to ',next_keyb64,' to go to', this.#known_key_idxs[b64encode(next_hop)], 'announcing?', message[0]);
				if (message[0] === 1) {//request to announce
					//announce it. Let up to the 4 next nodes key-order-wise FROM THE next_key know.
					const hashed_key = new Uint8Array(await crypto.subtle.digest({ name: 'SHA-256' }, concat(this.#my_keys.pubraw, next_keyraw))); //so they don't know real key
					const hashed_key_b64 = b64encode(hashed_key);
					clog("Announcing ",hashed_key_b64);
					this.#directory[hashed_key_b64] = { 'key': this.#my_keys.pubraw, 'last': new Date().getTime() };
					const announcement = concat(new Uint8Array([MESSAGE_ANNOUNCE]), this.#my_keys.pubraw, hashed_key); //TODO - sign announcement
					if(next_keyb64 in this.#known_key_idxs){
						clog("ERROR: trying to set up forward for host key");
						return;
					}
					this.#known_key_idxs[next_keyb64] = 0; //HACK: adding to list to get position in nodes easily
					let all_b64_keys = Object.keys(this.#known_key_idxs).sort();
					delete this.#known_key_idxs[next_keyb64];
					let search_idx = all_b64_keys.indexOf(next_keyb64);
					for (let i = 1; i < 5; i++) {
						const idx = (i + search_idx) % all_b64_keys.length;
						if (idx === search_idx) break; //stop if all nodes hit
						if (all_b64_keys[idx] === this.#my_keys.pub64) continue; //skip ourselves
						const dst_idx = this.#known_key_idxs[all_b64_keys[idx]];
						try{//TODO: remove nodes from known_key_idxs if unreachable
							let path = shortest_path(0, dst_idx, this.#idx_links); //Find most direct route to announce (this is not the private part of the link)
							clog("path ",path,"i",i,idx,search_idx,all_b64_keys.length);
							this.#send_wrapped_with_route(path, announcement); //and send the announcement. Don't wait.
						}catch(e){clog("No path to "+dst_idx);}
					}
				}
			} else {
				clog('WARNING: bad forward setup?');
			}
		} else if (code === MESSAGE_ANNOUNCE) {
			let next_host, hashed_key;
			[next_host, message] = splice(message, KEY_LENGTH);
			[hashed_key, message] = splice(message, HASH_LENGTH);
			const announcedkey = b64encode(hashed_key);
			if(!(announcedkey in this.#directory))clog("Learned of ",announcedkey," at ",b64encode(next_host));
			this.#directory[announcedkey] = { 'key': next_host, 'last': new Date().getTime() };
		} else if (code === MESSAGE_DIR_QUERY) { //TODO: make this routed
			let hashed_key, next_host;
			[hashed_key, message] = splice(message, HASH_LENGTH);
			const hkb64 = b64encode(hashed_key);
			[next_host, message] = splice(message, KEY_LENGTH);
			if (hkb64 in this.#directory) {
				const reply = concat(new Uint8Array([MESSAGE_DIR_ANSWER]), hashed_key, this.#directory[hkb64].key);
				this.#send_wrapped_routed(next_host, reply); //TODO: match this up (send to hosted?)
			}
		} else if (code === MESSAGE_DIR_ANSWER) {
			let hashed_key, host_key;
			[hashed_key, message] = splice(message, HASH_LENGTH);
			[host_key, message] = splice(message, KEY_LENGTH);
			this.#directory[b64encode(hashed_key)] = { 'key': host_key, 'last': new Date().getTime() };
		} else if (code === MESSAGE_CHAT) {
			let sender_pubraw, chat_msg_bin;
			[sender_pubraw, chat_msg_bin] = splice(message, KEY_LENGTH);
			const sender_pub64 = b64encode(sender_pubraw);
			const chat_msg = new TextDecoder().decode(chat_msg_bin);
			this.#received_chat(chat_msg, sender_pub64);
		} else if (code !== MESSAGE_PING) {
			clog('unknown message ', message, 'len', message.length, 'vals', message.subarray(0, 6).join(','));
		}
	}

	//returns a random idx of a node linked to host_idx
	#pick_random_neighbor(host_idx) {
		return random_choice(Array.from(this.#idx_links[host_idx]));
	}

	async setup_my_forwards(do_announce) {
		if (this.#idx_links.length < 3 || this.#idx_links[0].size < 2) {
			throw 'not enough nodes to setup forwards';
		} else if (this.#my_hidden_keys === null) {
			throw 'No chat keys provisioned - must generate or import';
		}
		//pick several hops (2 for now, if we can find them) and generate a key for each.
		const num_hops = 2;
		this.#my_forward_chain = [];
		let host_idx = 0; //us
		let rand_route_indexed = [0];
		for (let i = 0; i < num_hops; i++) {
			const keys = (i < num_hops - 1) ? (await generate()) : this.#my_hidden_keys; //make some intermediate keys
			if (i > 0) { //every hop except the last one (us), set up the forward
				//tell host when they get a message for keys.pubraw, wrap it to next keys.pubraw and send to next host
				const last_hop_key_raw = this.#known_keys[this.#my_forward_chain[i - 1].host_idx];
				const announce_code = i === num_hops - 1 && do_announce ? 1 : 0; //last one in the chain announces
				const inner = concat(new Uint8Array([SETUP_FORWARD_INNER]), last_hop_key_raw, this.#my_forward_chain[i - 1].keys.pubraw, new Uint8Array([announce_code]));
				const signature = await sign(inner, keys.ecdsa.privateKey);
				rand_route_indexed.push(host_idx);
				clog("rri ",rand_route_indexed);
				this.#send_wrapped_with_route(rand_route_indexed, concat(new Uint8Array([MESSAGE_SETUP_FORWARD]), keys.pubraw, signature, inner));
				clog('setting up forward ' + i + ':', host_idx, '->', rand_route_indexed[i - 1], '=', this.#my_forward_chain[i - 1].host_idx, 'next hop key', b64encode(last_hop_key_raw));
			}
			this.#my_forward_chain.push({ host_idx, keys, link_pubkey: keys.pub64 });
			host_idx = this.#pick_random_neighbor(host_idx); //pick a host
		}
		return true;
	}

	//Sends a message over the network in a metadata-hiding wrapped way by selecting one or more intermediate hops
	async #send_wrapped_routed(host, messagebuffer) {
		const my_idx = 0;
		const their_idx = this.#nodeidx_for_pubkey(host);
		//First find random route as indexed array
		const rand_route_indexed = find_route_of_length(my_idx, ROUTE_LENGTH, their_idx, this.#idx_links);
		clog("rri frol ",rand_route_indexed);
		return this.#send_wrapped_with_route(rand_route_indexed, messagebuffer);
	}

	async #send_wrapped_with_route(route, messagebuffer) {
		//wrap message to destination
		messagebuffer = concat(new Uint8Array([MESSAGE_SEALED]), await seal_to(messagebuffer, this.#known_keys[route[route.length - 1]]));
		//Successively wrap messages to target. First iteration of loop, hop_plus_one will be the final destination and hop will be i (node before hop_plus_one)
		for (let i = route.length - 2; i > 0; i--) {
			const hop_plus_one = this.#known_keys[route[i+1]];
			messagebuffer = concat(new Uint8Array([MESSAGE_FWD]), hop_plus_one, messagebuffer);
			const hop = this.#known_keys[route[i]];
			if (i > 0) messagebuffer = concat(new Uint8Array([MESSAGE_SEALED]), await seal_to(messagebuffer, hop));
		}

		if(!(route[1] in this.#known_aliases)){
			clog("ERROR: bad route? ",route);
			return;
		}
		//find server_id and peer_id that go to next hop and queue it to send
		for (let server_peer_id of this.#known_aliases[route[1]]) { //e.g. server_peer_id = "1_4"
			let [server_id, peer_id] = server_peer_id.split('_').map(f => parseInt(f));
			if (server_id in this.#realms && peer_id in this.#realms[server_id].queued) {
				clog('queueing relayed send to ' + server_peer_id + ' ('+route[1]+')');
				this.#realms[server_id].queued[peer_id].push(messagebuffer);
				return;
			}
		}
		clog("ERROR - no known alias for", route[1]);
	}

	//look up or get and store server ID
	#get_or_set_server_id(wsurl) {
		let id = 1;
		if (wsurl in this.#known_servers) {
			id = this.#known_servers[wsurl];
		} else {
			while (id in this.#server_ids) id++;
			this.#known_servers[wsurl] = id;
		}
		this.#server_ids[id] = wsurl;
		this.#connect_to_server(wsurl, id);
		return id;
	}

	get_my_id() {
		return this.#my_hidden_keys.pub64;
	}

	async #get_host_for_pubkey(other_pubraw) {
		// Try local cache first
		const all_node_idxs = Object.keys(this.#known_keys);
		for (let idx = 0; idx < all_node_idxs.length; idx++) {
			const node_pub = this.#known_keys[idx];
			const hashed = new Uint8Array(await crypto.subtle.digest({ name: 'SHA-256' }, concat(node_pub, other_pubraw)));
			const h64 = b64encode(hashed);
			if (h64 in this.#directory) {
				clog("found ",h64," in directory for host ",b64encode(node_pub)," at ",b64encode(this.#directory[h64].key));
				return this.#directory[h64].key;
			}
			clog("did not find ",h64," in directory for host ",b64encode(node_pub)," key ",b64encode(other_pubraw));
		}
		clog("did not find ",b64encode(other_pubraw)," in directory ",Object.keys(this.#directory));

		// If not found, broadcast a query to all direct peers
		//TODO: send wrapped query directly to next nodes key order wise and get wrapped response
		for (let idx in this.#my_peers) {
			const node_pub = this.#known_keys[idx];
			const hashed = new Uint8Array(await crypto.subtle.digest({ name: 'SHA-256' }, concat(node_pub, other_pubraw)));
			const query = concat(new Uint8Array([MESSAGE_DIR_QUERY]), hashed, this.#my_keys.pubraw);
			this.#send_wrapped_routed(node_pub, query);
		}
		return null;
	}

	async send_chat(other_pub64, message_text) {
		clog("Sending chat message "+other_pub64+" "+message_text);
		const other_pubraw = b64decode(other_pub64);
		let host = await this.#get_host_for_pubkey(other_pubraw);
		if (!host) {
			clog("Failed to find host for " + other_pub64 + " you will need to retry send after a second.");
			return false;
		}

		const inner = concat(new Uint8Array([MESSAGE_CHAT]), this.#my_hidden_keys.pubraw, new TextEncoder().encode(message_text));
		const sealed = concat(new Uint8Array([MESSAGE_FWD]), other_pubraw, new Uint8Array([MESSAGE_SEALED]), await seal_to(inner, other_pubraw));
		clog("inner chat text len "+inner.length+" sealed len "+sealed.length);
		await this.#send_wrapped_routed(host, sealed);
		return true;
	}
}

function make_id(server_id, client_id) {
	return server_id + '_' + client_id;
}

let context = new Note();

//Start loading
context.init();

//save dummy encrypted key with random PW even if never used
if (localStorage.getItem(LOCAL_STORAGE_ENC_KEY_NAME) === null) {
	context.generate_keys().then(() => context.export_keys_with_password(b64encode(crypto.getRandomValues(new Uint8Array(16)))));
}

export { Note, context };
