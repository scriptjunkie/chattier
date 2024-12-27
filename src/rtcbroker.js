// RTC broker - automatically establishes a set of peer connections using a websocket broker
const CODE_FULL_LIST = 1;
const CODE_CLIENT_EXIT = 2;
const CODE_CLIENT_RTC_REQUEST = 3;
const CODE_CLIENT_RTC_RESPONSE = 4;
const CODE_CLIENT_ANNOUNCE = 0xc;
const CODE_CLIENT_FWD_NOW = 0xd;

class RtcBroker {
	#client_id;
	#links;
	#pending_peer_connections;
	#onstarted; 
	#onnewconn;
	#onnode;
	#onnodeexit;
	#onmessage;
	#on_conn_close;
	
	constructor(wsurl, zone, onclose, onerror, onstarted, onnewconn, onnode, onnodeexit, onmessage, onconnclose) {
		this.#client_id = null;
		this.#links = {};
		this.#pending_peer_connections = {};
		this.#onstarted = onstarted;
		this.#onnewconn = onnewconn;
		this.#onnode = onnode;
		this.#onnodeexit = onnodeexit;
		this.#onmessage = onmessage;
		this.#on_conn_close = onconnclose;
		console.log('connecting to ', wsurl);
		//Now do the connection
		zone=(zone && zone.length == 32 ? zone : '00000000000000000000000000000000');
		let sock = new WebSocket(wsurl);
		sock.onclose = e => {
			console.log('websocket ',wsurl,' closing ',e);
			onclose(e);
		};
		sock.onerror = e => {
			console.log('websocket ',wsurl,' error ',e);
			onerror(e);
		};
		sock.onopen = e => {
			console.log('websocket opened to ', wsurl);
			sock.send(new Uint32Array([zone.substr(24,8),zone.substr(16,8),zone.substr(8,8),zone.substr(0,8)].map(z=>parseInt(z,16))).buffer);
		};
		sock.onmessage = (msg) => this.#handle_websocket_message(msg, sock);
	}

	//returns list of peers
	peers(){
		return Object.keys(this.#links);
	}

	//sends an arrayBuffer to a peer
	send(peer_id, message){
		this.#links[peer_id].dc.send(new Uint8Array(message));
	}

	//clear a closed connection
	#clearConn(peer_id, message){
		console.log(message, peer_id);
		if(peer_id in this.#links) delete this.#links[peer_id];
		if(peer_id in this.#pending_peer_connections) delete this.#pending_peer_connections[peer_id];
		if(this.#on_conn_close) this.#on_conn_close(peer_id);
	}

	//web socket message function
	async #handle_websocket_message(msgevt, sock) {
		const u8 = new Uint8Array(await msgevt.data.arrayBuffer());
		if(u8[0] == CODE_CLIENT_ANNOUNCE){
			const announced_int = new Uint32Array(u8.slice(1,5).buffer)[0];
			if(this.#client_id === null){
				this.#client_id = announced_int;
				if(this.#onstarted)
					this.#onstarted(announced_int);
			}else if (Math.random() < 2 / (1 + Object.keys(this.#links).length)){ //new peer - connect with decreasing probability
				this.#connectto(announced_int, sock);
			}else {
				console.log('Not trying to connect to new peer ',announced_int,'. We already have ',Object.keys(this.#links).length);
			}
			if(this.#client_id !== announced_int && this.#onnode)
				this.#onnode(announced_int);
		}else if(u8[0] == CODE_CLIENT_RTC_REQUEST && u8.length > 5){
			const peer_id = new Uint32Array(u8.slice(1,5).buffer)[0];
			const rtcRequest = JSON.parse((new TextDecoder()).decode(u8.subarray(5)));
			console.log('RTC RESPONDER 1/8 CODE_CLIENT_RTC_REQUEST', rtcRequest, 'from', peer_id);
			
			let submitIces = (rtcpeerconn, ice_list) => {
				for(let i = 0; i < ice_list.length; i++){
					const icej = JSON.stringify(ice_list[i]);
					if(!(icej in this.#pending_peer_connections[peer_id].ices)){ //it's a new one
						this.#pending_peer_connections[peer_id].ices[icej] = 1;
						console.log('RTC RESPONDER 4/8 adding received ICE candidate '+icej, peer_id);
						rtcpeerconn.addIceCandidate(ice_list[i]);
					}
				}
			};
				
			if(peer_id in this.#pending_peer_connections){
				console.log('already in pending_peer_connections with state of ', this.#pending_peer_connections[peer_id].rtcpc.connectionState, ' and ice connection state of ',this.#pending_peer_connections[peer_id].rtcpc.iceConnectionState,' probably learned new ICE option');
				if(this.#pending_peer_connections[peer_id].rtcpc.iceConnectionState !== 'connected')
					submitIces(this.#pending_peer_connections[peer_id].rtcpc, rtcRequest.connectToMePlz);
				return; //DONE
			}
			//create connection with same stun server hopefully
			let inboundPeerConn = new RTCPeerConnection({iceServers: [{urls:[iceserver]}]});
			this.#pending_peer_connections[peer_id] = {rtcpc: inboundPeerConn, ices: {}};
			inboundPeerConn.ondatachannel = dcevt => {
				let chan = dcevt.channel;
				console.log('RTC RESPONDER 7/8 inboundPeerConn ondatachannel', dcevt, peer_id);
				chan.onopen = () => {
					console.log('RTC RESPONDER 8/8 Data channel open to ', peer_id);
					this.#links[peer_id] = {rtcpc: inboundPeerConn, dc: chan, started: new Date().getTime(), last: new Date().getTime(), remoteRTC: rtcRequest};
					if(peer_id in this.#pending_peer_connections) delete this.#pending_peer_connections[peer_id];
					if(this.#onnewconn)
						this.#onnewconn(peer_id); //do normal new connection
				};
				chan.onmessage = async e => this.#onmessage(e.data, peer_id);
				chan.onclose = () => this.#clearConn(peer_id, 'Data channel inboundPeerConn closed');
				chan.onclosing = () => console.log('Data channel inboundPeerConn closing', peer_id);
				chan.onerror = (e) => this.#clearConn(peer_id, 'Data channel inboundPeerConn err '+JSON.stringify(e));
			};
			inboundPeerConn.onclose = () => this.#clearConn(peer_id, 'inboundPeerConn closed');
			let inboundIces = [];
			let answerReady = false;
			let completed = false;
			let completer = (forceit) => {
				if((completed && !forceit) || answerReady === false || (inboundPeerConn.connectionState !== 'connected' && inboundIces.length === 0))
					return;
				console.log('RTC RESPONDER 6/8 Sending RTC answer', JSON.stringify(inboundIces), ' to ', peer_id, ' from ', this.#client_id);
				completed = true;
				
				//now answer other side the ice candidates
				let plaintxt = JSON.stringify({connectToMePlz: inboundIces, description: inboundPeerConn.localDescription});
				let plainbytes = new Uint8Array((new TextEncoder()).encode(plaintxt)); //inner msg bytes
				//Create CODE_CLIENT_RTC_RESPONSE msg for other side
				let rtcrespmsg = new Uint8Array(1 + 4 + 1 + 4 + plainbytes.length);
				rtcrespmsg[0] = CODE_CLIENT_FWD_NOW;
				rtcrespmsg.subarray(1,5).set(new Uint32Array([peer_id]));
				rtcrespmsg[5] = CODE_CLIENT_RTC_RESPONSE;
				rtcrespmsg.subarray(6,10).set(new Uint32Array([this.#client_id]));
				rtcrespmsg.set(plainbytes, 10);
				sock.send(rtcrespmsg);
			};
			inboundPeerConn.onconnectionstatechange = () => {
				console.log('inboundPeerConn onconnectionstatechange',peer_id,inboundPeerConn.connectionState); //'failed' if it dies
				if(inboundPeerConn.connectionState === 'failed' || inboundPeerConn.connectionState === 'disconnected'){
					this.#clearConn(peer_id, 'inboundPeerConn ' + inboundPeerConn.connectionState);
				}else if(inboundPeerConn.connectionState === 'connected'){
					completer(false);
				}
			};
			inboundPeerConn.onsignalingstatechange = e => {
				if(inboundPeerConn.signalingState === 'have-remote-offer')
					console.log('RTC RESPONDER 2/8 peer signaling state change', inboundPeerConn.signalingState, peer_id);
				else if(inboundPeerConn.signalingState === 'stable')
					console.log('RTC RESPONDER 3/8 peer signaling state change', inboundPeerConn.signalingState, peer_id);
				else
					console.log('signaling state change', inboundPeerConn.signalingState, peer_id);
			};
			inboundPeerConn.setRemoteDescription(rtcRequest.description)
				.then(() => inboundPeerConn.createAnswer())
				.then(answer => inboundPeerConn.setLocalDescription(answer)
				.then(() => {
					if(!inboundPeerConn.canTrickleIceCandidates) console.log('RTC RESPONDER WARNING: other side cannot trickle ICE candidates. Nonstandard browser?');
					submitIces(inboundPeerConn, rtcRequest.connectToMePlz);
					answerReady = true;
					completer(false);
				}));
			inboundPeerConn.onicecandidate = e => {
				if(e.candidate && e.candidate.candidate) {
					console.log('RTC RESPONDER 5/8 Peer ICE candidate',e.candidate.candidate, ' ice gathering state ', inboundPeerConn.iceGatheringState, peer_id);
					inboundIces.push(e.candidate);
					if(e.candidate.candidate.indexOf('.local') === -1){
						completer(true);
					}
				}
			};
			inboundPeerConn.onicecandidateerror = e => console.log('RTC RESPONDER ice candidate error '+JSON.stringify(e));
			inboundPeerConn.onicegatheringstatechange = e => console.log('RTC RESPONDER ice gathering state change ', e.target.iceGatheringState);
			inboundPeerConn.oniceconnectionstatechange = e => console.log('RTC RESPONDER ice connection state change ', e.target.iceConnectionState);
		}else if(u8[0] == CODE_CLIENT_RTC_RESPONSE && u8.length > 5){
			const peer_id = new Uint32Array(u8.slice(1,5).buffer)[0];
			const rtcResponse = JSON.parse((new TextDecoder()).decode(u8.subarray(5)));
			if(peer_id in this.#pending_peer_connections){
				console.log('RTC INITIATOR 6/11 CODE_CLIENT_RTC_RESPONSE', rtcResponse, peer_id);
				let followup = () => {
					if(this.#pending_peer_connections[peer_id].rtcpc.connectionState !== 'connected'){
						this.#pending_peer_connections[peer_id].remoteRTC = rtcResponse;
						for(let i = 0; i < rtcResponse.connectToMePlz.length; i++){
							console.log('RTC INITIATOR 8/11 RTC_RESPONSE adding received ICE candidate '+JSON.stringify(rtcResponse.connectToMePlz[i]));
							if(!this.#pending_peer_connections[peer_id].rtcpc.canTrickleIceCandidates) console.log('RTC INITIATOR WARNING: other side cannot trickle ICE candidates. Nonstandard browser?');
							this.#pending_peer_connections[peer_id].rtcpc.addIceCandidate(rtcResponse.connectToMePlz[i]);
						}
					}
				};
				if(this.#pending_peer_connections[peer_id].rtcpc.remoteDescription)
					followup();
				else
					this.#pending_peer_connections[peer_id].rtcpc.setRemoteDescription(rtcResponse.description).then(followup);
			} else {
				console.log('Unknown CODE_CLIENT_RTC_RESPONSE? Not waiting for '+peer_id);
			}
		}else if(u8[0] == CODE_CLIENT_EXIT && u8.length >= 5){//short-circuit close when server tells us
			const peer_id = new Uint32Array(u8.slice(1,5).buffer)[0];//since ID can be immediately reused
			console.log('Client ',peer_id,' exited per server');
			if(peer_id in this.#pending_peer_connections){
				this.#pending_peer_connections[peer_id].rtcpc.close();
				delete this.#pending_peer_connections[peer_id];
			}
			//immediately close peer link. It's likely they closed their webpage/browser, and this will time out eventually
			//but the peer_id is invalid right now and may be re-used leading to bugs if we don't close now.
			//This is kind of sad since there's a rare chance the server just has a bug or died and we could continue strictly
			//peer-to-peer with our webrtc connection... but we can't handle that right now since our addressing is server-based.
			if(peer_id in this.#links){
				this.#links[peer_id].rtcpc.close();
				delete this.#links[peer_id];
			}
			if(this.#client_id !== peer_id && this.#onnodeexit)
				this.#onnodeexit(peer_id);
		}else if(u8[0] == CODE_FULL_LIST){
			if(this.#onnode)
			Array.from(new Uint32Array(u8.slice(1).buffer)).forEach(id=>this.#onnode(id)); //we don't try to reach out here; they should try to reach us
		}
	}

	async #connectto(peer_id, sock){
		if(peer_id in this.#links || peer_id === this.#client_id){
			console.log('already connected to ',peer_id);
			return;
		}else if(peer_id in this.#pending_peer_connections){
			console.log('not trying to reconnect to ',peer_id,' so soon.');
			return;
		}
		if(Object.keys(this.#links).length > 9){ //too many peers, throw out the 10th least recent
			console.log('closing 10th oldest connection');
			Object.values(this.#links).reduce((a,b) => a.last < b.last ? a : b).rtcpc.close();
		}
		console.log('RTC INITIATOR 1/11 seeking to open peer to '+peer_id); 
		let peer = new RTCPeerConnection({iceServers: [{urls:[iceserver]}]});
		let ci = {rtcpc: peer, dc: peer.createDataChannel('peerchan'), started: new Date().getTime(), last: new Date().getTime()};
		setTimeout(()=>{
			if(peer_id in this.#pending_peer_connections && this.#pending_peer_connections[peer_id].started === ci.started){
				console.log('RTC INITIATOR TIMED OUT :-(');
				ci.rtcpc.close();
			}
		},30000);
		this.#pending_peer_connections[peer_id] = ci;
		ci.dc.onopen = () => {
			console.log('RTC INITIATOR 11/11 peer open - to '+peer_id, ci.dc);
			this.#links[peer_id] = ci;
			delete this.#pending_peer_connections[peer_id];
			if(this.#onnewconn)
				this.#onnewconn(peer_id);
		};
		ci.dc.onmessage = async e => this.#onmessage(e.data, peer_id);
		ci.dc.onclose = () => {
			peer.close();
			this.#clearConn(peer_id, 'peer dc closed');
		};
		ci.dc.onclosing = () => console.log('Peer data channel closing', peer_id);
		ci.dc.onerror = (e) => {
			peer.close();
			this.#clearConn(peer_id, 'Peer data channel err '+JSON.stringify(e));
		};
		let ices = [];
		let offerReady = false;
		let completeit = () => {
			if(ices.length === 0 || offerReady === false)
				return;
			console.log('RTC INITIATOR 5/11 telling other side (',peer_id,') ICE candidates',ices);
			//now tell other side the ice candidates
			let plaintxt = JSON.stringify({connectToMePlz: ices, description: peer.localDescription});
			let plainbytes = new Uint8Array((new TextEncoder()).encode(plaintxt)); //inner msg bytes
			let fwdmsg = new Uint8Array(1 + 4 + 1 + 4 + plainbytes.length);
			fwdmsg[0] = CODE_CLIENT_FWD_NOW;
			fwdmsg.subarray(1,5).set(new Uint32Array([peer_id]));
			fwdmsg[5] = CODE_CLIENT_RTC_REQUEST;
			fwdmsg.subarray(6,10).set(new Uint32Array([this.#client_id]));
			fwdmsg.set(plainbytes, 10);
			sock.send(fwdmsg);
		};
		//Once you call setLocalDescription(offer) all the ices will fill up then the promise will resolve
		peer.createOffer().then(offer => peer.setLocalDescription(offer).then(() => {
			offerReady = true;
			console.log('RTC INITIATOR 3/11 ',offer);
			completeit();
		}));
		peer.onicecandidate = e => {
			if(e.candidate && e.candidate.candidate){
				console.log('RTC INITIATOR 4/11 ICE candidate',e.candidate.candidate);
				ices.push(e.candidate);
				if(e.candidate.candidate.indexOf('.local') === -1){
					completeit();
				}
			}
		};
		peer.onicecandidateerror = e => console.log('RTC INITIATOR ice candidate error '+JSON.stringify(e));
		peer.onicegatheringstatechange = e => console.log('RTC INITIATOR ice gathering state change ', e.target.iceGatheringState);
		peer.oniceconnectionstatechange = e => console.log('RTC INITIATOR ice connection state change ', e.target.iceConnectionState);
		peer.onsignalingstatechange = e => {
			if(peer.signalingState === 'have-local-offer')
				console.log('RTC INITIATOR 2/11 peer signaling state change', peer.signalingState, peer_id);
			else if(peer.signalingState === 'stable')
				console.log('RTC INITIATOR 7/11 peer signaling state change', peer.signalingState, peer_id);
			else
				console.log('peer signaling state change', peer.signalingState, peer_id)
		};
		peer.onclose = () => this.#clearConn(peer_id, 'peer RTC close');
		peer.onconnectionstatechange = () => {
			if(peer.connectionState === 'connecting')
				console.log('RTC INITIATOR 9/11 peer onconnectionstatechange',peer.connectionState);
			else if(peer.connectionState === 'connected')
				console.log('RTC INITIATOR 10/11 peer onconnectionstatechange',peer.connectionState);
			else if(peer.connectionState === 'failed' || peer.connectionState === 'disconnected'){
				this.#clearConn(peer_id, 'RTC INITIATOR Peer connection failed or disconnected');
			}else
				console.log('RTC INITIATOR peer onconnectionstatechange',peer.connectionState);
		};
	}
}

export { RtcBroker };
