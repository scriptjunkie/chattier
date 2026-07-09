import { pack, unpack, b64encode, b64decode, splice, concat } from './bits.js';
const KEY_LENGTH = 65;

// Derive AES-GCM wrapping key from password + salt (shared by key and blob helpers)
async function wrapping_key_from_password(password, salt) {
	const pbkdfKey = await crypto.subtle.importKey('raw', (new TextEncoder()).encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
	return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, pbkdfKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// Encrypt an arbitrary JSON-serializable object. Plaintext is length-prefixed and
// padded with random bytes to a multiple of block_size so ciphertext size does not leak object length.
async function encrypt_blob_with_password(obj, password, block_size) {
	if (!(block_size > 0) || (block_size | 0) !== block_size) {
		throw new Error('block_size must be a positive integer');
	}
	const plaintext = new TextEncoder().encode(JSON.stringify(obj));
	const length_prefix = pack(plaintext.length);
	const unpadded_len = length_prefix.length + plaintext.length;
	const pad_len = (block_size - (unpadded_len % block_size)) % block_size;
	const padded = concat(length_prefix, plaintext, crypto.getRandomValues(new Uint8Array(pad_len)));
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const wrappingKey = await wrapping_key_from_password(password, salt);
	const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, padded);
	return b64encode(new Uint8Array(await (new Blob([salt, iv, wrapped])).arrayBuffer()));
}

// Decrypt a blob produced by encrypt_blob_with_password; returns the original object.
async function decrypt_blob_with_password(encrypted, password) {
	const enckbin = b64decode(encrypted);
	const salt = enckbin.subarray(0, 16);
	const iv = enckbin.subarray(16, 32);
	const wrappingKey = await wrapping_key_from_password(password, salt);
	const dewrapped = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, enckbin.subarray(32)));
	let inner_length, rest;
	[inner_length, rest] = unpack(dewrapped);
	const [json_bytes] = splice(rest, inner_length);
	return JSON.parse(new TextDecoder().decode(json_bytes));
}

async function decrypt_keys_with_password(encryptedKey, password){
	const enckbin = b64decode(encryptedKey);
	const salt = enckbin.subarray(0,16);
	const iv = enckbin.subarray(16,32);
	const wrappingKey = await wrapping_key_from_password(password, salt);
	const exported_k = enckbin.subarray(32);
	const dewrapped = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, wrappingKey, exported_k);
	const {data, exported} = JSON.parse(new TextDecoder().decode(dewrapped));
	const ecdh_privkey = await crypto.subtle.importKey('pkcs8', b64decode(exported), { name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
	//Convert private ECDH key to public key by exporing as JWK and deleting 'd'
	let ecdh_priv_jwk = await crypto.subtle.exportKey('jwk', ecdh_privkey);
	let ecdh_pub_jwk = JSON.parse(JSON.stringify(ecdh_priv_jwk)); //make a deep copy by serializing/unserializing
	delete ecdh_pub_jwk['d'];
	let ecdh_pubkey = await crypto.subtle.importKey('jwk', ecdh_priv_jwk, {name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
	//Convert to ECDSA key by changing 'key_ops' and setting 'alg' in JWK
	ecdh_priv_jwk['alg'] = 'ES256';
	ecdh_priv_jwk['key_ops']=['sign'];
	let ecdsa_privkey = await crypto.subtle.importKey('jwk', ecdh_priv_jwk, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign']);
	delete ecdh_priv_jwk['d'];
	ecdh_priv_jwk['key_ops']=['verify'];
	let ecdsa_pubkey = await crypto.subtle.importKey('jwk', ecdh_priv_jwk, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
	const pubraw = new Uint8Array(await crypto.subtle.exportKey('raw', ecdsa_pubkey));//my pub key as arraybuffer
	const pub64 = b64encode(pubraw);
	return {ecdh: {privateKey: ecdh_privkey, publicKey: ecdh_pubkey}, ecdsa: {privateKey: ecdsa_privkey, publicKey: ecdsa_pubkey}, pubraw, pub64, data};
}

async function encrypt_keys_with_password(key, password, data){
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const wrappingKey = await wrapping_key_from_password(password, salt);
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const exported = b64encode(new Uint8Array(await crypto.subtle.exportKey('pkcs8', key)));
	const bin = new TextEncoder().encode(JSON.stringify({data, exported}));
	const wrapped = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, wrappingKey, bin);
	const wrappedblob = new Blob([salt, iv, wrapped]);
	return b64encode(new Uint8Array(await wrappedblob.arrayBuffer()));
}

async function generate(){
	const ecdh_keypair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
	let ecdh_priv_jwk = await crypto.subtle.exportKey('jwk', ecdh_keypair.privateKey);
	ecdh_priv_jwk['alg'] = 'ES256';
	ecdh_priv_jwk['key_ops']=['sign'];
	const ecdsa_privkey = await crypto.subtle.importKey('jwk', ecdh_priv_jwk, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign']);
	delete ecdh_priv_jwk['d'];
	ecdh_priv_jwk['key_ops']=['verify'];
	const ecdsa_pubkey = await crypto.subtle.importKey('jwk', ecdh_priv_jwk, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
	const pubraw = new Uint8Array(await crypto.subtle.exportKey('raw', ecdsa_pubkey));//my pub key as Uint8Array
	const pub64 = b64encode(pubraw);
	return {ecdh: ecdh_keypair, ecdsa: {privateKey: ecdsa_privkey, publicKey: ecdsa_pubkey}, pubraw, pub64};
}

async function shared_secret(publicKey, privateKey){
	const ssbits = await crypto.subtle.deriveBits({ name:'ECDH', public: publicKey }, privateKey, 128);
	return await crypto.subtle.importKey('raw', ssbits, { name: 'AES-GCM', length: 128 },true,['encrypt', 'decrypt']);
}

//wraps to a given pubkey using a given privkey. Assumes they know what our pubkey is.
async function wrap_to(plainbytes, publicKey, privateKey){
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const sharedsecret = await shared_secret(publicKey, privateKey);
	const encd = await crypto.subtle.encrypt({ name: 'aes-gcm', iv: iv }, sharedsecret, plainbytes);
	return new Uint8Array(await (new Blob([iv, encd])).arrayBuffer());
}

//seals to a given pubkey by generating a random keypair and wrapping to the pubkey with it.
async function seal_to(plainbytes, public_raw){
	const ecdh_keypair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']);
	const pk = new Uint8Array(await crypto.subtle.exportKey('raw', ecdh_keypair.publicKey));
	const imported_pub = await crypto.subtle.importKey('raw', public_raw, {name: 'ECDH', namedCurve: 'P-256'}, true, []);
	return concat(pk, await wrap_to(plainbytes, imported_pub, ecdh_keypair.privateKey));
}

async function unseal(sealed, privateKey){
	let pub_keyraw, ciphertext_iv, iv, ciphertext;
	[pub_keyraw, ciphertext_iv] = splice(sealed, KEY_LENGTH);
	[iv, ciphertext] = splice(ciphertext_iv, 16);
	const publicKey = await crypto.subtle.importKey('raw', pub_keyraw, { name: 'ECDH', namedCurve: 'P-256'}, true, []);
	const sharedsecret = await shared_secret(publicKey, privateKey);
	return new Uint8Array(await crypto.subtle.decrypt({ name: 'aes-gcm', iv: iv }, sharedsecret, ciphertext));
}

//64 bytes signature
async function sign(data, privateKey){
	return new Uint8Array(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, privateKey, data));
}

//returns true/false
async function verify(data, sig, publicKey){
	return await crypto.subtle.verify({name: 'ECDSA', hash: 'SHA-256'}, publicKey, sig, data);
}

export { generate, encrypt_keys_with_password, decrypt_keys_with_password, encrypt_blob_with_password, decrypt_blob_with_password, wrap_to, seal_to, unseal, sign, verify };
