//Functions for efficient binary serialization or base64 conversion

//simple int packing into compressed binary, kind of like utf-8, messagepack, or protobufs
function pack(number) {
  let retarr = [];
  do {
    retarr.push(number < 128 ? number : number % 128 | 128);
    number = (number - (number % 128)) / 128;
  } while (number > 0);
  return new Uint8Array(retarr);
}

//simple int unpacking. Returns the int and the rest of the array for ease in parsing
function unpack(u8arr) {
  let number = 0;
  let offset = 1;
  let current = u8arr[0];
  do {
    current = u8arr[0];
    number += offset * (current & 127);
    u8arr = u8arr.subarray(1);
    offset *= 128;
  } while (current >= 128);
  return [number, u8arr];
}

//base64 conversion for Uint8Array's
function b64encode(x) { 
	return btoa(Array.from(x).map((v) => String.fromCharCode(v)).join(''));
}

function b64decode(x) {
	return new Uint8Array(atob(x).split('').map((v) => v.codePointAt(0)));
}

//splitting and combining Uint8Array's
function splice(array, index){
	return [array.subarray(0, index), array.subarray(index)];
}

function concat(...args){
	let combined = new Uint8Array(args.reduce((a,b)=>a+b.length,0)); //make a buf big enough for all
	args.reduce((a,b)=>{
		combined.set(b, a); //now copy them in
		return a+b.length;
	},0);
	return combined;
}

export { pack, unpack, b64encode, b64decode, splice, concat };
