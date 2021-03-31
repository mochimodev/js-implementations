
// So here is the sha256 hash
function sha256(ascii) {
	function rightRotate(value, amount) {
		return (value>>>amount) | (value<<(32 - amount));
	};
	
	var mathPow = Math.pow;
	var maxWord = mathPow(2, 32);
	var lengthProperty = 'length'
	var i, j; // Used as a counter across the whole file
	var result = ''

	var words = [];
	var asciiBitLength = ascii[lengthProperty]*8;
	
	var hash = sha256.h = sha256.h || [];
	// Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
	var k = sha256.k = sha256.k || [];
	var primeCounter = k[lengthProperty];

	var isComposite = {};
	for (var candidate = 2; primeCounter < 64; candidate++) {
		if (!isComposite[candidate]) {
			for (i = 0; i < 313; i += candidate) {
				isComposite[i] = candidate;
			}
			hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
			k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
		}
	}
	
	ascii += '\x80' // Append Ƈ' bit (plus zero padding)
	while (ascii[lengthProperty]%64 - 56) ascii += '\x00' // More zero padding
	for (i = 0; i < ascii[lengthProperty]; i++) {
		j = ascii.charCodeAt(i);
		if (j>>8) return; // ASCII check: only accept characters in range 0-255
		words[i>>2] |= j << ((3 - i)%4)*8;
	}
	words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
	words[words[lengthProperty]] = (asciiBitLength)


	// process each chunk
	for (j = 0; j < words[lengthProperty];) {
		var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
		var oldHash = hash;
		// This is now the undefinedworking hash", often labelled as variables a...g
		// (we have to truncate as well, otherwise extra entries at the end accumulate
		hash = hash.slice(0, 8);
		
		for (i = 0; i < 64; i++) {
			var i2 = i + j;
			// Expand the message into 64 words
			// Used below if 
			var w15 = w[i - 15], w2 = w[i - 2];

			// Iterate
			var a = hash[0], e = hash[4];
			var temp1 = hash[7]
				+ (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
				+ ((e&hash[5])^((~e)&hash[6])) // ch
				+ k[i]
				// Expand the message schedule if needed
				+ (w[i] = (i < 16) ? w[i] : (
						w[i - 16]
						+ (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
						+ w[i - 7]
						+ (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
					)|0
				);
			// This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
			var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
				+ ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
			
			hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
			hash[4] = (hash[4] + temp1)|0;
		}
		
		for (i = 0; i < 8; i++) {
			hash[i] = (hash[i] + oldHash[i])|0;
		}
	}
    
    ///console.log(hash);

    var how_many_itinerations_done  = 1;

    var bytes_int_result = [];
	
	for (i = 0; i < 8; i++) {
		for (j = 3; j + 1; j--) {
            var b = (hash[i]>>(j*8))&255;

            //console.log(how_many_itinerations_done + ": " + b);
            bytes_int_result.push(b);

            result += ((b < 16) ? 0 : '') + b.toString(16);
            how_many_itinerations_done++;
		}
   	 }
	return bytes_int_result;
};

//I did this to make the code more clean
Array.prototype.toASCII = function () {
	var return_str = "";
	for (var i = 0; i < this.length; i++) {
		return_str += String.fromCharCode(this[i]);
	}
	return return_str; 
}
String.prototype.toBytes = function () {
	var return_bytes = [];
	for (var i = 0; i < this.length; i++) {
		return_bytes.push(this.charCodeAt(i));
	}
	return return_bytes; 
}
Array.prototype.pushArray = function(arr) {
    this.push.apply(this, arr);
};

// NOW THERE ARE THE DEFINITIONS

var PARAMSN = 32;
var WOTSW = 16;
var WOTSLOGW = 4;
var WOTSLEN1 = (8 * PARAMSN / WOTSLOGW);
var WOTSLEN2 = 3;
var WOTSLEN  = WOTSLEN1 + WOTSLEN2;
var WOTSSIGBYTES = WOTSLEN * PARAMSN;

/* 2144 + 32 + 32 = 2208 */
var TXSIGLEN  = 2144;
var TXADDRLEN = 2208;

var XMSS_HASH_PADDING_F = 0;
var XMSS_HASH_PADDING_PRF = 3;

var addr = {} //lol I know thats hard-coded

/* the seed is the private key. The seed its 32 bytes of 8 bits each */
function public_key_gen(seed, pub_seed) {
    console.log("generating a private key....");
    var private_key = expand_seed(seed); // I don't know if this is really the private key. Boh
	console.log("finished expand seed");
	var cache_pk = [];
	for (var i = 0; i < WOTSLEN; i++) {
		set_chain_addr(i); //here is not in byte array format cause I think I dont necessarly have to
    
		var priv_key_portion = private_key.slice(i*PARAMSN, PARAMSN + i*PARAMSN);
		var array_to_push = gen_chain(priv_key_portion, 0, WOTSW - 1, pub_seed );

		cache_pk.pushArray(array_to_push);
	}
	///console.log("final public key: " + cache_pk.toString());
	return cache_pk;
}

function wots_sign(msg, seed, pub_seed) {
	var lenghts = []; //its WOTSLEN long (67)
	var signature = [];
	lenghts = chain_lenghts(msg);

	/* the wots private key comes from the seed*/
	var private_key = expand_seed(seed); // this is the private key

	for(var i = 0; i < WOTSLEN; i++) {
		set_chain_addr(i);
		var priv_key_portion = private_key.slice(i*PARAMSN, PARAMSN + i*PARAMSN);
		var array_to_push = gen_chain(priv_key_portion, 0, lenghts[i], pub_seed );
		signature.pushArray(array_to_push);
	}
	///console.log("signature of WOTS_sign: " + signature);
	return signature;
}

function wots_publickey_from_sig(sig, msg, pub_seed) {
	var lenghts = []; //array of WOTSLEN size
	lenghts = chain_lenghts(msg);

	var public_key = [];
	for(var i = 0; i < WOTSLEN; i++) {
		set_chain_addr(i);
		var signature_portion = sig.slice(i*PARAMSN, PARAMSN + i*PARAMSN);
		public_key.pushArray(gen_chain(signature_portion, lenghts[i], WOTSW - 1 - lenghts[i], pub_seed));
	}
	return public_key;
}

function expand_seed(seed) {
    var ctr = []; //This will be max 32 items
    var out_seeds = []; //This will be maximum with WOTSLEN items
	console.log("WOTSLEN: " + WOTSLEN.toString());
    for(var i = 0; i < WOTSLEN; i++) {

        ctr = ull_to_bytes(PARAMSN, [i]); //yeah I hope "i" doesnt go more than 255
		out_seeds.pushArray(prf(ctr, seed));
    }
	return out_seeds;
}

function ull_to_bytes(outlen, input) {
	var out = []
	for (var i = outlen - 1; i >= 0; i--) {
        out[i] = input & 0xff;
        input = input >> 8;
    }
	return out;
}

/*
in its a 32 byte array
key its a number
*/
function prf(input, key) {
    var buf = [];
    buf = ull_to_bytes(PARAMSN, [XMSS_HASH_PADDING_PRF]); // 32 and 3

	var byte_copied_key = byte_copy(key, PARAMSN);
	buf.pushArray(byte_copied_key);
	
	var byte_copied_input = byte_copy(input,32);
	buf.pushArray(byte_copied_input);

	//I am dubios of this but should theoretically work as expected
	return sha256(buf.toASCII());
}
function t_hash(input, pub_seed) {
	var buf = []; // maximuym lenght 3*PARAMSN
	var bitmask = []; //maximum lenght PARAMSN
	var addr_as_bytes = []; //maximum lenght 32

	var buf = ull_to_bytes(PARAMSN, [XMSS_HASH_PADDING_F]);
	
	/* generate n-byte key */
	set_key_and_mask(0);
	addr_as_bytes = addr_to_bytes();
	var to_push_buf = prf(addr_as_bytes, pub_seed);
	buf.pushArray(to_push_buf);

	/*generate the n-byte mask */
	set_key_and_mask(1);
	addr_as_bytes = addr_to_bytes();
	var bitmask = prf(addr_as_bytes, pub_seed);

	var XOR_bitmask_input = []; 
	for(var i = 0; i < PARAMSN; i++) {
		XOR_bitmask_input.push(input[i] ^ bitmask[i]);
	}
	buf.pushArray(XOR_bitmask_input);
	return sha256(buf.toASCII());
}

function byte_copy(source, num_bytes) {
    var output = []
    for(var i = 0; i < num_bytes; i++) {
		output.push(source[i]);
    }
	return output;
}

function gen_chain(input, start, steps, pub_seed) {
	var out = byte_copy(input, PARAMSN);
	
	for ( var i = start; i < (start+steps) && i < WOTSW; i++) {
		set_hash_addr(i);
		out = t_hash(out, pub_seed);
	}
	return out;
}

/*
This works only if log_w is a divisor of 8!
*/
function base_w(outlen, input) {
	/*
	if(8 % WOTSLOGW != 0) {
		console.log("SECURITY PROBLEM! WOTSLOGW MUST BE A DIVISOR OF 8!");
	}
	thinking about then making an upper library that handles all those functions with objects, so I check that automatically
	*/
	var in_ = 0;
	var out = 0;
	var total; // I am not sure about this one
	var bits = 0;
	var output = [];
	for(var consumed = 0; consumed < outlen; consumed++) {
		if(bits == 0) {
			total = input[in_];
			in_ ++;
			bits += 8;
		}
		bits -= WOTSLOGW;
		output[out] = (total >> bits) & (WOTSW - 1);
		out++;
	}
	console.log("base_w output: " + output.toString());
	return output;
}
function wots_checksum(msg_base_w) {
	var csum = 0;
	var csum_bytes = []; //array of size (WOTSLEN2 * WOTSLOGW + 7) / 8 = (12 + 7) / 8 --> mhhhhhhh
	for (var i = 0; i < WOTSLEN1; i++) {
		csum += WOTSW - 1 - msg_base_w[i];
	}

	/* convert checksum to base_w */
	csum << (8 - ((WOTSLEN2 * WOTSLOGW) % 8));
	csum_bytes = ull_to_bytes(Math.round((WOTSLEN2 * WOTSLOGW + 7) / 8), csum);
	console.log("csum bytes: " + csum_bytes.toString());
	var csum_base_w = base_w(WOTSLEN2, csum_bytes);
	console.log("csum base_W : " + csum_base_w.toString());
	return csum_base_w;
}
function chain_lenghts(msg) {
	var lenghts = base_w(WOTSLEN1, msg);
	lenghts.pushArray(wots_checksum(lenghts));
	console.log("lenghts: " + lenghts.toString());
	return lenghts;
}

function set_chain_addr(chain_address) { //this should be 32 byte variable
	addr["5"] = chain_address; //yeah hard coded but its ok bro
}
function set_hash_addr(hash) {
	addr["6"] = hash;
}
function set_key_and_mask(key_and_mask) {
	addr["7"] = key_and_mask;
}
function addr_to_bytes() {
	var out_bytes = [];
	for(var i = 0; i < 8; i++) {
		if(addr[(i.toString())] == undefined) {
			addr[i.toString()] = 0;
		}
		var to_push = ull_to_bytes(4, [addr[(i.toString())]] );
		out_bytes.pushArray(to_push);
	}
	return out_bytes;
}

var seed = sha256("my super input 1");
var pub_seed = sha256("super input");
var message = "I'm a message";
message = message.toBytes();
console.log("message: " + message.toString());

var signature = wots_sign(message, seed, pub_seed);
var pk = public_key_gen(seed, pub_seed);
var pub_key = wots_publickey_from_sig(signature, message, pub_seed);

console.log("pub seed original ");
console.log(pk);

console.log("pub key from sig");
console.log(pub_key);


/*
from: https://stackoverflow.com/a/16436975
*/
function arraysEqual(a, b) {
	if (a === b) return true;
	if (a == null || b == null) return false;
	if (a.length !== b.length) return false;
  
	// If you don't care about the order of the elements inside
	// the array, you should sort both arrays here.
	// Please note that calling sort on an array will modify that array.
	// you might want to clone your array first.
  
	for (var i = 0; i < a.length; ++i) {
	  if (a[i] !== b[i]) return false;
	}
	return true;
}

if(arraysEqual(pk, pub_key)) {
	console.log("WORKSSS!!!!!!")
}
