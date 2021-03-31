import {wots_public_key_gen, wots_sign, wots_publickey_from_sig} from 'wots.mjs'; 
// theoretically the path should be in ./modules/wots.mjs              ^

/*
Minified version. 
From https://geraintluff.github.io/sha256/
*/
function sha256(r){function h(r,h){return r>>>h|r<<32-h}for(var t,n,o=Math.pow,a=o(2,32),
e=[],f=8*r.length,l=sha256.h=sha256.h||[],g=sha256.k=sha256.k||[],s=g.length,c={},i=2;s<64;i++)
if(!c[i]){for(t=0;t<313;t+=i)c[t]=i;l[s]=o(i,.5)*a|0,g[s++]=o(i,1/3)*a|0}for(r+="";r.length%64-56;)r+="\0";for(t=0;t<r.length;t++){if((n=r.charCodeAt(t))>>8)return;
e[t>>2]|=n<<(3-t)%4*8}for(e[e.length]=f/a|0,e[e.length]=f,n=0;n<e.length;){var u=e.slice(n,n+=16),v=l;for(l=l.slice(0,8),t=0;t<64;t++)
{var k=u[t-15],p=u[t-2],d=l[0],w=l[4],A=l[7]+(h(w,6)^h(w,11)^h(w,25))+(w&l[5]^~w&l[6])+g[t]+(u[t]=t<16?u[t]:u[t-16]+(h(k,7)^h(k,18)^k>>>3)+u[t-7]+(h(p,17)^h(p,19)^p>>>10)|0);
(l=[A+((h(d,2)^h(d,13)^h(d,22))+(d&l[1]^d&l[2]^l[1]&l[2]))|0].concat(l))[4]=l[4]+A|0}for(t=0;t<8;t++)l[t]=l[t]+v[t]|0}var C=[];
for(t=0;t<8;t++)for(n=3;n+1;n--){var M=l[t]>>8*n&255;C.push(M),(M<16?0:"")+M.toString(16),0}return C}

//Theese 3 variables should be 32 bytes long.
//For demonstrative purposes I won't paste here any byte array, but generate it with
// sha256() function, which is the same in wots.mjs
var seed = sha256("secret input");
var pub_seed = sha256("another input");
var address = sha256("putherewhateveryouwant"); 
// ^^ 
//the address doesn't need to be random or so, you can put whatever you want
//remember the last 12 bytes of the address are the tag, if you want to use a tag just
//overwrite them

var message = "Hello World"; //Here again, the thing to be signed should be the bytes.
message = message.toBytes();
console.log("message: " + message.toString());

var signature = wots_sign(message, seed, pub_seed, address);
var pk = wots_public_key_gen(seed, pub_seed, address );
var pub_key = wots_publickey_from_sig(signature, message, pub_seed, address);

console.log("public key original ");
console.log(pk);

console.log("public key from signature ");
console.log(pub_key);

console.log("signature");
console.log(signature);

/*
from: https://stackoverflow.com/a/16436975

This function checks if the two arrays are equal. If so, the signature is valid.
*/
function arraysEqual(a, b) {
	if (a === b) return true;
	if (a == null || b == null) return false;
	if (a.length !== b.length) return false;
  
	for (var i = 0; i < a.length; ++i) {
	  if (a[i] !== b[i]) return false;
	}
	return true;
}
if(arraysEqual(pk, pub_key)) {
    console.log("The signature is valid");
}
