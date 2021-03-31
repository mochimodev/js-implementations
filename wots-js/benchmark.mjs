/*
Theese are the benchmarks of my code. There is still room for improvement.
For example:
 - get a faster sha256 hashing function
 - use a different way for byte manipulation other than a byte array
 - and more

 For any question don't hesitate to contact me on Discord NickP05#6940
*/
import {wots_public_key_gen, wots_sign, wots_publickey_from_sig} from 'wots.min.mjs';
// theoretically the path should be in ./modules/wots.min.mjs              ^

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


var seed = sha256("secret input");
var pub_seed = sha256("another input");
var address = sha256("putherewhateveryouwant"); 

var message = "Hello World";
message = message.toBytes();

console.log("stating benchmark x100 for each function");

var signature = wots_sign(message, seed, pub_seed, address);
console.time('wots_sign x100');
for(var iter = 0; iter<100; iter++) {
    var signature = wots_sign(message, seed, pub_seed, address);
}
console.timeEnd('wots_sign x100');

console.time('wots_public_key_gen x100');
for(var iter = 0; iter<100; iter++) {
    var pk = wots_public_key_gen(seed, pub_seed, address );
}
console.timeEnd('wots_public_key_gen x100');

console.time('wots_publickey_from_sig x100');
for(var iter = 0; iter<100; iter++) {
    var pub_key = wots_publickey_from_sig(signature, message, pub_seed, address);
}
console.timeEnd('wots_publickey_from_sig x100');

console.log("benchmark finished");
