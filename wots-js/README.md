# WOTS-JS

Javascript implementation of WOTS+ signature. Inspired 99% by https://github.com/mochimodev/mochimo/tree/master/src/crypto/wots code owned by Adequate Systems. 
The thing should work, I do not give warranty but seems pretty obvious that works and is theoretically secure as WOTS+ algorithm is.
Credits to @stackoverflo on Discord (founder of Mochimo crypto), Matt Zweil, for explaining me the C code and helping me understanding.

I'm on Discord NickP05#6940 for any question or request.

Mochimo Discord server: https://discord.gg/39KNMbfXyX
(they are always helpful, give it a try)

## How to use the code:

### Generate a WOTS+ public key:
 > wots_public_key_gen(seed, pub_seed, addr)
 
 Where:
  - seed is a secret 32 bytes (8 bits each) decimal array (so values from 0 to 255)
  - pub_seed is a public 32 bytes (8 bits each) decimal array (0..255)
  - addr is a public 32 bytes, the last 12 will be overwritten, decimal array (0..255)
    addr can be whatever you want. It doesn't impact security in the Mochimo crypto, but remember the last 12 bytes will be used for the TAG
  It returns a 2144 bytes (0..255) decimal array which is the WOTS+ public key.

### Generate a WOTS+ signature:
  > wots_sign(message, seed, pub_seed, addr)
  
  Where:
   - message is the decimal array (0..255) of bytes you need to sign
   - seed is a secret 32 bytes (8 bits each) decimal array (so values from 0 to 255)
   - pub_seed is a public 32 bytes (8 bits each) decimal array (0..255)
   - addr is a public 32 bytes decimal array (0..255)
   Of course seed, pub_seed and addr must be the same as the ones used to generate the public key, to make the signature valid.

### Validate a WOTS+ signature:
  > wots_publickey_from_sig(signature, message, pub_seed, addr)
  
  Where:
   - signature is a 2144 bytes decimal array (0..255)
   - message is the decimal array (0..255) of bytes you need to sign
   - pub_seed is a public 32 bytes (8 bits each) decimal array (0..255)
   - addr is a public 32 bytes decimal array (0..255)
   
This code is licensed under the Mochimo Cryptocurrency Engine License Agreement Version 1.0.  See LICENSE.PDF.
