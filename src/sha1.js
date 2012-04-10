/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

goog.provide('SHA1');

goog.require('goog.crypt.Hmac');
goog.require('goog.crypt.Sha1');

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */

/** @type {number} */
SHA1.hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */

/** @type {string} */
SHA1.b64pad  = '='; /* base-64 pad character. "=" for strict RFC compliance   */

/** @type {number} */
SHA1.chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */

/**
 * @param {string} s
 * @return {string}
 */
SHA1.hex_sha1 = function(s) {
    return SHA1.binb2hex(SHA1.core_sha1(SHA1.str2binb(s),s.length * SHA1.chrsz));
};

/**
 * @param {string} s
 * @return {string}
 */
SHA1.b64_sha1 = function(s) {
    return SHA1.binb2b64(SHA1.core_sha1(SHA1.str2binb(s),s.length * SHA1.chrsz));
};

/**
 * @param {string} s
 * @return {string}
 */
SHA1.str_sha1 = function(s) {
    return SHA1.binb2str(SHA1.core_sha1(SHA1.str2binb(s),s.length * SHA1.chrsz));
};

/**
 * @param {Array.<number>} key
 * @param {Array.<number>} data
 * @return {string}
 */
SHA1.hex_hmac_sha1 = function(key, data) {
    return SHA1.binb2hex(SHA1.core_hmac_sha1(key, data));
};


/**
 * @param {Array.<number>|string} key
 * @param {Array.<number>|string} data
 * @return {string}
 */
SHA1.b64_hmac_sha1 = function(key, data) {
    return SHA1.binb2b64(SHA1.core_hmac_sha1(key, data));
};


/**
 * @param {Array.<number>|string} key
 * @param {Array.<number>|string} data
 * @return {string}
 */
SHA1.str_hmac_sha1 = function(key, data) {
    return SHA1.binb2str(SHA1.core_hmac_sha1(key, data));
};

/**
 * Perform a simple self-test to see if the VM is working
 * @return {boolean}
 */
SHA1.sha1_vm_test = function() {
  return SHA1.hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
};

/**
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 *
 * @param {Array.<number>} x
 * @param {number} len
 * @return {Array.<number>}
 */
SHA1.core_sha1 = function(x, len) {
    //var sha1 = new goog.crypt.Sha1();
    //sha1.update(x, len);
    //return sha1.digest();
    return [];
};

/**
 * Calculate the HMAC-SHA1 of a key and some data
 *
 * @param {Array.<number>|string} key
 * @param {Array.<number>|string} data
 * @return {Array.<number>}
 */
SHA1.core_hmac_sha1 = function(key, data) {
    //var sha1 = new goog.crypt.Sha1(),
    //    hmac = new goog.crypt.Hmac(sha1, key);
    //return hmac.getHmac(data);
    return [];
};

/**
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 *
 * @param {string} str
 * @return {Array.<number>}
 */
SHA1.str2binb = function(str) {
  var bin = [];
  var mask = (1 << SHA1.chrsz) - 1;
  for (var i = 0; i < str.length * SHA1.chrsz; i += SHA1.chrsz) {
    bin[i>>5] |= (str.charCodeAt(i / SHA1.chrsz) & mask) << (32 - SHA1.chrsz - i%32);
  }
  return bin;
};

/**
 * Convert an array of big-endian words to a string
 *
 * @param {Array.<number>} bin
 * @return {string}
 */
SHA1.binb2str = function(bin) {
  var str = "";
  var mask = (1 << SHA1.chrsz) - 1;
  for (var i = 0; i < bin.length * 32; i += SHA1.chrsz) {
    str += String.fromCharCode((bin[i>>5] >>> (32 - SHA1.chrsz - i%32)) & mask);
  }
  return str;
};

/**
 * Convert an array of big-endian words to a hex string.
 *
 * @param {Array.<number>} binarray
 * @return {string}
 */
SHA1.binb2hex = function(binarray) {
  var hex_tab = SHA1.hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for (var i = 0; i < binarray.length * 4; i++) {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
};

/**
 * Convert an array of big-endian words to a base-64 string
 *
 * @param {Array.<number>} binarray
 * @return {string}
 */
SHA1.binb2b64 = function(binarray) {
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  var triplet, j;
  for (var i = 0; i < binarray.length * 4; i += 3) {
    triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16) |
              (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 ) |
               ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for (j = 0; j < 4; j++)
    {
      if (i * 8 + j * 6 > binarray.length * 32) { str += SHA1.b64pad; }
      else { str += tab.charAt((triplet >> 6*(3-j)) & 0x3F); }
    }
  }
  return str;
};
