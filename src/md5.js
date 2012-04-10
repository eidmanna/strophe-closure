/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

goog.provide('MD5');

goog.require('goog.crypt.Hmac');
goog.require('goog.crypt.Md5');

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */

/** @type {number} */
MD5.hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase */

/** @type {number} */
MD5.chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode */

/**
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 *
 * @param {string} str
 * @return {Array.<number>}
 */
MD5.str2binl = function (str) {
    var bin = [];
    var mask = (1 << MD5.chrsz) - 1;
    for(var i = 0; i < str.length * MD5.chrsz; i += MD5.chrsz)
    {
        bin[i>>5] |= (str.charCodeAt(i / MD5.chrsz) & mask) << (i%32);
    }
    return bin;
};

/**
 * Convert an array of little-endian words to a string
 *
 * @param {Array.<number>} bin
 * @return {string}
 */
MD5.binl2str = function (bin) {
    var str = "";
    var mask = (1 << MD5.chrsz) - 1;
    for(var i = 0; i < bin.length * 32; i += MD5.chrsz)
    {
        str += String.fromCharCode((bin[i>>5] >>> (i % 32)) & mask);
    }
    return str;
};

/**
 * Convert an array of little-endian words to a hex string.
 *
 * @param {Array.<number>} binarray
 * @return {string}
 */
MD5.binl2hex = function (binarray) {
    var hex_tab = MD5.hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for(var i = 0; i < binarray.length * 4; i++)
    {
        str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
            hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
    }
    return str;
};

/**
 * Calculate the MD5 of an array of little-endian words, and a bit length
 *
 * @param {Array.<number>} x
 * @param {number} len
 * @return {Array.<number>}
 */
MD5.core_md5 = function (x, len) {
    var md5 = new goog.crypt.Md5();
    md5.update(x, len);
    return md5.digest();
};

/**
 * Calculate the HMAC-MD5, of a key and some data
 *
 * @param {Array.<number>} key
 * @param {Array.<number>} data
 * @return {Array.<number>}
 */
MD5.core_hmac_md5 = function (key, data) {
    var md5  = new goog.crypt.Md5(),
        hmac = new goog.crypt.Hmac(md5, key);
    return hmac.getHmac(data);
};

/**
 * These are the functions you'll usually want to call.
 * They take string arguments and return either hex or base-64 encoded
 * strings.
 *
 * @param {string} s
 * @return {string}
 */
MD5.hexdigest = function (s) {
    return MD5.binl2hex(MD5.core_md5(MD5.str2binl(s), s.length * MD5.chrsz));
},

/**
 * @param {string} s
 * @return {string}
 */
MD5.hash = function (s) {
    return MD5.binl2str(MD5.core_md5(MD5.str2binl(s), s.length * MD5.chrsz));
},

/**
 * Perform a simple self-test to see if the VM is working
 * @return {boolean}
 */
MD5.test = function () {
    return MD5.hexdigest("abc") === "900150983cd24fb0d6963f7d28e17f72";
}
