/*
    This program is distributed under the terms of the MIT license.
    Please see the LICENSE file for details.

    Copyright 2006-2008, OGG, LLC
*/

/*
 *  A JavaScript library for XMPP BOSH.
 *
 *  This is the JavaScript version of the Strophe library.  Since JavaScript
 *  has no facilities for persistent TCP connections, this library uses
 *  Bidirectional-streams Over Synchronous HTTP (BOSH) to emulate
 *  a persistent, stateful, two-way connection to an XMPP server.  More
 *  information on BOSH can be found in XEP 124.
 */

goog.provide('Strophe');
goog.provide('Strophe.Builder');
goog.provide('Strophe.Connection');
goog.provide('Strophe.XHTML');

goog.require('goog.array');
goog.require('goog.crypt');
goog.require('goog.crypt.Hmac');
goog.require('goog.crypt.Md5');
goog.require('goog.crypt.Sha1');
goog.require('goog.crypt.base64');
goog.require('goog.debug.Logger');
goog.require('goog.dom');
goog.require('goog.dom.xml');
goog.require('goog.net.XhrIo');
goog.require('goog.net.XmlHttp');
goog.require('goog.string');

/** @define {boolean} */
Strophe.ENABLE_DIGEST_MD5  = true;

/** @define {boolean} */
Strophe.ENABLE_SCRAM_SHA_1 = false;

/** @define {boolean} */
Strophe.ENABLE_PLAIN       = false;

/** @define {boolean} */
Strophe.ENABLE_ANONYMOUS   = false;

/** @define {boolean} */
Strophe.ENABLE_LEGACY_AUTH = false;

/**
 *  Create a Strophe.Builder.
 *  This is an alias for 'new Strophe.Builder(name, attrs)'.
 *
 * @param {string} name - The root element name.
 * @param {Object=} attrs - The attributes for the root element in object notation.
 *
 * @return {Strophe.Builder}
 */
function $build(name, attrs) { return new Strophe.Builder(name, attrs); }

/**
 *  Create a Strophe.Builder with a <message/> element as the root.
 *
 * @param {Object=} attrs - The <message/> element attributes in object notation.
 *
 * @return {Strophe.Builder}
 */
function $msg(attrs) { return new Strophe.Builder('message', attrs); }

/**
 *  Create a Strophe.Builder with an <iq/> element as the root.
 *
 * @param {Object=} attrs - The <iq/> element attributes in object notation.
 *
 * @return {Strophe.Builder}
 */
function $iq(attrs) { return new Strophe.Builder('iq', attrs); }

/**
 *  Create a Strophe.Builder with a <presence/> element as the root.
 *
 * @param {Object=} attrs - The <presence/> element attributes in object notation.
 *
 * @return {Strophe.Builder}
 */
function $pres(attrs) { return new Strophe.Builder('presence', attrs); }

/**
 * @type {string}
 * The version of the Strophe library. Unreleased builds will have
 * a version of head-HASH where HASH is a partial revision.
 */
Strophe.VERSION = '@VERSION@';

/**
 * @enum {string}
 * Common namespace constants from the XMPP RFCs and XEPs.
 *
 * NS.HTTPBIND - HTTP BIND namespace from XEP 124.
 * NS.BOSH - BOSH namespace from XEP 206.
 * NS.CLIENT - Main XMPP client namespace.
 * NS.AUTH - Legacy authentication namespace.
 * NS.ROSTER - Roster operations namespace.
 * NS.PROFILE - Profile namespace.
 * NS.DISCO_INFO - Service discovery info namespace from XEP 30.
 * NS.DISCO_ITEMS - Service discovery items namespace from XEP 30.
 * NS.MUC - Multi-User Chat namespace from XEP 45.
 * NS.SASL - XMPP SASL namespace from RFC 3920.
 * NS.STREAM - XMPP Streams namespace from RFC 3920.
 * NS.BIND - XMPP Binding namespace from RFC 3920.
 * NS.SESSION - XMPP Session namespace from RFC 3920.
 * NS.XHTML_IM - XHTML-IM namespace from XEP 71.
 * NS.XHTML - XHTML body namespace from XEP 71.
 */
Strophe.NS = {
    HTTPBIND: 'http://jabber.org/protocol/httpbind',
    BOSH: 'urn:xmpp:xbosh',
    CLIENT: 'jabber:client',
    AUTH: 'jabber:iq:auth',
    ROSTER: 'jabber:iq:roster',
    PROFILE: 'jabber:iq:profile',
    DISCO_INFO: 'http://jabber.org/protocol/disco#info',
    DISCO_ITEMS: 'http://jabber.org/protocol/disco#items',
    MUC: 'http://jabber.org/protocol/muc',
    SASL: 'urn:ietf:params:xml:ns:xmpp-sasl',
    STREAM: 'http://etherx.jabber.org/streams',
    BIND: 'urn:ietf:params:xml:ns:xmpp-bind',
    SESSION: 'urn:ietf:params:xml:ns:xmpp-session',
    VERSION: 'jabber:iq:version',
    STANZAS: 'urn:ietf:params:xml:ns:xmpp-stanzas',
    XHTML_IM: 'http://jabber.org/protocol/xhtml-im',
    XHTML: 'http://www.w3.org/1999/xhtml'
};

/** @type {Array.<string>} */
Strophe.XHTML.tags = ['a', 'blockquote', 'br', 'cite', 'em', 'img', 'li', 'ol', 'p', 'span', 'strong', 'ul', 'body'];

/** @type {Object.<Array.<string>>} */
Strophe.XHTML.attributes = {
    'a':          ['href'],
    'blockquote': ['style'],
    'br':         [],
    'cite':       ['style'],
    'em':         [],
    'img':        ['src', 'alt', 'style', 'height', 'width'],
    'li':         ['style'],
    'ol':         ['style'],
    'p':          ['style'],
    'span':       ['style'],
    'strong':     [],
    'ul':         ['style'],
    'body':       []
};

/** @type {Array.<string>} */
Strophe.XHTML.css = ['background-color', 'color', 'font-family', 'font-size', 'font-style', 'font-weight', 'margin-left', 'margin-right', 'text-align', 'text-decoration'];

/**
 * @param {string} tag
 * @return {boolean}
 */
Strophe.XHTML.validTag = function(tag) {
    return goog.array.contains(Strophe.XHTML.tags, tag);
};

/**
 * @param {string} tag
 * @param {string} attribute
 * @return {boolean}
 */
Strophe.XHTML.validAttribute = function(tag, attribute) {
    return goog.array.contains(Strophe.XHTML.attributes[tag], attribute);
};

/**
 * @param {string} style
 * @return {boolean}
 */
Strophe.XHTML.validCSS = function(style) {
    return goog.array.contains(Strophe.XHTML.css, style);
};

/**
 *  This function is used to extend the current namespaces in
 *	Strophe.NS.  It takes a key and a value with the key being the
 *	name of the new namespace, with its actual value.
 *	For example:
 *	Strophe.addNamespace('PUBSUB', "http://jabber.org/protocol/pubsub");
 *
 * @param {string} name - The name under which the namespace will be
 *      referenced under Strophe.NS
 * @param {string} value - The actual namespace.
 */
Strophe.addNamespace = function (name, value) {
    Strophe.NS[name] = value;
};

/**
 * @enum {number}
 *  Connection status constants for use by the connection handler
 *  callback.
 *
 *  Status.ERROR - An error has occurred
 *  Status.CONNECTING - The connection is currently being made
 *  Status.CONNFAIL - The connection attempt failed
 *  Status.AUTHENTICATING - The connection is authenticating
 *  Status.AUTHFAIL - The authentication attempt failed
 *  Status.CONNECTED - The connection has succeeded
 *  Status.DISCONNECTED - The connection has been terminated
 *  Status.DISCONNECTING - The connection is currently being terminated
 *  Status.ATTACHED - The connection has been attached
 */
Strophe.Status = {
    ERROR: 0,
    CONNECTING: 1,
    CONNFAIL: 2,
    AUTHENTICATING: 3,
    AUTHFAIL: 4,
    CONNECTED: 5,
    DISCONNECTED: 6,
    DISCONNECTING: 7,
    ATTACHED: 8
};

/**
 *  Timeout values for error states.  These values are in seconds.
 *  These should not be changed unless you know exactly what you are
 *  doing.
 *
 *  TIMEOUT - Timeout multiplier. A waiting request will be considered
 *      failed after Math.floor(TIMEOUT * wait) seconds have elapsed.
 *      This defaults to 1.1, and with default wait, 66 seconds.
 *  SECONDARY_TIMEOUT - Secondary timeout multiplier. In cases where
 *      Strophe can detect early failure, it will consider the request
 *      failed if it doesn't return after
 *      Math.floor(SECONDARY_TIMEOUT * wait) seconds have elapsed.
 *      This defaults to 0.1, and with default wait, 6 seconds.
 */

/** @constant {number} */
Strophe.TIMEOUT = 1.1;

/** @constant {number} */
Strophe.SECONDARY_TIMEOUT = 0.1;

/**
 *  Map a function over some or all child elements of a given element.
 *
 *  This is a small convenience function for mapping a function over
 *  some or all of the children of an element.  If elemName is null, all
 *  children will be passed to the function, otherwise only children
 *  whose tag names match elemName will be passed.
 *
 * @param {!Element} elem - The element to operate on.
 * @param {?string} elemName - The child element tag name filter.
 * @param {!function(!Element)} func - The function to apply to each child.  This
 *      function should take a single argument, a DOM element.
 */
Strophe.forEachChild = function (elem, elemName, func) {
    var i, childNode;

    for (i = 0; i < elem.childNodes.length; i++) {
        childNode = elem.childNodes[i];
        if (childNode.nodeType == goog.dom.NodeType.ELEMENT &&
            (!elemName || Strophe.isTagEqual(childNode, elemName))) {
            func(childNode);
        }
    }
};

/**
 *  Compare an element's tag name with a string.
 *
 *  This function is case insensitive.
 *
 * @param {!Element} el - A DOM element.
 * @param {string} name - The element name.
 *
 * @return {boolean}
 *    true if the element's tag name matches _el_, and false
 *    otherwise.
 */
Strophe.isTagEqual = function (el, name) {
    return el.tagName.toLowerCase() == name.toLowerCase();
};

/** @type {Document} */
Strophe._xmlGenerator;

/**
 * Get the DOM document to generate elements.
 *
 * @return {!Document}
 *    The currently used DOM document.
 */
Strophe.xmlGenerator = function () {
    if (! goog.isDefAndNotNull(Strophe._xmlGenerator)) {
        Strophe._xmlGenerator = goog.dom.xml.createDocument('strophe', 'jabber:client');
    }
    return /** @type {!Document} */ Strophe._xmlGenerator;
};

/**
 *  Create an XML DOM element.
 *
 *  This function creates an XML DOM element correctly across all
 *  implementations. Note that these are not HTML DOM elements, which
 *  aren't appropriate for XMPP stanzas.
 *
 * @param {string} name - The name for the element.
 * @param {Array|Object=} attrs - An optional array or object containing
 *      key/value pairs to use as element attributes. The object should
 *      be in the format {'key': 'value'} or {key: 'value'}. The array
 *      should have the format [['key1', 'value1'], ['key2', 'value2']].
 * @param {string=} text - The text child data for the element.
 *
 * @return {!Element}
 *    A new XML DOM element.
 */
Strophe.xmlElement = function (name, attrs, text) {
    var node = Strophe.xmlGenerator().createElement(name);

    // FIXME: this should throw errors if args are the wrong type or
    // there are more than two optional args
    var a, i, k;
    for (a = 1; a < arguments.length; a++) {
        if (! goog.isDefAndNotNull(arguments[a])) { continue; }
        if (goog.isString(arguments[a]) || goog.isNumber(arguments[a])) {
            node.appendChild(Strophe.xmlTextNode(arguments[a]));
        } else if (goog.isArray(arguments[a])) {
            for (i = 0; i < arguments[a].length; i++) {
                if (goog.isArray(arguments[a][i])) {
                    node.setAttribute(arguments[a][i][0], arguments[a][i][1]);
                }
            }
        } else if (goog.isObject(arguments[a])) {
            goog.dom.xml.setAttributes(node, arguments[a]);
        }
    }

    return node;
};

/**
 *  Excapes invalid xml characters.
 *
 * @param {string} text - text to escape.
 *
 * @return {string}
 *      Escaped text.
 */
Strophe.xmlescape = function(text) {
    return text.replace(/\&/g, '&amp;')
               .replace(/</g,  '&lt;')
               .replace(/>/g,  '&gt;')
               .replace(/'/g,  '&apos;')
               .replace(/"/g,  '&quot;');
};

/**
 *  Creates an XML DOM text node.
 *
 *  Provides a cross implementation version of document.createTextNode.
 *
 * @param {string} text - The content of the text node.
 *
 * @return {!Node}
 *    A new XML DOM text node.
 */
Strophe.xmlTextNode = function (text) {
    return Strophe.xmlGenerator().createTextNode(text);
};

/**
 *  Creates an XML DOM html node.
 *
 * @param {string} html - The content of the html node.
 *
 * @return {Document}
 *    A new XML DOM text node.
 */
Strophe.xmlHtmlNode = function (html) {
    return goog.dom.xml.loadXml(html);
};

/**
 *  Get the concatenation of all text children of an element.
 *
 * @param {Element} elem - A DOM element.
 *
 * @return {string}
 *    A String with the concatenated text of all text element children.
 */
Strophe.getText = function (elem) {
    var str = '';
    if (!elem) { return str; }

    if (elem.childNodes.length === 0 && elem.nodeType ==
        goog.dom.NodeType.TEXT) {
        str += elem.nodeValue;
    }

    for (var i = 0; i < elem.childNodes.length; i++) {
        if (elem.childNodes[i].nodeType == goog.dom.NodeType.TEXT) {
            str += elem.childNodes[i].nodeValue;
        }
    }

    // Don't do XML escaping here, because will do HTML escaping later.
    return str;
};

/**
 *  Copy an XML DOM element.
 *
 *  This function copies a DOM element and all its descendants and returns
 *  the new copy.
 *
 * @param {Node} elem - A DOM element.
 *
 * @return {Node}
 *    A new, copied DOM element tree.
 */
Strophe.copyElement = function (elem) {
    var el = null;
    if (elem.nodeType == goog.dom.NodeType.ELEMENT) {
        el = Strophe.xmlElement(elem.tagName);

        for (var i = 0; i < elem.attributes.length; i++) {
            el.setAttribute(elem.attributes[i].nodeName.toLowerCase(),
                            elem.attributes[i].value);
        }

        for (var i = 0; i < elem.childNodes.length; i++) {
            el.appendChild(Strophe.copyElement(elem.childNodes[i]));
        }
    } else if (elem.nodeType == goog.dom.NodeType.TEXT) {
        el = Strophe.xmlGenerator().createTextNode(elem.nodeValue);
    }

    return el;
};


/**
 *  Copy an HTML DOM element into an XML DOM.
 *
 *  This function copies a DOM element and all its descendants and returns
 *  the new copy.
 *
 * @param {Node} elem - A DOM element.
 *
 * @return {Node}
 *    A new, copied DOM element tree.
 */
Strophe.createHtml = function (elem) {
    var i, el = null, j, tag, attribute, value, css, cssAttrs, attr, cssName, cssValue, children, child;
    if (elem.nodeType == goog.dom.NodeType.ELEMENT) {
        tag = elem.nodeName.toLowerCase();
        if(Strophe.XHTML.validTag(tag)) {
            try {
                el = Strophe.xmlElement(tag);
                for(i = 0; i < Strophe.XHTML.attributes[tag].length; i++) {
                    attribute = Strophe.XHTML.attributes[tag][i];
                    value = elem.getAttribute(attribute);
                    //if(typeof value == 'undefined' || value === null || value === '' || value === false || value === 0) {
                    if (! goog.isDefAndNotNull(value)) {
                        continue;
                    }
                    if (attribute == 'style' && goog.isObject(value)) {
                        if (goog.isDefAndNotNull(value.cssText)) {
                            value = value.cssText; // we're dealing with IE, need to get CSS out
                        }
                    }
                    // filter out invalid css styles
                    if(attribute == 'style') {
                        css = [];
                        cssAttrs = value.split(';');
                        for(j = 0; j < cssAttrs.length; j++) {
                            attr = cssAttrs[j].split(':');
                            cssName = attr[0].replace(/^\s*/, "").replace(/\s*$/, "").toLowerCase();
                            if(Strophe.XHTML.validCSS(cssName)) {
                                cssValue = attr[1].replace(/^\s*/, "").replace(/\s*$/, "");
                                css.push(cssName + ': ' + cssValue);
                            }
                        }
                        if(css.length > 0) {
                            value = css.join('; ');
                            el.setAttribute(attribute, value);
                        }
                    } else {
                        el.setAttribute(attribute, value);
                    }
                }

                for (i = 0; i < elem.childNodes.length; i++) {
                    el.appendChild(Strophe.createHtml(elem.childNodes[i]));
                }
            } catch(e) { // invalid elements
              el = Strophe.xmlTextNode('');
            }
        } else {
            el = Strophe.xmlGenerator().createDocumentFragment();
            for (i = 0; i < elem.childNodes.length; i++) {
                el.appendChild(Strophe.createHtml(elem.childNodes[i]));
            }
        }
    } else if (elem.nodeType == goog.dom.NodeType.DOCUMENT_FRAGMENT) {
        el = Strophe.xmlGenerator().createDocumentFragment();
        for (i = 0; i < elem.childNodes.length; i++) {
            el.appendChild(Strophe.createHtml(elem.childNodes[i]));
        }
    } else if (elem.nodeType == goog.dom.NodeType.TEXT) {
        el = Strophe.xmlTextNode(elem.nodeValue);
    }

    return el;
};

/**
 *  Escape the node part (also called local part) of a JID.
 *
 * @param {string} node - A node (or local part).
 *
 * @return {string}
 *    An escaped node (or local part).
 */
Strophe.escapeNode = function (node) {
    return node.replace(/^\s+|\s+$/g, '')
               .replace(/\\/g,  '\\5c')
               .replace(/ /g,   '\\20')
               .replace(/\"/g,  '\\22')
               .replace(/\&/g,  '\\26')
               .replace(/\'/g,  '\\27')
               .replace(/\//g,  '\\2f')
               .replace(/:/g,   '\\3a')
               .replace(/</g,   '\\3c')
               .replace(/>/g,   '\\3e')
               .replace(/@/g,   '\\40');
};

/**
 *  Unescape a node part (also called local part) of a JID.
 *
 * @param {string} node - A node (or local part).
 *
 * @return {string}
 *    An unescaped node (or local part).
 */
Strophe.unescapeNode = function (node) {
    return node.replace(/\\20/g, ' ')
               .replace(/\\22/g, '"')
               .replace(/\\26/g, '&')
               .replace(/\\27/g, '\'')
               .replace(/\\2f/g, '/')
               .replace(/\\3a/g, ':')
               .replace(/\\3c/g, '<')
               .replace(/\\3e/g, '>')
               .replace(/\\40/g, '@')
               .replace(/\\5c/g, '\\');
};

/**
 *  Get the node portion of a JID String.
 *
 * @param {?string} jid - A JID.
 *
 * @return {?string}
 *    A String containing the node.
 */
Strophe.getNodeFromJid = function (jid) {
    if (jid.indexOf("@") < 0) { return null; }
    return jid.split("@")[0];
};

/**
 *  Get the domain portion of a JID String.
 *
 * @param {?string} jid - A JID.
 *
 * @return {?string}
 *    A String containing the domain.
 */
Strophe.getDomainFromJid = function (jid) {
    var bare = Strophe.getBareJidFromJid(jid);
    if (bare.indexOf("@") < 0) {
        return bare;
    } else {
        var parts = bare.split("@");
        parts.splice(0, 1);
        return parts.join('@');
    }
};

/**
 *  Get the resource portion of a JID String.
 *
 * @param {?string} jid - A JID.
 *
 * @return {?string}
 *    A String containing the resource.
 */
Strophe.getResourceFromJid = function (jid) {
    var s = jid.split("/");
    if (s.length < 2) { return null; }
    s.splice(0, 1);
    return s.join('/');
};

/**
 *  Get the bare JID from a JID String.
 *
 * @param {?string} jid - A JID.
 *
 * @return {?string}
 *    A String containing the bare JID.
 */
Strophe.getBareJidFromJid = function (jid) {
    return jid ? jid.split("/")[0] : null;
};

/**
 *  User overrideable logging function.
 *
 *  This function is called whenever the Strophe library calls any
 *  of the logging functions.  The default implementation of this
 *  function does nothing.  If client code wishes to handle the logging
 *  messages, it should override this with
 *  > Strophe.log = function (level, msg) {
 *  >   (user code here)
 *  > };
 *
 *  Please note that data sent and received over the wire is logged
 *  via Strophe.Connection.rawInput() and Strophe.Connection.rawOutput().
 *
 *  The different levels and their meanings are
 *
 *    DEBUG - Messages useful for debugging purposes.
 *    INFO - Informational messages.  This is mostly information like
 *      'disconnect was called' or 'SASL auth succeeded'.
 *    WARN - Warnings about potential problems.  This is mostly used
 *      to report transient connection errors like request timeouts.
 *    ERROR - Some error occurred.
 *    FATAL - A non-recoverable fatal error occurred.
 *
 * @param {goog.debug.Logger.Level} level - The log level of the log message.  This will
 *      be one of the values in Strophe.LogLevel.
 * @param {string} msg - The log message.
 */
Strophe.log = function (level, msg) {
    return;
};

if (goog.DEBUG) {
    /**
     * @param {string} msg - The log message.
     */
    Strophe.debug = function(msg) {
        Strophe.log(goog.debug.Logger.Level.FINE, msg);
    };
}

/**
 * @param {string} msg - The log message.
 */
Strophe.info = function (msg) {
    Strophe.log(goog.debug.Logger.Level.INFO, msg);
};

/**
 * @param {string} msg - The log message.
 */
Strophe.warn = function (msg) {
    Strophe.log(goog.debug.Logger.Level.WARNING, msg);
};

/**
 * @param {string} msg - The log message.
 */
Strophe.error = function (msg) {
    Strophe.log(goog.debug.Logger.Level.SEVERE, msg);
};

/**
 * @param {string} msg - The log message.
 */
Strophe.fatal = function (msg) {
    Strophe.log(goog.debug.Logger.Level.SHOUT, msg);
};

/**
 *  Render a DOM element and all descendants to a String.
 *
 * @param {!Document|Element} elem - A DOM element.
 *
 * @return {string}
 *    The serialized element tree as a String.
 */
Strophe.serialize = function (elem) {
    var result;

    if (goog.isFunction(elem.tree)) {
        elem = elem.tree();
    }

    var nodeName = elem.nodeName;
    var i, child;

    if (elem.getAttribute("_realname")) {
        nodeName = elem.getAttribute("_realname");
    }

    result = "<" + nodeName;
    for (i = 0; i < elem.attributes.length; i++) {
           if(elem.attributes[i].nodeName != "_realname") {
             result += " " + elem.attributes[i].nodeName.toLowerCase() +
                        "='" + elem.attributes[i].value.replace(/&/g, "&amp;")
                                                       .replace(/\'/g, "&apos;")
                                                       .replace(/>/g, "&gt;")
                                                       .replace(/</g, "&lt;") + "'";
           }
    }

    if (elem.childNodes.length > 0) {
        result += ">";
        for (i = 0; i < elem.childNodes.length; i++) {
            child = elem.childNodes[i];
            switch( child.nodeType ){
              case goog.dom.NodeType.ELEMENT:
                // normal element, so recurse
                result += Strophe.serialize(child);
                break;
              case goog.dom.NodeType.TEXT:
                // text element to escape values
                result += Strophe.xmlescape(child.nodeValue);
                break;
              case goog.dom.NodeType.CDATA_SECTION:
                // cdata section so don't escape values
                result += "<![CDATA["+child.nodeValue+"]]>";
            }
        }
        result += "</" + nodeName + ">";
    } else {
        result += "/>";
    }

    return result;
};

/**
 *  _Private_ variable that keeps track of the request ids for
 *  connections.
 *  @type {number}
 */
Strophe._requestId = 0;

/** @typedef {{ init: function(Strophe.Connection), statusChanged: function(number, ?string) }} */
Strophe.plugin;

/**
 *  _Private_ variable Used to store plugin names that need
 *  initialization on Strophe.Connection construction.
 *  @type {Object.<Strophe.plugin>}
 */
Strophe._connectionPlugins = {};

/**
 *  Extends the Strophe.Connection object with the given plugin.
 *
 * @param {string} name - The name of the extension.
 * @param {Strophe.plugin} ptype - The plugin's prototype.
 */
Strophe.addConnectionPlugin = function (name, ptype) {
    Strophe._connectionPlugins[name] = ptype;
};

/** Class: Strophe.Builder
 *  XML DOM builder.
 *
 *  This object provides an interface similar to JQuery but for building
 *  DOM element easily and rapidly.  All the functions except for toString()
 *  and tree() return the object, so calls can be chained.  Here's an
 *  example using the $iq() builder helper.
 *  > $iq({to: 'you', from: 'me', type: 'get', id: '1'})
 *  >     .c('query', {xmlns: 'strophe:example'})
 *  >     .c('example')
 *  >     .toString()
 *  The above generates this XML fragment
 *  > <iq to='you' from='me' type='get' id='1'>
 *  >   <query xmlns='strophe:example'>
 *  >     <example/>
 *  >   </query>
 *  > </iq>
 *  The corresponding DOM manipulations to get a similar fragment would be
 *  a lot more tedious and probably involve several helper variables.
 *
 *  Since adding children makes new operations operate on the child, up()
 *  is provided to traverse up the tree.  To add two children, do
 *  > builder.c('child1', ...).up().c('child2', ...)
 *  The next operation on the Builder will be relative to the second child.
 */

/**
 * @constructor
 *
 *  The attributes should be passed in object notation.  For example
 *  > var b = new Builder('message', {to: 'you', from: 'me'});
 *  or
 *  > var b = new Builder('messsage', {'xml:lang': 'en'});
 *
 * @param {string} name - The name of the root element.
 * @param {Object=} attrs - The attributes for the root element in object notation.
 */
Strophe.Builder = function (name, attrs)
{
    // Set correct namespace for jabber:client elements
    if (name == "presence" || name == "message" || name == "iq") {
        if (attrs && !attrs.xmlns) {
            attrs['xmlns'] = Strophe.NS.CLIENT;
        } else if (!attrs) {
            attrs = {'xmlns': Strophe.NS.CLIENT};
        }
    }

    // Holds the tree being built.
    this.nodeTree = Strophe.xmlElement(name, attrs);

    // Points to the current operation node.
    this.node = this.nodeTree;
};

/** @type {!Element} */
Strophe.Builder.prototype.nodeTree;

/** @type {!Element} */
Strophe.Builder.prototype.node;

/**
 *  Return the DOM tree.
 *
 *  This function returns the current DOM tree as an element object.  This
 *  is suitable for passing to functions like Strophe.Connection.send().
 *
 * @return {!Element}
 *    The DOM tree as a element object.
 */
Strophe.Builder.prototype.tree = function () {
    return this.nodeTree;
};

/**
 *  Serialize the DOM tree to a String.
 *
 *  This function returns a string serialization of the current DOM
 *  tree.  It is often used internally to pass data to a
 *  Strophe.Request object.
 *
 * @return {string}
 *    The serialized DOM tree in a String.
 */
Strophe.Builder.prototype.toString = function () {
    return Strophe.serialize(this.nodeTree);
};

/**
 *  Make the current parent element the new current element.
 *
 *  This function is often used after c() to traverse back up the tree.
 *  For example, to add two children to the same element
 *  > builder.c('child1', {}).up().c('child2', {});
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.up = function () {
    if (goog.isDefAndNotNull(this.node.parentNode)) {
        this.node = /** @type {!Element} */ this.node.parentNode;
    }
    return this;
};

/**
 *  Add or modify attributes of the current element.
 *
 *  The attributes should be passed in object notation.  This function
 *  does not move the current element pointer.
 *
 * @param {!Object.<string, string>} moreattrs - The attributes to add/modify in object notation.
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.attrs = function (moreattrs) {
    goog.dom.xml.setAttributes(this.node, moreattrs);
    return this;
};

/**
 *  Add a child to the current element and make it the new current
 *  element.
 *
 *  This function moves the current element pointer to the child,
 *  unless text is provided.  If you need to add another child, it
 *  is necessary to use up() to go back to the parent in the tree.
 *
 * @param {string} name - The name of the child.
 * @param {Object=} attrs - The attributes of the child in object notation.
 * @param {string=} text - The text to add to the child.
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.c = function (name, attrs, text) {
    var child = Strophe.xmlElement(name, attrs, text);
    this.node.appendChild(child);
    if (!text) {
        this.node = child;
    }
    return this;
};

/**
 *  Add a child to the current element and make it the new current
 *  element.
 *
 *  This function is the same as c() except that instead of using a
 *  name and an attributes object to create the child it uses an
 *  existing DOM element object.
 *
 * @param {!Element} elem - A DOM element.
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.cnode = function (elem) {
    var xmlGen = Strophe.xmlGenerator();
    try {
        var impNode = (xmlGen.importNode !== undefined);
    }
    catch (e) {
        var impNode = false;
    }
    var newElem = impNode ?
                  xmlGen.importNode(elem, true) :
                  Strophe.copyElement(elem);
    this.node.appendChild(newElem);
    this.node = /** @type {!Element} */ newElem;
    return this;
};

/**
 *  Add a child text element.
 *
 *  This *does not* make the child the new current element since there
 *  are no children of text elements.
 *
 * @param {string} text - The text data to append to the current element.
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.t = function (text) {
    var child = Strophe.xmlTextNode(text);
    this.node.appendChild(child);
    return this;
};

/**
 *  Replace current element contents with the HTML passed in.
 *
 *  This *does not* make the child the new current element
 *
 * @param {string} html - The html to insert as contents of current element.
 *
 * @return {!Strophe.Builder}
 */
Strophe.Builder.prototype.h = function (html) {
    var fragment = document.createElement('body');

    // force the browser to try and fix any invalid HTML tags
    fragment.innerHTML = html;

    // copy cleaned html into an xml dom
    var xhtml = Strophe.createHtml(fragment);

    while(xhtml.childNodes.length > 0) {
        this.node.appendChild(xhtml.childNodes[0]);
    }
    return this;
};

/**
 * @constructor
 *
 * @param {!function(!Element):boolean} handler - A function to be executed when the handler is run.
 * @param {?string} ns - The namespace to match.
 * @param {?string} name - The element name to match.
 * @param {?string=} type - The element type to match.
 * @param {?string=} id - The element id attribute to match.
 * @param {string=} from - The element from attribute to match.
 * @param {Object=} options - Handler options
 */
Strophe.Handler = function (handler, ns, name, type, id, from, options) {
    this.handler = handler;
    this.ns = ns;
    this.name = name;
    this.type = type;
    this.id = id;
    this.options = options || {matchbare: false};
    
    // default matchBare to false if undefined
    if (!this.options.matchBare) {
        this.options.matchBare = false;
    }

    if (this.options.matchBare) {
        this.from = from ? Strophe.getBareJidFromJid(from) : null;
    } else {
        this.from = from;
    }

    // whether the handler is a user handler or a system handler
    this.user = true;
};

/** @type {!function(!Element):boolean} */
Strophe.Handler.prototype.handler;

/** @type {?string} */
Strophe.Handler.prototype.ns;

/** @type {?string} */
Strophe.Handler.prototype.name;

/** @type {?string|undefined} */
Strophe.Handler.prototype.type;

/** @type {?string|undefined} */
Strophe.Handler.prototype.id;

/** @type {Object} */
Strophe.Handler.prototype.options;

/** @type {boolean} */
Strophe.Handler.prototype.user = true;

/**
 *  Tests if a stanza matches the Strophe.Handler.
 *
 * @param {Element} elem - The XML element to test.
 *
 * @return {boolean}
 *    true if the stanza matches and false otherwise.
 */
Strophe.Handler.prototype.isMatch = function (elem) {
    var nsMatch;
    var from = null;
    
    if (this.options.matchBare) {
        from = Strophe.getBareJidFromJid(elem.getAttribute('from'));
    } else {
        from = elem.getAttribute('from');
    }

    nsMatch = false;
    if (!this.ns) {
        nsMatch = true;
    } else {
        var that = this;
        Strophe.forEachChild(elem, null, function (elem) {
            if (elem.getAttribute("xmlns") == that.ns) {
                nsMatch = true;
            }
        });

        nsMatch = nsMatch || elem.getAttribute("xmlns") == this.ns;
    }

    if (nsMatch &&
        (!this.name || Strophe.isTagEqual(elem, this.name)) &&
        (!this.type || elem.getAttribute("type") == this.type) &&
        (!this.id || elem.getAttribute("id") == this.id) &&
        (!this.from || from == this.from)) {
            return true;
    }

    return false;
};

/**
 *  Run the callback on a matching stanza.
 *
 * @param {!Element} elem - The DOM element that triggered the
 *      Strophe.Handler.
 *
 * @return {boolean}
 *    A boolean indicating if the handler should remain active.
 */
Strophe.Handler.prototype.run = function (elem) {
    var result = false;
    try {
        result = this.handler(elem);
    } catch (e) {
        if (e.sourceURL) {
            Strophe.fatal("error: " + this.handler +
                          " " + e.sourceURL + ":" +
                          e.line + " - " + e.name + ": " + e.message);
        } else if (e.fileName) {
            Strophe.fatal("error: " + this.handler + " " +
                          e.fileName + ":" + e.lineNumber + " - " +
                          e.name + ": " + e.message);
        } else {
            Strophe.fatal("error: " + e.message + "\n" + e.stack);
        }

        throw e;
    }

    return result;
};

/**
 *  Get a String representation of the Strophe.Handler object.
 *
 * @return {string}
 *    A String.
 */
Strophe.Handler.prototype.toString = function () {
    return "{Handler: " + this.handler + "(" + this.name + "," + this.id + "," + this.ns + ")}";
};

/**
 * @constructor
 *
 * @param {number} period - The number of milliseconds to wait before the
 *      handler is called.
 * @param {function():boolean} handler - The callback to run when the handler fires.  This
 *      function should take no arguments.
 */
Strophe.TimedHandler = function (period, handler) {
    this.period = period;
    this.handler = handler;

    this.lastCalled = goog.now();
    this.user = true;
};

/**
 *  Run the callback for the Strophe.TimedHandler.
 *
 * @return {boolean}
 *    true if the Strophe.TimedHandler should be called again, and false
 *      otherwise.
 */
Strophe.TimedHandler.prototype.run = function () {
    this.lastCalled = goog.now();
    return this.handler();
};

/**
 *  Reset the last called time for the Strophe.TimedHandler.
 */
Strophe.TimedHandler.prototype.reset = function () {
    this.lastCalled = goog.now();
};

/**
 *  Get a string representation of the Strophe.TimedHandler object.
 *
 * @return {string}
 *    The string representation.
 */
Strophe.TimedHandler.prototype.toString = function () {
    return "{TimedHandler: " + this.handler + "(" + this.period +")}";
};

/**
 * @constructor
 *
 * @param {!Element} elem - The XML data to be sent in the request.
 * @param {!function(Strophe.Request, Event)} func - The function that will be called when the XMLHttpRequest readyState changes.
 * @param {number} rid - The BOSH rid attribute associated with this request.
 * @param {number=} sends - The number of times this same request has been sent.
 */
Strophe.Request = function (elem, func, rid, sends) {
    this.id = ++Strophe._requestId;
    this.xmlData = elem;
    this.data = Strophe.serialize(elem);
    // save original function in case we need to make a new request
    // from this one.
    this.origFunc = func;
    this.func = func;
    this.rid = rid;
    this.sends = sends || 0;
    this.xhr = this._newXHR();
};

/** @type {number} */
Strophe.Request.prototype.id;

/** @type {!Element} */
Strophe.Request.prototype.xmlData;

/** @type {string} */
Strophe.Request.prototype.data;

/** @type {!function(Strophe.Request, Event)} */
Strophe.Request.prototype.origFunc;

/** @type {!function(Strophe.Request, Event)} */
Strophe.Request.prototype.func;

/** @type {number} */
Strophe.Request.prototype.rid;

/** @type {number} */
Strophe.Request.prototype.sends;

/** @type {number} */
Strophe.Request.prototype.date = NaN;

/** @type {boolean} */
Strophe.Request.prototype.abort = false;

Strophe.Request.prototype.dead = null;

/** @return {number} */
Strophe.Request.prototype.age = function() {
    if (!this.date) { return 0; }
    var now = goog.now();
    return (now - this.date) / 1000;
};

/** @return {number} */
Strophe.Request.prototype.timeDead = function() {
    if (!this.dead) { return 0; }
    var now = goog.now();
    return (now - this.dead) / 1000;
};

/** @type {goog.net.XhrIo} */
Strophe.Request.prototype.xhr;

/**
 *  Get a response from the underlying XMLHttpRequest.
 *
 *  This function attempts to get a response from the request and checks
 *  for errors.
 *
 *  Throws:
 *    "parsererror" - A parser error occured.
 *
 * @return {Element}
 *    The DOM element tree of the response.
 */
Strophe.Request.prototype.getResponse = function () {
    var node = null;
    if (this.xhr.getResponseXml() && this.xhr.getResponseXml().documentElement) {
        node = this.xhr.getResponseXml().documentElement;
        if (node.tagName == "parsererror") {
            Strophe.error("invalid response received");
            Strophe.error("responseText: " + this.xhr.getResponseText());
            Strophe.error("responseXML: " + Strophe.serialize(this.xhr.getResponseXml()));
            throw "parsererror";
        }
    } else if (this.xhr.getResponseText()) {
        Strophe.error("invalid response received");
        Strophe.error("responseText: " + this.xhr.getResponseText());
        Strophe.error("responseXML: " + Strophe.serialize(this.xhr.getResponseXml()));
    }

    return node;
};

/**
 * This function creates XMLHttpRequests across all implementations.
 * @return {goog.net.XhrIo} a new XMLHttpRequest.
 */
Strophe.Request.prototype._newXHR = function () {
    var xhr = new goog.net.XhrIo();
    goog.events.listen(xhr, goog.net.EventType.COMPLETE, goog.partial(this.func, this));
    return xhr;
};

/**
 *  XMPP Connection manager.
 *
 *  This class is the main part of Strophe.  It manages a BOSH connection
 *  to an XMPP server and dispatches events to the user callbacks as
 *  data arrives.  It supports SASL PLAIN, SASL DIGEST-MD5, and legacy
 *  authentication.
 *
 *  After creating a Strophe.Connection object, the user will typically
 *  call connect() with a user supplied callback to handle connection level
 *  events like authentication failure, disconnection, or connection
 *  complete.
 *
 *  The user will also have several event handlers defined by using
 *  addHandler() and addTimedHandler().  These will allow the user code to
 *  respond to interesting stanzas or do something periodically with the
 *  connection.  These handlers will be active once authentication is
 *  finished.
 *
 *  To send data to the connection, use send().
 */

/**
 * @constructor
 *
 * @param {string} service - The BOSH service URL.
 */
Strophe.Connection = function (service)
{
    /* The path to the httpbind service. */
    this.service = service;
    /* request id for body tags */
    this.rid = Math.floor(Math.random() * 4294967295);

    // SASL
    this._sasl_data = [];

    // handler lists
    this.timedHandlers = [];
    this.handlers = [];
    this.removeTimeds = [];
    this.removeHandlers = [];
    this.addTimeds = [];
    this.addHandlers = [];

    this._authentication = {};

    this._data = [];
    this._requests = [];
    this._uniqueId = Math.round(Math.random() * 10000);

    // setup onIdle callback every 1/10th of a second
    this._idleTimeout = setTimeout(goog.bind(this._onIdle, this), 100);

    // initialize plugins
    for (var k in Strophe._connectionPlugins) {
        if (Strophe._connectionPlugins.hasOwnProperty(k)) {
	    var ptype = Strophe._connectionPlugins[k];
            // jslint complaints about the below line, but this is fine
            var F = /** @constructor */ function () {};
            F.prototype = ptype;
            this[k] = new F();
	    this[k]['init'](this);
        }
    }
};

/** @type {string} */
Strophe.Connection.prototype.service;

/** @type {?string} */
Strophe.Connection.prototype.jid = '';

/** @type {?string} */
Strophe.Connection.prototype.domain = null;

/** @type {number} */
Strophe.Connection.prototype.rid;

/** @type {?string} */
Strophe.Connection.prototype.sid = null;

/** @type {?string} */
Strophe.Connection.prototype.streamId = null;

Strophe.Connection.prototype.features = null;

//Strophe.Connection.prototype._sasl_data;

/** @type {boolean} */
Strophe.Connection.prototype.do_session = false;

/** @type {boolean} */
Strophe.Connection.prototype.do_bind = false;

/** @type {Array.<!Strophe.TimedHandler>} */
Strophe.Connection.prototype.timedHandlers;

/** @type {Array.<!Strophe.Handler>} */
Strophe.Connection.prototype.handlers;

/** @type {Array.<Strophe.TimedHandler>} */
Strophe.Connection.prototype.removeTimeds;

/** @type {Array.<Strophe.Handler>} */
Strophe.Connection.prototype.removeHandlers;

/** @type {Array.<Strophe.TimedHandler>} */
Strophe.Connection.prototype.addTimeds;

/** @type {Array.<Strophe.Handler>} */
Strophe.Connection.prototype.addHandlers;

/** @type {Object} */
Strophe.Connection.prototype._authentication;

Strophe.Connection.prototype._idleTimeout = null;

Strophe.Connection.prototype._disconnectTimeout = null;

/** @type {boolean} */
Strophe.Connection.prototype.do_authentication = true;

/** @type {boolean} */
Strophe.Connection.prototype.authenticated = false;

/** @type {boolean} */
Strophe.Connection.prototype.disconnecting = false;

/** @type {boolean} */
Strophe.Connection.prototype.connected = false;

/** @type {number} */
Strophe.Connection.prototype.errors = 0;

/** @type {boolean} */
Strophe.Connection.prototype.paused = false;

/** @type {number} */
Strophe.Connection.prototype.hold = 1;

/** @type {number} */
Strophe.Connection.prototype.wait = 60;

/** @type {number} */
Strophe.Connection.prototype.window = 5;

/** @type {Array} */
Strophe.Connection.prototype._data;

/** @type {Array.<Strophe.Request>} */
Strophe.Connection.prototype._requests;

/** @type {number} */
Strophe.Connection.prototype._uniqueId;

Strophe.Connection.prototype._sasl_success_handler = null;

Strophe.Connection.prototype._sasl_failure_handler = null;

Strophe.Connection.prototype._sasl_challenge_handler = null;

/** @type {number} */
Strophe.Connection.prototype.maxRetries = 5;

//Strophe.Connection.prototype._idleTimeout;

/**
 *  Reset the connection.
 *
 *  This function should be called after a connection is disconnected
 *  before that connection is reused.
 */
Strophe.Connection.prototype.reset = function () {
    this.rid = Math.floor(Math.random() * 4294967295);

    this.sid = null;
    this.streamId = null;

    // SASL
    this.do_session = false;
    this.do_bind = false;

    // handler lists
    this.timedHandlers = [];
    this.handlers = [];
    this.removeTimeds = [];
    this.removeHandlers = [];
    this.addTimeds = [];
    this.addHandlers = [];
    this._authentication = {};

    this.authenticated = false;
    this.disconnecting = false;
    this.connected = false;

    this.errors = 0;

    this._requests = [];
    this._uniqueId = Math.round(Math.random()*10000);
};

/**
 *  Pause the request manager.
 *
 *  This will prevent Strophe from sending any more requests to the
 *  server.  This is very useful for temporarily pausing while a lot
 *  of send() calls are happening quickly.  This causes Strophe to
 *  send the data in a single request, saving many request trips.
 */
Strophe.Connection.prototype.pause = function () {
    this.paused = true;
};

/**
 *  Resume the request manager.
 *
 *  This resumes after pause() has been called.
 */
Strophe.Connection.prototype.resume = function () {
    this.paused = false;
};

/**
 *  Generate a unique ID for use in <iq/> elements.
 *
 *  All <iq/> stanzas are required to have unique id attributes.  This
 *  function makes creating these easy.  Each connection instance has
 *  a counter which starts from zero, and the value of this counter
 *  plus a colon followed by the suffix becomes the unique id. If no
 *  suffix is supplied, the counter is used as the unique id.
 *
 *  Suffixes are used to make debugging easier when reading the stream
 *  data, and their use is recommended.  The counter resets to 0 for
 *  every new connection for the same reason.  For connections to the
 *  same server that authenticate the same way, all the ids should be
 *  the same, which makes it easy to see changes.  This is useful for
 *  automated testing as well.
 *
 * @param {string=} suffix - A optional suffix to append to the id.
 *
 * @return {string}
 *    A unique string to be used for the id attribute.
 */
Strophe.Connection.prototype.getUniqueId = function (suffix) {
    if (goog.isString(suffix) || goog.isNumber(suffix)) {
        return ++this._uniqueId + ":" + suffix;
    } else {
        return ++this._uniqueId + "";
    }
};

/**
 *  Starts the connection process.
 *
 *  As the connection process proceeds, the user supplied callback will
 *  be triggered multiple times with status updates.  The callback
 *  should take two arguments - the status code and the error condition.
 *
 *  The status code will be one of the values in the Strophe.Status
 *  constants.  The error condition will be one of the conditions
 *  defined in RFC 3920 or the condition 'strophe-parsererror'.
 *
 *  Please see XEP 124 for a more detailed explanation of the optional
 *  parameters below.
 *
 * @param {string} jid - The user's JID.  This may be a bare JID,
 *      or a full JID.  If a node is not supplied, SASL ANONYMOUS
 *      authentication will be attempted.
 * @param {?string} pass - The user's password.
 * @param {function(number, ?string)} callback - The connect callback function.
 * @param {number=} wait - The optional HTTPBIND wait value.  This is the
 *      time the server will wait before returning an empty result for
 *      a request.  The default setting of 60 seconds is recommended.
 *      Other settings will require tweaks to the Strophe.TIMEOUT value.
 * @param {number=} hold - The optional HTTPBIND hold value.  This is the
 *      number of connections the server will hold at one time.  This
 *      should almost always be set to 1 (the default).
 * @param {string=} route
 */
Strophe.Connection.prototype.connect = function (jid, pass, callback, wait, hold, route) {
    this.jid = jid;
    this.pass = pass;
    this.connect_callback = callback;
    this.disconnecting = false;
    this.connected = false;
    this.authenticated = false;
    this.errors = 0;

    this.wait = wait || this.wait;
    this.hold = hold || this.hold;

    // parse jid for domain and resource
    this.domain = this.domain || Strophe.getDomainFromJid(this.jid);

    // build the body tag
    var body = this._buildBody().attrs({
        'to': this.domain,
        'xml:lang': 'en',
        'wait': this.wait,
        'hold': this.hold,
        'content': 'text/xml; charset=utf-8',
        'ver': '1.6',
        'xmpp:version': '1.0',
        'xmlns:xmpp': Strophe.NS.BOSH
    });

    if(route){
        body.attrs({
            'route': route
        });
    }

    this._changeConnectStatus(Strophe.Status.CONNECTING, null);

    this._requests.push(
        new Strophe.Request(body.tree(),
                            goog.bind(this._onRequestStateChange, this, goog.bind(this._connect_cb, this)),
                            parseInt(body.tree().getAttribute("rid"), 10)));
    this._throttledRequestHandler();
};

/**
 *  Attach to an already created and authenticated BOSH session.
 *
 *  This function is provided to allow Strophe to attach to BOSH
 *  sessions which have been created externally, perhaps by a Web
 *  application.  This is often used to support auto-login type features
 *  without putting user credentials into the page.
 *
 *  Parameters:
 * @param {string} jid - The full JID that is bound by the session.
 * @param {string} sid - The SID of the BOSH session.
 * @param {number} rid - The current RID of the BOSH session.  This RID
 *      will be used by the next request.
 * @param {function(number, ?string)} callback The connect callback function.
 * @param {number=} wait - The optional HTTPBIND wait value.  This is the
 *      time the server will wait before returning an empty result for
 *      a request.  The default setting of 60 seconds is recommended.
 *      Other settings will require tweaks to the Strophe.TIMEOUT value.
 * @param {number=} hold - The optional HTTPBIND hold value.  This is the
 *      number of connections the server will hold at one time.  This
 *      should almost always be set to 1 (the default).
 * @param {number=} wind - The optional HTTBIND window value.  This is the
 *      allowed range of request ids that are valid.  The default is 5.
 */
Strophe.Connection.prototype.attach = function (jid, sid, rid, callback, wait, hold, wind) {
    this.jid = jid;
    this.sid = sid;
    this.rid = rid;
    this.connect_callback = callback;

    this.domain = Strophe.getDomainFromJid(this.jid);

    this.authenticated = true;
    this.connected = true;

    this.wait = wait || this.wait;
    this.hold = hold || this.hold;
    this.window = wind || this.window;

    this._changeConnectStatus(Strophe.Status.ATTACHED, null);
};

/**
 *  User overrideable function that receives XML data coming into the
 *  connection.
 *
 *  The default function does nothing.  User code can override this with
 *  > Strophe.Connection.xmlInput = function (elem) {
 *  >   (user code)
 *  > };
 *
 * @param {Element} elem - The XML data received by the connection.
 */
Strophe.Connection.prototype.xmlInput = function (elem) {
    return;
};

/**
 *  User overrideable function that receives XML data sent to the
 *  connection.
 *
 *  The default function does nothing.  User code can override this with
 *  > Strophe.Connection.xmlOutput = function (elem) {
 *  >   (user code)
 *  > };
 *
 * @param {Element} elem - The XMLdata sent by the connection.
 */
Strophe.Connection.prototype.xmlOutput = function (elem) {
    return;
};

/**
 *  User overrideable function that receives raw data coming into the
 *  connection.
 *
 *  The default function does nothing.  User code can override this with
 *  > Strophe.Connection.rawInput = function (data) {
 *  >   (user code)
 *  > };
 *
 * @param {?string} data - The data received by the connection.
 */
Strophe.Connection.prototype.rawInput = function (data) {
    return;
};

/**
 *  User overrideable function that receives raw data sent to the
 *  connection.
 *
 *  The default function does nothing.  User code can override this with
 *  > Strophe.Connection.rawOutput = function (data) {
 *  >   (user code)
 *  > };
 *
 * @param {?string} data - The data sent by the connection.
 */
Strophe.Connection.prototype.rawOutput = function (data) {
    return;
};

/**
 *  Send a stanza.
 *
 *  This function is called to push data onto the send queue to
 *  go out over the wire.  Whenever a request is sent to the BOSH
 *  server, all pending data is sent and the queue is flushed.
 *
 * @param {Element|Array.<Element>|Strophe.Builder} elem
 */
Strophe.Connection.prototype.send = function (elem) {
    if (elem === null) { return ; }
    if (goog.isArray(elem)) {
        for (var i = 0; i < elem.length; i++) {
            this._queueData(elem[i]);
        }
    } else if (goog.isFunction(elem.tree)) {
        this._queueData(elem.tree());
    } else {
        this._queueData(elem);
    }

    this._throttledRequestHandler();
    clearTimeout(this._idleTimeout);
    this._idleTimeout = setTimeout(goog.bind(this._onIdle, this), 100);
};

/**
 *  Immediately send any pending outgoing data.
 *
 *  Normally send() queues outgoing data until the next idle period
 *  (100ms), which optimizes network use in the common cases when
 *  several send()s are called in succession. flush() can be used to
 *  immediately send all pending data.
 */
Strophe.Connection.prototype.flush = function () {
    // cancel the pending idle period and run the idle function
    // immediately
    clearTimeout(this._idleTimeout);
    this._onIdle();
};

/**
 *  Helper function to send IQ stanzas.
 *
 * @param {Element} elem - The stanza to send.
 * @param {Function} callback - The callback function for a successful request.
 * @param {Function} errback - The callback function for a failed or timed
 *      out request.  On timeout, the stanza will be null.
 * @param {number} timeout - The time specified in milliseconds for a
 *      timeout to occur.
 *
 * @return {string}
 *    The id used to send the IQ.
*/
Strophe.Connection.prototype.sendIQ = function(elem, callback, errback, timeout) {
    var timeoutHandler = null;
    var that = this;

    if (goog.isFunction(elem.tree)) {
        elem = elem.tree();
    }
    var id = elem.getAttribute('id');

    // inject id if not found
    if (!id) {
        id = this.getUniqueId("sendIQ");
        elem.setAttribute("id", id);
    }

    var handler = this.addHandler(function (stanza) {
        // remove timeout handler if there is one
        if (timeoutHandler) {
            that.deleteTimedHandler(timeoutHandler);
        }

        var iqtype = stanza.getAttribute('type');
        if (iqtype == 'result') {
            if (callback) {
                callback(stanza);
            }
        } else if (iqtype == 'error') {
            if (errback) {
                errback(stanza);
            }
        } else {
            throw {
                name: "StropheError",
                message: "Got bad IQ type of " + iqtype
            };
        }

        return false;
    }, null, 'iq', null, id);

    // if timeout specified, setup timeout handler.
    if (timeout) {
        timeoutHandler = this.addTimedHandler(timeout, function () {
            // get rid of normal handler
            that.deleteHandler(handler);

            // call errback on timeout with null stanza
            if (errback) {
                errback(null);
            }
            return false;
        });
    }

    this.send(elem);

    return id;
};

/**
 *  Queue outgoing data for later sending.  Also ensures that the data
 *  is a DOMElement.
 */
Strophe.Connection.prototype._queueData = function (element) {
    if (element === null || !element.tagName || !element.childNodes) {
        throw {
            name: "StropheError",
            message: "Cannot queue non-DOMElement."
        };
    }
    
    this._data.push(element);
};

/**
 *  Send an xmpp:restart stanza.
 */
Strophe.Connection.prototype._sendRestart = function () {
    this._data.push("restart");

    this._throttledRequestHandler();
    clearTimeout(this._idleTimeout);
    this._idleTimeout = setTimeout(goog.bind(this._onIdle, this), 100);
};

/**
 *  Add a timed handler to the connection.
 *
 *  This function adds a timed handler.  The provided handler will
 *  be called every period milliseconds until it returns false,
 *  the connection is terminated, or the handler is removed.  Handlers
 *  that wish to continue being invoked should return true.
 *
 *  Because of method binding it is necessary to save the result of
 *  this function if you wish to remove a handler with
 *  deleteTimedHandler().
 *
 *  Note that user handlers are not active until authentication is
 *  successful.
 *
 * @param {number} period - The period of the handler.
 * @param {function()} handler - The callback function.
 *
 * @return {Strophe.TimedHandler}
 *    A reference to the handler that can be used to remove it.
 */
Strophe.Connection.prototype.addTimedHandler = function (period, handler) {
    var thand = new Strophe.TimedHandler(period, handler);
    this.addTimeds.push(thand);
    return thand;
};

/**
 *  Delete a timed handler for a connection.
 *
 *  This function removes a timed handler from the connection.  The
 *  handRef parameter is *not* the function passed to addTimedHandler(),
 *  but is the reference returned from addTimedHandler().
 *
 * @param {Strophe.TimedHandler} handRef - The handler reference.
 */
Strophe.Connection.prototype.deleteTimedHandler = function (handRef) {
    // this must be done in the Idle loop so that we don't change
    // the handlers during iteration
    this.removeTimeds.push(handRef);
};

/**
 *  Add a stanza handler for the connection.
 *
 *  This function adds a stanza handler to the connection.  The
 *  handler callback will be called for any stanza that matches
 *  the parameters.  Note that if multiple parameters are supplied,
 *  they must all match for the handler to be invoked.
 *
 *  The handler will receive the stanza that triggered it as its argument.
 *  The handler should return true if it is to be invoked again;
 *  returning false will remove the handler after it returns.
 *
 *  As a convenience, the ns parameters applies to the top level element
 *  and also any of its immediate children.  This is primarily to make
 *  matching /iq/query elements easy.
 *
 *  The options argument contains handler matching flags that affect how
 *  matches are determined. Currently the only flag is matchBare (a
 *  boolean). When matchBare is true, the from parameter and the from
 *  attribute on the stanza will be matched as bare JIDs instead of
 *  full JIDs. To use this, pass {matchBare: true} as the value of
 *  options. The default value for matchBare is false.
 *
 *  The return value should be saved if you wish to remove the handler
 *  with deleteHandler().
 *
 * @param {!function(!Element):boolean} handler - The user callback.
 * @param {?string} ns - The namespace to match.
 * @param {?string} name - The stanza name to match.
 * @param {?string=} type - The stanza type attribute to match.
 * @param {string=} id - The stanza id attribute to match.
 * @param {string=} from - The stanza from attribute to match.
 * @param {Object=} options - The handler options
 *
 * @return {Strophe.Handler}
 *    A reference to the handler that can be used to remove it.
 */
Strophe.Connection.prototype.addHandler = function (handler, ns, name, type, id, from, options) {
    var hand = new Strophe.Handler(handler, ns, name, type, id, from, options);
    this.addHandlers.push(hand);
    return hand;
};

/**
 *  Delete a stanza handler for a connection.
 *
 *  This function removes a stanza handler from the connection.  The
 *  handRef parameter is *not* the function passed to addHandler(),
 *  but is the reference returned from addHandler().
 *
 * @param {Strophe.Handler} handRef - The handler reference.
 */
Strophe.Connection.prototype.deleteHandler = function (handRef) {
    // this must be done in the Idle loop so that we don't change
    // the handlers during iteration
    this.removeHandlers.push(handRef);
};

/**
 *  Start the graceful disconnection process.
 *
 *  This function starts the disconnection process.  This process starts
 *  by sending unavailable presence and sending BOSH body of type
 *  terminate.  A timeout handler makes sure that disconnection happens
 *  even if the BOSH server does not respond.
 *
 *  The user supplied connection callback will be notified of the
 *  progress as this process happens.
 *
 * @param {string=} reason - The reason the disconnect is occuring.
 */
Strophe.Connection.prototype.disconnect = function (reason) {
    this._changeConnectStatus(Strophe.Status.DISCONNECTING, reason || null);

    Strophe.info("Disconnect was called because: " + reason);
    if (this.connected) {
        // setup timeout handler
        this._disconnectTimeout = this._addSysTimedHandler(
            3000, goog.bind(this._onDisconnectTimeout, this));
        this._sendTerminate();
    }
};

/**
 *  _Private_ helper function that makes sure plugins and the user's
 *  callback are notified of connection status changes.
 *
 * @param {number} status - the new connection status, one of the values
 *      in Strophe.Status
 * @param {?string} condition - the error condition or null
 */
Strophe.Connection.prototype._changeConnectStatus = function (status, condition) {
    // notify all plugins listening for status changes
    for (var k in Strophe._connectionPlugins) {
        if (Strophe._connectionPlugins.hasOwnProperty(k)) {
            var plugin = this[k];
            if (plugin['statusChanged']) {
                try {
                    plugin['statusChanged'](status, condition);
                } catch (err) {
                    Strophe.error("" + k + " plugin caused an exception " + "changing status: " + err);
                }
            }
        }
    }

    // notify the user's callback
    if (this.connect_callback) {
        try {
            this.connect_callback(status, condition);
        } catch (e) {
            Strophe.error("User connection callback caused an " + "exception: " + e);
        }
    }
};

/**
 * @return {Strophe.Builder} a Strophe.Builder with a <body/> element.
 */
Strophe.Connection.prototype._buildBody = function () {
    var bodyWrap = $build('body', {
        'rid': this.rid++,
        'xmlns': Strophe.NS.HTTPBIND
    });

    if (this.sid !== null) {
        bodyWrap.attrs({'sid': this.sid});
    }

    return bodyWrap;
};

/**
 *  _Private_ function to remove a request from the queue.
 *
 * @param {Strophe.Request} req - The request to remove.
 */
Strophe.Connection.prototype._removeRequest = function (req) {
    if (goog.DEBUG) {
        Strophe.debug("removing request");
    }

    var i;
    for (i = this._requests.length - 1; i >= 0; i--) {
        if (req == this._requests[i]) {
            this._requests.splice(i, 1);
        }
    }

    this._throttledRequestHandler();
};

/**
 *  _Private_ function to restart a request that is presumed dead.
 *
 * @param {number} i - The index of the request in the queue.
 */
Strophe.Connection.prototype._restartRequest = function (i) {
    var req = this._requests[i];
    if (req.dead === null) {
        req.dead = goog.now();
    }

    this._processRequest(i);
};

/**
 *  _Private_ function to process a request in the queue.
 *
 *  This function takes requests off the queue and sends them and
 *  restarts dead requests.
 *
 * @param {number} i - The index of the request in the queue.
 */
Strophe.Connection.prototype._processRequest = function (i) {
    var req = this._requests[i];
    var reqStatus = -1;

    try {
        if (req.xhr.getReadyState() == goog.net.XmlHttp.ReadyState.COMPLETE) {
            reqStatus = req.xhr.getStatus();
        }
    } catch (e) {
        Strophe.error("caught an error in _requests[" + i +
                      "], reqStatus: " + reqStatus);
    }

    if (! goog.isDefAndNotNull(reqStatus)) {
        reqStatus = -1;
    }

    // make sure we limit the number of retries
    if (req.sends > this.maxRetries) {
        this._onDisconnectTimeout();
        return;
    }

    var time_elapsed = req.age();
    var primaryTimeout = (!isNaN(time_elapsed) &&
                          time_elapsed > Math.floor(Strophe.TIMEOUT * this.wait));
    var secondaryTimeout = (req.dead !== null &&
                            req.timeDead() > Math.floor(Strophe.SECONDARY_TIMEOUT * this.wait));
    var requestCompletedWithServerError = (req.xhr.getReadyState() == goog.net.XmlHttp.ReadyState.COMPLETE &&
                                           (reqStatus < 1 ||
                                            reqStatus >= 500));
    if (primaryTimeout || secondaryTimeout ||
        requestCompletedWithServerError) {
        if (secondaryTimeout) {
            Strophe.error("Request " +
                          this._requests[i].id +
                          " timed out (secondary), restarting");
        }
        req.abort = true;
        req.xhr.dispose();
        this._requests[i] = new Strophe.Request(req.xmlData, req.origFunc, req.rid, req.sends);
        req = this._requests[i];
    }

    if (req.xhr.getReadyState() === goog.net.XmlHttp.ReadyState.UNINITIALIZED) {
        if (goog.DEBUG) {
            Strophe.debug("request id " + req.id + "." + req.sends + " posting");
        }

        // Fires the XHR request -- may be invoked immediately
        // or on a gradually expanding retry window for reconnects
        var self = this,
            sendFunc = function () {
                req.date = goog.now();
                try {
                    req.xhr.send(self.service, 'POST', req.data, { 'Content-Type': 'text/xml; charset=UTF-8' });
                } catch (e2) {
                    Strophe.error("XHR send failed.");
                    if (!self.connected) {
                        self._changeConnectStatus(Strophe.Status.CONNFAIL, "bad-service");
                    }
                    self.disconnect();
                    return;
                }
            };

        // Implement progressive backoff for reconnects --
        // First retry (send == 1) should also be instantaneous
        if (req.sends > 1) {
            // Using a cube of the retry number creates a nicely
            // expanding retry window
            var backoff = Math.min(Math.floor(Strophe.TIMEOUT * this.wait),
                                   Math.pow(req.sends, 3)) * 1000;
            setTimeout(sendFunc, backoff);
        } else {
            sendFunc();
        }

        req.sends++;

        if (this.xmlOutput !== Strophe.Connection.prototype.xmlOutput) {
            this.xmlOutput(req.xmlData);
        }
        if (this.rawOutput !== Strophe.Connection.prototype.rawOutput) {
            this.rawOutput(req.data);
        }
    } else {
        if (goog.DEBUG) {
            Strophe.debug("_processRequest: " +
                          (i === 0 ? "first" : "second") +
                          " request has readyState of " +
                          req.xhr.getReadyState());
        }
    }
};

/**
 *  _Private_ function to throttle requests to the connection window.
 *
 *  This function makes sure we don't send requests so fast that the
 *  request ids overflow the connection window in the case that one
 *  request died.
 */
Strophe.Connection.prototype._throttledRequestHandler = function () {
    if (goog.DEBUG) {
        if (!this._requests) {
            Strophe.debug("_throttledRequestHandler called with " +
                          "undefined requests");
        } else {
            Strophe.debug("_throttledRequestHandler called with " +
                          this._requests.length + " requests");
        }
    }

    if (!this._requests || this._requests.length === 0) {
        return;
    }

    if (this._requests.length > 0) {
        this._processRequest(0);
    }

    if (this._requests.length > 1 &&
        Math.abs(this._requests[0].rid -
                 this._requests[1].rid) < this.window) {
        this._processRequest(1);
    }
};

/**
 *  This function is called when the XMLHttpRequest readyState changes.
 *  It contains a lot of error handling logic for the many ways that
 *  requests can fail, and calls the request callback when requests
 *  succeed.
 *
 * @param {!function(Strophe.Request)} func - The handler for the request.
 * @param {!Strophe.Request} req - The request that is changing readyState.
 */
Strophe.Connection.prototype._onRequestStateChange = function (func, req) {
    if (req.abort) {
        req.abort = false;
        return;
    }

    var reqStatus = req.xhr.getStatus();

    if (this.disconnecting) {
        if (reqStatus >= 400) {
            this._hitError(reqStatus);
            return;
        }
    }

    var reqIs0 = (this._requests[0] == req);
    var reqIs1 = (this._requests[1] == req);

    if ((reqStatus > 0 && reqStatus < 500) || req.sends > 5) {
        // remove from internal queue
        this._removeRequest(req);
        if (goog.DEBUG) {
            Strophe.debug("request id " + req.id + " should now be removed");
        }
    }

    // request succeeded
    if (req.xhr.isSuccess()) {
        // if request 1 finished, or request 0 finished and request
        // 1 is over Strophe.SECONDARY_TIMEOUT seconds old, we need to
        // restart the other - both will be in the first spot, as the
        // completed request has been removed from the queue already
        if (reqIs1 ||
            (reqIs0 && this._requests.length > 0 &&
             this._requests[0].age() > Math.floor(Strophe.SECONDARY_TIMEOUT * this.wait))) {
            this._restartRequest(0);
        }
        // call handler
        if (goog.DEBUG) {
            Strophe.debug("request id " + req.id + "." + req.sends + " got 200");
        }
        if (func) {
            func(req);
        }
        this.errors = 0;
    } else {
        Strophe.error("request id " + req.id + "." + req.sends + " error " + reqStatus + " happened");
        if (reqStatus === 0 ||
            (reqStatus >= 400 && reqStatus < 600) ||
            reqStatus >= 12000) {
            this._hitError(reqStatus);
            if (reqStatus >= 400 && reqStatus < 500) {
                this._changeConnectStatus(Strophe.Status.DISCONNECTING, null);
                this._doDisconnect();
            }
        }
    }

    if (!((reqStatus > 0 && reqStatus < 500) || req.sends > 5)) {
        this._throttledRequestHandler();
    }

    //req.xhr.dispose();
};

/**
 *  _Private_ function to handle the error count.
 *
 *  Requests are resent automatically until their error count reaches
 *  5.  Each time an error is encountered, this function is called to
 *  increment the count and disconnect if the count is too high.
 *
 * @param {number} reqStatus - The request status.
 */
Strophe.Connection.prototype._hitError = function (reqStatus) {
    this.errors++;
    Strophe.warn("request errored, status: " + reqStatus + ", number of errors: " + this.errors);
    if (this.errors > 4) {
        this._onDisconnectTimeout();
    }
};

/**
 *  _Private_ function to disconnect.
 *
 *  This is the last piece of the disconnection logic.  This resets the
 *  connection and alerts the user's connection callback.
 */
Strophe.Connection.prototype._doDisconnect = function () {
    Strophe.info("_doDisconnect was called");
    this.authenticated = false;
    this.disconnecting = false;
    this.sid = null;
    this.streamId = null;
    this.rid = Math.floor(Math.random() * 4294967295);

    // tell the parent we disconnected
    if (this.connected) {
        this._changeConnectStatus(Strophe.Status.DISCONNECTED, null);
        this.connected = false;
    }

    // delete handlers
    this.handlers = [];
    this.timedHandlers = [];
    this.removeTimeds = [];
    this.removeHandlers = [];
    this.addTimeds = [];
    this.addHandlers = [];
};

/**
 *  Except for _connect_cb handling the initial connection request,
 *  this function handles the incoming data for all requests.  This
 *  function also fires stanza handlers that match each incoming
 *  stanza.
 *
 * @param {Strophe.Request} req - The request that has data ready.
 */
Strophe.Connection.prototype._dataRecv = function (req) {
    try {
        var elem = req.getResponse();
    } catch (e) {
        if (e != "parsererror") { throw e; }
        this.disconnect("strophe-parsererror");
    }
    if (elem === null) { return; }

    if (this.xmlInput !== Strophe.Connection.prototype.xmlInput) {
        this.xmlInput(elem);
    }
    if (this.rawInput !== Strophe.Connection.prototype.rawInput) {
        this.rawInput(Strophe.serialize(elem));
    }

    // remove handlers scheduled for deletion
    var i, hand;
    while (this.removeHandlers.length > 0) {
        hand = this.removeHandlers.pop();
        i = goog.array.indexOf(this.handlers, hand);
        if (i >= 0) {
            this.handlers.splice(i, 1);
        }
    }

    // add handlers scheduled for addition
    while (this.addHandlers.length > 0) {
        this.handlers.push(this.addHandlers.pop());
    }

    // handle graceful disconnect
    if (this.disconnecting && this._requests.length === 0) {
        this.deleteTimedHandler(this._disconnectTimeout);
        this._disconnectTimeout = null;
        this._doDisconnect();
        return;
    }

    var typ = elem.getAttribute("type");
    var cond, conflict;
    if (typ !== null && typ == "terminate") {
        // Don't process stanzas that come in after disconnect
        if (this.disconnecting) {
            return;
        }

        // an error occurred
        cond = elem.getAttribute("condition");
        conflict = elem.getElementsByTagName("conflict");
        if (cond !== null) {
            if (cond == "remote-stream-error" && conflict.length > 0) {
                cond = "conflict";
            }
            this._changeConnectStatus(Strophe.Status.CONNFAIL, cond);
        } else {
            this._changeConnectStatus(Strophe.Status.CONNFAIL, "unknown");
        }
        this.disconnect();
        return;
    }

    // send each incoming stanza through the handler chain
    var that = this;
    Strophe.forEachChild(elem, null, function (child) {
        var i, newList;
        // process handlers
        newList = that.handlers;
        that.handlers = [];
        for (i = 0; i < newList.length; i++) {
            var hand = newList[i];
            // encapsulate 'handler.run' not to lose the whole handler list if
            // one of the handlers throws an exception
            try {
                if (hand.isMatch(child) &&
                    (that.authenticated || !hand.user)) {
                    if (hand.run(child)) {
                        that.handlers.push(hand);
                    }
                } else {
                    that.handlers.push(hand);
                }
            } catch(e) {
                //if the handler throws an exception, we consider it as false
            }
        }
    });
};

/**
 *  _Private_ function to send initial disconnect sequence.
 *
 *  This is the first step in a graceful disconnect.  It sends
 *  the BOSH server a terminate body and includes an unavailable
 *  presence if authentication has completed.
 */
Strophe.Connection.prototype._sendTerminate = function () {
    Strophe.info("_sendTerminate was called");
    var body = this._buildBody().attrs({'type': "terminate"});

    if (this.authenticated) {
        body.c('presence', {
            'xmlns': Strophe.NS.CLIENT,
            'type': 'unavailable'
        });
    }

    this.disconnecting = true;

    var req = new Strophe.Request(body.tree(),
                                  goog.bind(this._onRequestStateChange, this, goog.bind(this._dataRecv, this)),
                                  parseInt(body.tree().getAttribute("rid"), 10));

    this._requests.push(req);
    this._throttledRequestHandler();
};

/**
 *  _Private_ handler for initial connection request.
 *
 *  This handler is used to process the initial connection request
 *  response from the BOSH server. It is used to set up authentication
 *  handlers and start the authentication process.
 *
 *  SASL authentication will be attempted if available, otherwise
 *  the code will fall back to legacy authentication.
 *
 * @param {Strophe.Request} req - The current request.
 */
Strophe.Connection.prototype._connect_cb = function (req) {
    Strophe.info("_connect_cb was called");

    this.connected = true;
    var bodyWrap = req.getResponse();
    if (!bodyWrap) { return; }

    if (this.xmlInput !== Strophe.Connection.prototype.xmlInput) {
        this.xmlInput(bodyWrap);
    }
    if (this.rawInput !== Strophe.Connection.prototype.rawInput) {
        this.rawInput(Strophe.serialize(bodyWrap));
    }

    var typ = bodyWrap.getAttribute("type");
    var cond, conflict;
    if (typ !== null && typ == "terminate") {
        // an error occurred
        cond = bodyWrap.getAttribute("condition");
        conflict = bodyWrap.getElementsByTagName("conflict");
        if (cond !== null) {
            if (cond == "remote-stream-error" && conflict.length > 0) {
                cond = "conflict";
            }
            this._changeConnectStatus(Strophe.Status.CONNFAIL, cond);
        } else {
            this._changeConnectStatus(Strophe.Status.CONNFAIL, "unknown");
        }
        return;
    }

    // check to make sure we don't overwrite these if _connect_cb is
    // called multiple times in the case of missing stream:features
    if (!this.sid) {
        this.sid = bodyWrap.getAttribute("sid");
    }
    if (!this.stream_id) {
        this.stream_id = bodyWrap.getAttribute("authid");
    }
    var wind = bodyWrap.getAttribute('requests');
    if (wind) { this.window = parseInt(wind, 10); }
    var hold = bodyWrap.getAttribute('hold');
    if (hold) { this.hold = parseInt(hold, 10); }
    var wait = bodyWrap.getAttribute('wait');
    if (wait) { this.wait = parseInt(wait, 10); }

    this._authentication.sasl_scram_sha1 = false;
    this._authentication.sasl_plain = false;
    this._authentication.sasl_digest_md5 = false;
    this._authentication.sasl_anonymous = false;
    this._authentication.legacy_auth = false;


    // Check for the stream:features tag
    var hasFeatures = bodyWrap.getElementsByTagName("stream:features").length > 0;
    if (!hasFeatures) {
        hasFeatures = bodyWrap.getElementsByTagName("features").length > 0;
    }
    var mechanisms = bodyWrap.getElementsByTagName("mechanism");
    var i, mech, auth_str, hashed_auth_str,
        found_authentication = false;
    if (hasFeatures && mechanisms.length > 0) {
        var missmatchedmechs = 0;
        for (i = 0; i < mechanisms.length; i++) {
            mech = Strophe.getText(mechanisms[i]);
            if (mech == 'SCRAM-SHA-1') {
                this._authentication.sasl_scram_sha1 = Strophe.ENABLE_SCRAM_SHA_1;
            } else if (mech == 'DIGEST-MD5') {
                this._authentication.sasl_digest_md5 = Strophe.ENABLE_DIGEST_MD5;
            } else if (mech == 'PLAIN') {
                this._authentication.sasl_plain = Strophe.ENABLE_PLAIN;
            } else if (mech == 'ANONYMOUS') {
                this._authentication.sasl_anonymous = Strophe.ENABLE_ANONYMOUS;
            } else missmatchedmechs++;
        }

        this._authentication.legacy_auth =
            Strophe.ENABLE_LEGACY_AUTH && bodyWrap.getElementsByTagName("auth").length > 0;

        found_authentication =
            this._authentication.legacy_auth ||
            missmatchedmechs < mechanisms.length;
    }
    if (!found_authentication) {
        // we didn't get stream:features yet, so we need wait for it
        // by sending a blank poll request
        var body = this._buildBody();
        this._requests.push(
            new Strophe.Request(body.tree(),
                                goog.bind(this._onRequestStateChange, this, goog.bind(this._connect_cb, this)),
                                parseInt(body.tree().getAttribute("rid"), 10)));
        this._throttledRequestHandler();
        return;
    }
    if (this.do_authentication !== false) {
        this.authenticate();
    }
};

if (Strophe.ENABLE_DIGEST_MD5 || Strophe.ENABLE_SCRAM_SHA_1) {
    /**
     * @param {Array.<number>} x
     */
    Strophe.md5 = function (x) {
        var md5 = new goog.crypt.Md5();
        md5.update(x);
        return md5.digest();
    };

    /**
     * @param {string} s
     * @return {string}
     */
    Strophe.hash = function (s) {
        return goog.crypt.byteArrayToString(Strophe.md5(goog.crypt.stringToByteArray(s)));
    };

    /**
     * @param {Array.<number>} key
     * @param {Array.<number>} data
     * @return {Array.<number>}
     */
    Strophe.hmac_md5 = function (key, data) {
        var md5  = new goog.crypt.Md5(),
            hmac = new goog.crypt.Hmac(md5, key);
        return hmac.getHmac(data);
    };

    /**
     * @param {string} s
     * @return {string}
     */
    Strophe.hexdigest = function (s) {
        return goog.crypt.byteArrayToHex(Strophe.md5(goog.crypt.stringToByteArray(s)));
    };
}

/**
 * Set up authentication
 *
 *  Contiunues the initial connection request by setting up authentication
 *  handlers and start the authentication process.
 *
 *  SASL authentication will be attempted if available, otherwise
 *  the code will fall back to legacy authentication.
 *
 */
Strophe.Connection.prototype.authenticate = function () {
    if (Strophe.getNodeFromJid(this.jid) === null &&
        this._authentication.sasl_anonymous) {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_success_handler = this._addSysHandler(
            goog.bind(this._sasl_success_cb, this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        this.send($build("auth", {
            'xmlns': Strophe.NS.SASL,
            'mechanism': "ANONYMOUS"
        }).tree());
    } else if (Strophe.getNodeFromJid(this.jid) === null) {
        // we don't have a node, which is required for non-anonymous
        // client connections
        this._changeConnectStatus(Strophe.Status.CONNFAIL, 'x-strophe-bad-non-anon-jid');
        this.disconnect();
    } else if (Strophe.ENABLE_SCRAM_SHA_1 && this._authentication.sasl_scram_sha1) {
        var cnonce = Strophe.hexdigest('' + Math.random() * 1234567890);

        var auth_str = "n=" + Strophe.getNodeFromJid(this.jid);
        auth_str += ",r=";
        auth_str += cnonce;

        this._sasl_data["cnonce"] = cnonce;
        this._sasl_data["client-first-message-bare"] = auth_str;

        auth_str = "n,," + auth_str;

        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_challenge_handler = this._addSysHandler(
            goog.bind(this._sasl_scram_challenge_cb, this), null,
            "challenge", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        this.send($build('auth', {
            'xmlns': Strophe.NS.SASL,
            'mechanism': 'SCRAM-SHA-1'
        }).t(goog.crypt.base64.encodeString(auth_str)).tree());
    } else if (Strophe.ENABLE_DIGEST_MD5 && this._authentication.sasl_digest_md5) {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_challenge_handler = this._addSysHandler(
            goog.bind(this._sasl_digest_challenge1_cb, this), null,
            "challenge", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        this.send($build("auth", {
            'xmlns': Strophe.NS.SASL,
            'mechanism': "DIGEST-MD5"
        }).tree());
    } else if (Strophe.ENABLE_PLAIN && this._authentication.sasl_plain) {
        // Build the plain auth string (barejid null
        // username null password) and base 64 encoded.
        auth_str = Strophe.getBareJidFromJid(this.jid);
        auth_str = auth_str + "\u0000";
        auth_str = auth_str + Strophe.getNodeFromJid(this.jid);
        auth_str = auth_str + "\u0000";
        auth_str = auth_str + this.pass;

        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_success_handler = this._addSysHandler(
            goog.bind(this._sasl_success_cb, this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        var hashed_auth_str = goog.crypt.base64.encodeString(auth_str);
        this.send($build("auth", {
            'xmlns': Strophe.NS.SASL,
            'mechanism': "PLAIN"
        }).t(hashed_auth_str).tree());
    } else {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._addSysHandler(goog.bind(this._auth1_cb, this), null, null,
                            null, "_auth_1");

        this.send($iq({
            'type': "get",
            'to': this.domain,
            'id': "_auth_1"
        }).c("query", {
            'xmlns': Strophe.NS.AUTH
        }).c("username", {}).t(Strophe.getNodeFromJid(this.jid) || '').tree());
    }
};

if (Strophe.ENABLE_DIGEST_MD5) {
    /**
     *  _Private_ handler for DIGEST-MD5 SASL authentication.
     *
     * @param {Element} elem - The challenge stanza.
     *
     * @return {boolean}
     *    false to remove the handler.
     */
    Strophe.Connection.prototype._sasl_digest_challenge1_cb = function (elem) {
        var challenge = goog.crypt.base64.decodeString(Strophe.getText(elem)),
            cnonce    = Strophe.hexdigest('' + (Math.random() * 1234567890));

        // remove unneeded handlers
        this.deleteHandler(this._sasl_failure_handler);

        var realm = '', nonce, qop, host;
        challenge.replace(/([a-z]+)=("[^"]+"|[^,"]+)(?:,|$)/g, function(match, key, value) {
            value = value.replace(/^"(.+)"$/, "$1");
            switch (key) {
            case "realm":
                realm = value;
                break;
            case "nonce":
                nonce = value;
                break;
            case "qop":
                qop   = value;
                break;
            case "host":
                host  = value;
                break;
            }
        });

        var digest_uri = "xmpp/" + this.domain;
        if (goog.isDefAndNotNull(host)) {
            digest_uri = digest_uri + "/" + host;
        }

        var A1 = Strophe.hash(Strophe.getNodeFromJid(this.jid) +
                              ":" + realm + ":" + this.pass) +
                 ":" + nonce + ":" + cnonce;
        var A2 = 'AUTHENTICATE:' + digest_uri;

        var responseText = "";
        responseText += 'username=' +
            goog.string.quote(Strophe.getNodeFromJid(this.jid) || '') + ',';
        responseText += 'realm=' + goog.string.quote(realm) + ',';
        responseText += 'nonce=' + goog.string.quote(nonce) + ',';
        responseText += 'cnonce=' + goog.string.quote(cnonce) + ',';
        responseText += 'nc="00000001",';
        responseText += 'qop="auth",';
        responseText += 'digest-uri=' + goog.string.quote(digest_uri) + ',';
        responseText += 'response=' + goog.string.quote(
            Strophe.hexdigest(Strophe.hexdigest(A1) + ":" +
                              nonce + ":00000001:" +
                              cnonce + ":auth:" +
                              Strophe.hexdigest(A2))) + ',';
        responseText += 'charset="utf-8"';

        this._sasl_challenge_handler = this._addSysHandler(
            goog.bind(this._sasl_digest_challenge2_cb, this), null,
            "challenge", null, null);
        this._sasl_success_handler = this._addSysHandler(
            goog.bind(this._sasl_success_cb, this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        this.send($build('response', {
            'xmlns': Strophe.NS.SASL
        }).t(goog.crypt.base64.encodeString(responseText)).tree());

        return false;
    };

    /**
     *  _Private_ handler for second step of DIGEST-MD5 SASL authentication.
     *
     * @param {Element} elem - The challenge stanza.
     *
     * @return {boolean}
     *    false to remove the handler.
     */
    Strophe.Connection.prototype._sasl_digest_challenge2_cb = function (elem) {
        // remove unneeded handlers
        this.deleteHandler(this._sasl_success_handler);
        this.deleteHandler(this._sasl_failure_handler);

        this._sasl_success_handler = this._addSysHandler(
            goog.bind(this._sasl_success_cb, this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);
        this.send($build('response', {'xmlns': Strophe.NS.SASL}).tree());
        return false;
    };
}

if (Strophe.ENABLE_SCRAM_SHA_1) {
    /**
     * @param {Array.<number>} x
     * @return {Array.<number>}
     */
    Strophe.sha1 = function (x) {
        var sha1 = new goog.crypt.Sha1();
        sha1.update(x);
        return sha1.digest();
    };

    /**
     * @param {Array.<number>} key
     * @param {Array.<number>} data
     * @return {Array.<number>}
     */
    Strophe.hmac_sha1 = function (key, data) {
        var sha1 = new goog.crypt.Sha1(),
            hmac = new goog.crypt.Hmac(sha1, key);
        return hmac.getHmac(data);
    };

    /**
     *  _Private_ handler for SCRAM-SHA-1 SASL authentication.
     *
     * @param {Element} elem - The challenge stanza.
     *
     * @return {boolean}
     *    false to remove the handler.
     */
    Strophe.Connection.prototype._sasl_scram_challenge_cb = function (elem) {
        var challenge = goog.crypt.base64.decodeString(Strophe.getText(elem));

        // remove unneeded handlers
        this.deleteHandler(this._sasl_failure_handler);

        var nonce, salt, iter;
        challenge.replace(/([a-z]+)=([^,]+)(,|$)/g, function(match, key, value) {
            switch (key) {
            case 'r':
                nonce = value;
                break;
            case 's':
                salt  = goog.array.concat(goog.crypt.base64.decodeStringToByteArray(value), 0, 0, 0, 1);
                break;
            case 'i':
                iter  = value;
                break;
            }
        });

        if (! goog.string.startsWith(nonce, this._sasl_data['cnonce'])) {
            this._sasl_data = [];
            return this._sasl_failure_cb(null);
        }

        var responseText = 'c=biws,r=' + nonce,
            authMessage  = goog.crypt.stringToByteArray(
                this._sasl_data['client-first-message-bare'] + ',' + challenge + ',' + responseText);

        var password = goog.crypt.stringToByteArray(this.pass),
            U_old    = Strophe.hmac_sha1(password, salt),
            saltedPassword = U_old;

        for (var i = 1; i < iter; i++) {
            var U = Strophe.hmac_sha1(password, U_old);
            for (var k = 0; k < 20; ++k) {
                saltedPassword[k] ^= U[k];
            }
            U_old = U;
        }

        var clientKey       = Strophe.hmac_sha1(saltedPassword, goog.crypt.stringToByteArray('Client Key')),
            storedKey       = Strophe.sha1(clientKey),
            clientSignature = Strophe.hmac_sha1(storedKey, authMessage),
            clientProof     = clientKey,
            serverKey       = Strophe.hmac_sha1(saltedPassword, goog.crypt.stringToByteArray('Server Key')),
            serverSignature = Strophe.hmac_sha1(serverKey, authMessage);

        this._sasl_data["server-signature"] = goog.crypt.base64.encodeByteArray(serverSignature);

        for (var k = 0; k < 20; ++k) {
            clientProof[k] ^= clientSignature[k];
        }

        responseText += ",p=" + goog.crypt.base64.encodeByteArray(clientProof);

        this._sasl_success_handler = this._addSysHandler(
            goog.bind(this._sasl_success_cb, this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            goog.bind(this._sasl_failure_cb, this), null,
            "failure", null, null);

        this.send($build('response', {
            'xmlns': Strophe.NS.SASL
        }).t(goog.crypt.base64.encodeString(responseText)).tree());

        return false;
    };
}

if (Strophe.ENABLE_LEGACY_AUTH) {
    /**
     *  _Private_ handler for legacy authentication.
     *
     *  This handler is called in response to the initial <iq type='get'/>
     *  for legacy authentication.  It builds an authentication <iq/> and
     *  sends it, creating a handler (calling back to _auth2_cb()) to
     *  handle the result
     *
     * @param {Element} elem - The stanza that triggered the callback.
     *
     * @return {boolean}
     *    false to remove the handler.
     */
    Strophe.Connection.prototype._auth1_cb = function (elem) {
        // build plaintext auth iq
        var iq = $iq({'type': "set", 'id': "_auth_2"})
            .c('query', {'xmlns': Strophe.NS.AUTH})
            .c('username', {}).t(Strophe.getNodeFromJid(this.jid) || '')
            .up()
            .c('password').t(this.pass);

        if (!Strophe.getResourceFromJid(this.jid)) {
            // since the user has not supplied a resource, we pick
            // a default one here.  unlike other auth methods, the server
            // cannot do this for us.
            this.jid = Strophe.getBareJidFromJid(this.jid) + '/strophe';
        }
        iq.up().c('resource', {}).t(Strophe.getResourceFromJid(this.jid) || '');

        this._addSysHandler(goog.bind(this._auth2_cb, this), null,
                            null, null, "_auth_2");

        this.send(iq.tree());

        return false;
    };
}

/**
 *  _Private_ handler for succesful SASL authentication.
 *
 * @param {Element} elem - The matching stanza.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._sasl_success_cb = function (elem) {
    if (this._sasl_data["server-signature"]) {
        var serverSignature;
        var success = goog.crypt.base64.decodeString(Strophe.getText(elem));
        var attribMatch = /([a-z]+)=([^,]+)(,|$)/;
        var matches = success.match(attribMatch);
        if (matches[1] == "v") {
            serverSignature = matches[2];
        }
        if (serverSignature != this._sasl_data["server-signature"]) {
            // remove old handlers
            this.deleteHandler(this._sasl_failure_handler);
            this._sasl_failure_handler = null;
            if (this._sasl_challenge_handler) {
                    this.deleteHandler(this._sasl_challenge_handler);
                    this._sasl_challenge_handler = null;
            }

            this._sasl_data = [];
            return this._sasl_failure_cb(null);
        }
    }

    Strophe.info("SASL authentication succeeded.");

    // remove old handlers
    this.deleteHandler(this._sasl_failure_handler);
    this._sasl_failure_handler = null;
    if (this._sasl_challenge_handler) {
        this.deleteHandler(this._sasl_challenge_handler);
        this._sasl_challenge_handler = null;
    }

    this._addSysHandler(goog.bind(this._sasl_auth1_cb, this), null,
                        "stream:features", null, null);

    // we must send an xmpp:restart now
    this._sendRestart();

    return false;
};

/**
 *  _Private_ handler to start stream binding.
 *
 * @param {Element} elem - The matching stanza.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._sasl_auth1_cb = function (elem) {
    // save stream:features for future usage
    this.features = elem;

    var i, child;

    for (i = 0; i < elem.childNodes.length; i++) {
        child = elem.childNodes[i];
        if (child.nodeName == 'bind') {
            this.do_bind = true;
        }

        if (child.nodeName == 'session') {
            this.do_session = true;
        }
    }

    if (!this.do_bind) {
        this._changeConnectStatus(Strophe.Status.AUTHFAIL, null);
        return false;
    } else {
        this._addSysHandler(goog.bind(this._sasl_bind_cb, this), null, null,
                            null, "_bind_auth_2");

        var resource = Strophe.getResourceFromJid(this.jid);
        if (resource) {
            this.send($iq({'type': "set", 'id': "_bind_auth_2"})
                      .c('bind', {'xmlns': Strophe.NS.BIND})
                      .c('resource', {}).t(resource).tree());
        } else {
            this.send($iq({'type': "set", 'id': "_bind_auth_2"})
                      .c('bind', {'xmlns': Strophe.NS.BIND})
                      .tree());
        }
    }

    return false;
};

/**
 *  _Private_ handler for binding result and session start.
 *
 * @param {Element} elem - The matching stanza.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._sasl_bind_cb = function (elem) {
    if (elem.getAttribute("type") == "error") {
        Strophe.info("SASL binding failed.");
        var conflict = elem.getElementsByTagName("conflict"), condition = null;
        if (conflict.length > 0) {
                condition = 'conflict';
        }
        this._changeConnectStatus(Strophe.Status.AUTHFAIL, condition);
        return false;
    }

    // TODO - need to grab errors
    var bind = elem.getElementsByTagName("bind");
    var jidNode;
    if (bind.length > 0) {
        // Grab jid
        jidNode = bind[0].getElementsByTagName("jid");
        if (jidNode.length > 0) {
            this.jid = Strophe.getText(jidNode[0]);

            if (this.do_session) {
                this._addSysHandler(goog.bind(this._sasl_session_cb, this),
                                    null, null, null, "_session_auth_2");

                this.send($iq({'type': "set", 'id': "_session_auth_2"})
                              .c('session', {'xmlns': Strophe.NS.SESSION})
                              .tree());
            } else {
                this.authenticated = true;
                this._changeConnectStatus(Strophe.Status.CONNECTED, null);
            }
        }

        return false;
    } else {
        Strophe.info("SASL binding failed.");
        this._changeConnectStatus(Strophe.Status.AUTHFAIL, null);
        return false;
    }
};

/**
 *  _Private_ handler to finish successful SASL connection.
 *
 *  This sets Connection.authenticated to true on success, which
 *  starts the processing of user handlers.
 *
 * @param {Element} elem - The matching stanza.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._sasl_session_cb = function (elem) {
    if (elem.getAttribute("type") == "result") {
        this.authenticated = true;
        this._changeConnectStatus(Strophe.Status.CONNECTED, null);
    } else if (elem.getAttribute("type") == "error") {
        Strophe.info("Session creation failed.");
        this._changeConnectStatus(Strophe.Status.AUTHFAIL, null);
        return false;
    }

    return false;
};

/**
 *  _Private_ handler for SASL authentication failure.
 *
 * @param {Element} elem - The matching stanza.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._sasl_failure_cb = function (elem) {
    // delete unneeded handlers
    if (this._sasl_success_handler) {
        this.deleteHandler(this._sasl_success_handler);
        this._sasl_success_handler = null;
    }
    if (this._sasl_challenge_handler) {
        this.deleteHandler(this._sasl_challenge_handler);
        this._sasl_challenge_handler = null;
    }

    this._changeConnectStatus(Strophe.Status.AUTHFAIL, null);
    return false;
};

/**
 *  _Private_ handler to finish legacy authentication.
 *
 *  This handler is called when the result from the jabber:iq:auth
 *  <iq/> stanza is returned.
 *
 * @param {Element} elem - The stanza that triggered the callback.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._auth2_cb = function (elem) {
    if (elem.getAttribute("type") == "result") {
        this.authenticated = true;
        this._changeConnectStatus(Strophe.Status.CONNECTED, null);
    } else if (elem.getAttribute("type") == "error") {
        this._changeConnectStatus(Strophe.Status.AUTHFAIL, null);
        this.disconnect();
    }

    return false;
};

/**
 *  _Private_ function to add a system level timed handler.
 *
 *  This function is used to add a Strophe.TimedHandler for the
 *  library code.  System timed handlers are allowed to run before
 *  authentication is complete.
 *
 * @param {number} period - The period of the handler.
 * @param {function()} handler - The callback function.
 */
Strophe.Connection.prototype._addSysTimedHandler = function (period, handler) {
    var thand = new Strophe.TimedHandler(period, handler);
    thand.user = false;
    this.addTimeds.push(thand);
    return thand;
};

/**
 *  _Private_ function to add a system level stanza handler.
 *
 *  This function is used to add a Strophe.Handler for the
 *  library code.  System stanza handlers are allowed to run before
 *  authentication is complete.
 *
 * @param {!function()} handler - The callback function.
 * @param {?string} ns - The namespace to match.
 * @param {?string} name - The stanza name to match.
 * @param {?string} type - The stanza type attribute to match.
 * @param {?string} id - The stanza id attribute to match.
 * @return {!Strophe.Handler}
 */
Strophe.Connection.prototype._addSysHandler = function (handler, ns, name, type, id) {
    var hand = new Strophe.Handler(handler, ns, name, type, id);
    hand.user = false;
    this.addHandlers.push(hand);
    return hand;
};

/**
 *  _Private_ timeout handler for handling non-graceful disconnection.
 *
 *  If the graceful disconnect process does not complete within the
 *  time allotted, this handler finishes the disconnect anyway.
 *
 * @return {boolean}
 *    false to remove the handler.
 */
Strophe.Connection.prototype._onDisconnectTimeout = function () {
    Strophe.info("_onDisconnectTimeout was called");

    // cancel all remaining requests and clear the queue
    var req;
    while (this._requests.length > 0) {
        req = this._requests.pop();
        req.abort = true;
        req.xhr.dispose();
    }

    // actually disconnect
    this._doDisconnect();

    return false;
};

/**
 *  _Private_ handler to process events during idle cycle.
 *
 *  This handler is called every 100ms to fire timed handlers that
 *  are ready and keep poll requests going.
 */
Strophe.Connection.prototype._onIdle = function () {
    var i, thand, since, newList;

    // add timed handlers scheduled for addition
    // NOTE: we add before remove in the case a timed handler is
    // added and then deleted before the next _onIdle() call.
    while (this.addTimeds.length > 0) {
        this.timedHandlers.push(this.addTimeds.pop());
    }

    // remove timed handlers that have been scheduled for deletion
    while (this.removeTimeds.length > 0) {
        thand = this.removeTimeds.pop();
        i = goog.array.indexOf(this.timedHandlers, thand);
        if (i >= 0) {
            this.timedHandlers.splice(i, 1);
        }
    }

    // call ready timed handlers
    var now = goog.now();
    newList = [];
    for (i = 0; i < this.timedHandlers.length; i++) {
        thand = this.timedHandlers[i];
        if (this.authenticated || !thand.user) {
            since = thand.lastCalled + thand.period;
            if (since - now <= 0) {
                if (thand.run()) {
                    newList.push(thand);
                }
            } else {
                newList.push(thand);
            }
        }
    }
    this.timedHandlers = newList;

    var body, time_elapsed;

    // if no requests are in progress, poll
    if (this.authenticated && this._requests.length === 0 &&
        this._data.length === 0 && !this.disconnecting) {
        Strophe.info("no requests during idle cycle, sending " +
                     "blank request");
        this._data.push(null);
    }

    if (this._requests.length < 2 && this._data.length > 0 &&
        !this.paused) {
        body = this._buildBody();
        for (i = 0; i < this._data.length; i++) {
            if (this._data[i] !== null) {
                if (this._data[i] === "restart") {
                    body.attrs({
                        'to': this.domain,
                        "xml:lang": "en",
                        "xmpp:restart": "true",
                        "xmlns:xmpp": Strophe.NS.BOSH
                    });
                } else {
                    body.cnode(this._data[i]).up();
                }
            }
        }
        delete this._data;
        this._data = [];
        this._requests.push(
            new Strophe.Request(body.tree(),
                                goog.bind(this._onRequestStateChange, this, goog.bind(this._dataRecv, this)),
                                parseInt(body.tree().getAttribute("rid"), 10)));
        this._processRequest(this._requests.length - 1);
    }

    if (this._requests.length > 0) {
        time_elapsed = this._requests[0].age();
        if (this._requests[0].dead !== null) {
            if (this._requests[0].timeDead() >
                Math.floor(Strophe.SECONDARY_TIMEOUT * this.wait)) {
                this._throttledRequestHandler();
            }
        }

        if (time_elapsed > Math.floor(Strophe.TIMEOUT * this.wait)) {
            Strophe.warn("Request " +
                         this._requests[0].id +
                         " timed out, over " + Math.floor(Strophe.TIMEOUT * this.wait) +
                         " seconds since last activity");
            this._throttledRequestHandler();
        }
    }

    clearTimeout(this._idleTimeout);

    // reactivate the timer only if connected
    if (this.connected) {
        this._idleTimeout = setTimeout(goog.bind(this._onIdle, this), 100);
    }
};
