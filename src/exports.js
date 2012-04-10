goog.exportSymbol('$build', $build);
goog.exportSymbol('$msg', $msg);
goog.exportSymbol('$iq', $iq);
goog.exportSymbol('$pres', $pres);

goog.exportSymbol('Strophe', Strophe);
goog.exportProperty(Strophe, 'addConnectionPlugin', Strophe.addConnectionPlugin);
goog.exportProperty(Strophe, 'addNamespace', Strophe.addNamespace);
goog.exportProperty(Strophe, 'forEachChild', Strophe.forEachChild);
goog.exportProperty(Strophe, 'getText', Strophe.getText);
goog.exportProperty(Strophe, 'getNodeFromJid', Strophe.getNodeFromJid);
goog.exportProperty(Strophe, 'getDomainFromJid', Strophe.getDomainFromJid);
goog.exportProperty(Strophe, 'getResourceFromJid', Strophe.getResourceFromJid);
goog.exportProperty(Strophe, 'getBareJidFromJid', Strophe.getBareJidFromJid);

goog.exportProperty(Strophe, 'NS', Strophe.NS);
goog.exportProperty(Strophe.NS, 'DISCO_INFO', Strophe.NS.DISCO_INFO);
goog.exportProperty(Strophe.NS, 'ROSTER', Strophe.NS.ROSTER);

goog.exportProperty(Strophe, 'Status', Strophe.Status);
goog.exportProperty(Strophe.Status, 'ERROR', Strophe.Status.ERROR);
goog.exportProperty(Strophe.Status, 'CONNECTING', Strophe.Status.CONNECTING);
goog.exportProperty(Strophe.Status, 'CONNFAIL', Strophe.Status.CONNFAIL);
goog.exportProperty(Strophe.Status, 'AUTHENTICATING', Strophe.Status.AUTHENTICATING);
goog.exportProperty(Strophe.Status, 'AUTHFAIL', Strophe.Status.AUTHFAIL);
goog.exportProperty(Strophe.Status, 'CONNECTED', Strophe.Status.CONNECTED);
goog.exportProperty(Strophe.Status, 'DISCONNECTED', Strophe.Status.DISCONNECTED);
goog.exportProperty(Strophe.Status, 'DISCONNECTING', Strophe.Status.DISCONNECTING);
goog.exportProperty(Strophe.Status, 'ATTACHED', Strophe.Status.ATTACHED);

goog.exportProperty(Strophe, 'Builder', Strophe.Builder);
goog.exportProperty(Strophe.Builder.prototype, 'tree', Strophe.Builder.prototype.tree);
goog.exportProperty(Strophe.Builder.prototype, 'toString', Strophe.Builder.prototype.toString);
goog.exportProperty(Strophe.Builder.prototype, 'up', Strophe.Builder.prototype.up);
goog.exportProperty(Strophe.Builder.prototype, 'attrs', Strophe.Builder.prototype.attrs);
goog.exportProperty(Strophe.Builder.prototype, 'c', Strophe.Builder.prototype.c);
goog.exportProperty(Strophe.Builder.prototype, 'cnode', Strophe.Builder.prototype.cnode);
goog.exportProperty(Strophe.Builder.prototype, 't', Strophe.Builder.prototype.t);
goog.exportProperty(Strophe.Builder.prototype, 'h', Strophe.Builder.prototype.h);

goog.exportProperty(Strophe, 'Connection', Strophe.Connection);
goog.exportProperty(Strophe.Connection.prototype, 'disconnect', Strophe.Connection.prototype.disconnect);
goog.exportProperty(Strophe.Connection.prototype, 'flush', Strophe.Connection.prototype.flush);
goog.exportProperty(Strophe.Connection.prototype, 'pause', Strophe.Connection.prototype.pause);
goog.exportProperty(Strophe.Connection.prototype, 'reset', Strophe.Connection.prototype.reset);
goog.exportProperty(Strophe.Connection.prototype, 'resume', Strophe.Connection.prototype.resume);
goog.exportProperty(Strophe.Connection.prototype, 'jid', Strophe.Connection.prototype.jid);
goog.exportProperty(Strophe.Connection.prototype, 'getUniqueId', Strophe.Connection.prototype.getUniqueId);
goog.exportProperty(Strophe.Connection.prototype, 'addHandler', Strophe.Connection.prototype.addHandler);
goog.exportProperty(Strophe.Connection.prototype, 'connect', Strophe.Connection.prototype.connect);
goog.exportProperty(Strophe.Connection.prototype, 'attach', Strophe.Connection.prototype.attach);
goog.exportProperty(Strophe.Connection.prototype, 'send', Strophe.Connection.prototype.send);
goog.exportProperty(Strophe.Connection.prototype, 'sendIQ', Strophe.Connection.prototype.sendIQ);
