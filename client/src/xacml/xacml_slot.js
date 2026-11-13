// File: xacml_slot.js
//
// The one-instance holder the editor and the ALFA reader were written
// against. Loading the module builds the default instance. There is no
// composition root in this debugger.

'use strict';

function InstanceSlot(name, build, wire, log) {
  log.debug("Entering InstanceSlot.constructor(). " + name);
  this.name = name;
  this.build = build;
  this.wire = wire;
  this.log = log;
  this.instance = null;
  this.how = "none";
  log.debug("Leaving InstanceSlot.constructor().");
}

InstanceSlot.deferred = false;

InstanceSlot.prototype.install = function (instance) {
  this.log.debug("Entering InstanceSlot.install(). " + this.name);
  if (this.instance) {
    this.log.debug("Leaving InstanceSlot.install(). Already " +
                   this.how + ".");
    throw new Error(this.name + ": an instance is already installed (" +
                    this.how + ").");
  }
  this.instance = instance;
  this.how = "root";
  if (this.wire) {
    this.wire(instance);
  }
  this.log.debug("Leaving InstanceSlot.install().");
};

// Called on every facade call. No Entering/Leaving pair: this is the
// hot path the editor walks once per node of a redraw.
InstanceSlot.prototype.get = function () {
  if (this.instance) {
    return this.instance;
  }
  var built = this.build();
  this.instance = built;
  this.how = "default";
  if (this.wire) {
    this.wire(built);
  }
  return built;
};

InstanceSlot.prototype.buildNowUnlessDeferred = function () {
  this.log.debug("Entering InstanceSlot.buildNowUnlessDeferred(). " +
                 this.name);
  if (!InstanceSlot.deferred) {
    this.get();
  }
  this.log.debug("Leaving InstanceSlot.buildNowUnlessDeferred(). " +
                 this.how);
};

InstanceSlot.prototype.origin = function () {
  this.log.debug("Entering InstanceSlot.origin(). " + this.name);
  this.log.debug("Leaving InstanceSlot.origin(). " + this.how);
  return this.how;
};

InstanceSlot.prototype.forward = function (key) {
  this.log.debug("Entering InstanceSlot.forward(). " + this.name +
                 "." + String(key));
  var slot = this;
  // Runs on every facade call. No Entering/Leaving pair: the hot-path
  // exception, same as get().
  var facade = function () {
    var target = slot.get();
    return target[key].apply(target, arguments);
  };
  Object.defineProperty(facade, "name", {
    value: "bound " + String(key)
  });
  this.log.debug("Leaving InstanceSlot.forward().");
  return facade;
};

module.exports = InstanceSlot;
