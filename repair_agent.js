// Frida agent for repair_worker.py: gets decrypted copies of FairPlay-encrypted ranges.
//
// iOS 15 and earlier (decrypt/read/release): the range is mapped from the installed file and
// handed to mremap_encrypted(), so the kernel decrypts it with the app's keys. This works in
// frida-server's own process, so no app has to run.
//
// iOS 16 and later refuse that, so the system loads the code instead and it is read from memory:
// imageBase/readAt read the decrypted image of a process (an app spawned suspended, or an app
// extension started with launchExtension and caught suspended by spawn gating). Frameworks are
// loaded with loadImage into the app, once hookAppMain has let it start without its UI.
//
// Works with Frida 12 through 17 and needs no Objective-C bridge. It is written in ES5: Frida 12
// runs scripts in Duktape, which does not parse let/const, arrow functions or method shorthands.

'use strict';

var O_RDONLY = 0;
var PROT_READ = 1;
var PROT_EXEC = 4;
var MAP_PRIVATE = 2;

function exported(name) {
  if (typeof Module.getGlobalExportByName === 'function') {
    return Module.getGlobalExportByName(name); // Frida 17
  }
  return Module.getExportByName(null, name); // Frida 12 to 16
}

function endsWith(text, suffix) {
  return text.length >= suffix.length && text.substr(text.length - suffix.length) === suffix;
}

function moduleExport(module, name) {
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(module, name); // Frida 16
  }
  var found = Process.findModuleByName(module); // Frida 17
  return found === null ? null : found.findExportByName(name);
}

// Frida 12 has no 'size_t' argument type.
var SIZE_T = Process.pointerSize === 8 ? 'uint64' : 'uint32';

var open = new SystemFunction(exported('open'), 'int', ['pointer', 'int']);
var close = new NativeFunction(exported('close'), 'int', ['int']);
var mmap = new SystemFunction(exported('mmap'), 'pointer', ['pointer', SIZE_T, 'int', 'int', 'int', 'int64']);
var munmap = new NativeFunction(exported('munmap'), 'int', ['pointer', SIZE_T]);
var mremapEncrypted = new SystemFunction(exported('mremap_encrypted'), 'int',
  ['pointer', SIZE_T, 'uint32', 'uint32', 'uint32']);
var strerror = new NativeFunction(exported('strerror'), 'pointer', ['int']);

var mappings = {};
var nextId = 1;

function failure(call, result) {
  return call + ' failed: ' + strerror(result.errno).readUtf8String() + ' (errno ' + result.errno + ')';
}

// Objective-C through objc_msgSend, so Frida 17 needs no bridge.
var objc = null;
function objcApi() {
  if (objc === null) {
    var fn = function (name, ret, args) { return new NativeFunction(exported(name), ret, args); };
    var getClass = fn('objc_getClass', 'pointer', ['pointer']);
    var registerName = fn('sel_registerName', 'pointer', ['pointer']);
    var send = function (args, ret) {
      return fn('objc_msgSend', ret || 'pointer', ['pointer', 'pointer'].concat(args));
    };
    objc = {
      cls: function (name) { return getClass(Memory.allocUtf8String(name)); },
      sel: function (name) { return registerName(Memory.allocUtf8String(name)); },
      send: send,
      str: function (text) {
        return send(['pointer'])(objc.cls('NSString'), objc.sel('stringWithUTF8String:'), Memory.allocUtf8String(text));
      },
    };
  }
  return objc;
}

rpc.exports = {
  // Decrypt one slice in memory with mremap_encrypted; returns an id for read()/release().
  decrypt: function (path, offset, cryptoff, cryptsize, cryptid, cpu, subtype) {
    var fd = open.call(null, Memory.allocUtf8String(path), O_RDONLY);
    if (fd.value < 0) {
      throw new Error(failure('open', fd));
    }
    try {
      var page = Process.pageSize;
      var start = offset + cryptoff;
      var aligned = start - (start % page);
      var delta = start - aligned;
      var length = cryptsize + delta;
      var mapped = mmap.call(null, NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd.value, aligned);
      if (mapped.value.equals(ptr('-1'))) {
        throw new Error(failure('mmap', mapped));
      }
      var result = mremapEncrypted.call(null, mapped.value.add(delta), cryptsize, cryptid, cpu >>> 0, subtype >>> 0);
      if (result.value !== 0) {
        munmap(mapped.value, length);
        throw new Error(failure('mremap_encrypted', result));
      }
      var id = nextId++;
      mappings[id] = { base: mapped.value, length: length, delta: delta, size: cryptsize };
      return id;
    } finally {
      close(fd.value);
    }
  },

  // Bytes [start, start + size) of a range decrypted by decrypt().
  read: function (id, start, size) {
    var mapping = mappings[id];
    return mapping.base.add(mapping.delta + start).readByteArray(size);
  },

  release: function (id) {
    var mapping = mappings[id];
    if (mapping) {
      munmap(mapping.base, mapping.length);
      delete mappings[id];
    }
  },

  // Where the image whose path ends with suffix is loaded, with its CPU type, or null.
  // A process spawned suspended has no module list yet, but the kernel has already mapped
  // (and set up decryption for) its main executable.
  imageBase: function (suffix) {
    var base = null;
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length && base === null; i++) {
      if (endsWith(modules[i].path, suffix)) {
        base = modules[i].base;
      }
    }
    if (base === null) {
      var ranges = Process.enumerateRanges('r--');
      for (var j = 0; j < ranges.length && base === null; j++) {
        var r = ranges[j];
        if (r.file && r.file.offset === 0 && endsWith(r.file.path, suffix)) {
          base = r.base;
        }
      }
    }
    if (base === null) {
      return null;
    }
    return { base: base.toString(), cpu: base.add(4).readS32(), subtype: base.add(8).readS32() };
  },

  readAt: function (base, offset, size) {
    return ptr(base).add(offset).readByteArray(size);
  },

  // iOS 16 and later decrypt a framework only when it is loaded, and loading needs the app to be
  // past dyld's setup. Called before an app spawned suspended is resumed: UIApplicationMain is
  // replaced by a bare run loop, so the app never brings up its UI (its initializers still run).
  hookAppMain: function () {
    var runLoop = moduleExport('CoreFoundation', 'CFRunLoopRun');
    var hooked = false;
    var names = ['UIKitCore', 'UIKit'];
    for (var i = 0; i < names.length; i++) {
      var main = moduleExport(names[i], 'UIApplicationMain');
      if (main !== null && runLoop !== null) {
        Interceptor.replace(main, runLoop);
        hooked = true;
        break;
      }
    }
    return hooked;
  },

  // Load a framework or dylib (dlopen) so the system decrypts it; imageBase() then finds it.
  loadImage: function (path) {
    return Module.load(path).base.toString();
  },

  // Ask the system to start an app extension, as a host does when it uses one. The caller has
  // spawn gating on, so the extension stops before running any code. Returns what was found.
  launchExtension: function (identifier) {
    var o = objcApi();
    var error = Memory.alloc(Process.pointerSize);
    var extension = o.send(['pointer', 'pointer'])(o.cls('NSExtension'), o.sel('extensionWithIdentifier:error:'),
      o.str(identifier), error);
    if (extension.isNull()) {
      return { found: false };
    }
    var items = o.send([])(o.cls('NSArray'), o.sel('array'));
    // Fails once the gated extension does not answer; by then it has been read.
    o.send(['pointer', 'pointer'])(extension, o.sel('beginExtensionRequestWithInputItems:error:'), items, error);
    return { found: true };
  },
};
