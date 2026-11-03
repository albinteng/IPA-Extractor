// Frida agent for repair_worker.py: gets decrypted copies of FairPlay-encrypted ranges.
//
// iOS 15 and earlier (decrypt/read/release): the range is mapped from the installed file and
// handed to mremap_encrypted(), so the kernel decrypts it with the app's keys. This works in
// frida-server's own process, so no app has to run.
//
// iOS 16 and later refuse that, so the system loads the code instead and it is read from memory:
// imageBase/readAt read the decrypted image of a process (an app spawned suspended, or an app
// extension started with launchExtension and caught suspended by spawn gating).
//
// Works with Frida 16 and 17 and needs no Objective-C bridge.

'use strict';

const O_RDONLY = 0;
const PROT_READ = 1;
const PROT_EXEC = 4;
const MAP_PRIVATE = 2;

function exported(name) {
  if (typeof Module.getGlobalExportByName === 'function') {
    return Module.getGlobalExportByName(name); // Frida 17
  }
  return Module.getExportByName(null, name); // Frida 16
}

const open = new SystemFunction(exported('open'), 'int', ['pointer', 'int']);
const close = new NativeFunction(exported('close'), 'int', ['int']);
const mmap = new SystemFunction(exported('mmap'), 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'int64']);
const munmap = new NativeFunction(exported('munmap'), 'int', ['pointer', 'size_t']);
const mremapEncrypted = new SystemFunction(exported('mremap_encrypted'), 'int',
  ['pointer', 'size_t', 'uint32', 'uint32', 'uint32']);
const strerror = new NativeFunction(exported('strerror'), 'pointer', ['int']);

const mappings = new Map();
let nextId = 1;

function failure(call, result) {
  return call + ' failed: ' + strerror(result.errno).readUtf8String() + ' (errno ' + result.errno + ')';
}

// Objective-C through objc_msgSend, so Frida 17 needs no bridge.
let objc = null;
function objcApi() {
  if (objc === null) {
    const fn = (name, ret, args) => new NativeFunction(exported(name), ret, args);
    const getClass = fn('objc_getClass', 'pointer', ['pointer']);
    const registerName = fn('sel_registerName', 'pointer', ['pointer']);
    const send = (args, ret) => fn('objc_msgSend', ret || 'pointer', ['pointer', 'pointer'].concat(args));
    objc = {
      cls: (name) => getClass(Memory.allocUtf8String(name)),
      sel: (name) => registerName(Memory.allocUtf8String(name)),
      send: send,
      str: (text) => send(['pointer'])(objc.cls('NSString'), objc.sel('stringWithUTF8String:'), Memory.allocUtf8String(text)),
    };
  }
  return objc;
}

rpc.exports = {
  // Decrypt one slice in memory with mremap_encrypted; returns an id for read()/release().
  decrypt(path, offset, cryptoff, cryptsize, cryptid, cpu, subtype) {
    const fd = open.call(null, Memory.allocUtf8String(path), O_RDONLY);
    if (fd.value < 0) {
      throw new Error(failure('open', fd));
    }
    try {
      const page = Process.pageSize;
      const start = offset + cryptoff;
      const aligned = start - (start % page);
      const delta = start - aligned;
      const length = cryptsize + delta;
      const mapped = mmap.call(null, NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd.value, aligned);
      if (mapped.value.equals(ptr('-1'))) {
        throw new Error(failure('mmap', mapped));
      }
      const result = mremapEncrypted.call(null, mapped.value.add(delta), cryptsize, cryptid, cpu >>> 0, subtype >>> 0);
      if (result.value !== 0) {
        munmap(mapped.value, length);
        throw new Error(failure('mremap_encrypted', result));
      }
      const id = nextId++;
      mappings.set(id, { base: mapped.value, length: length, delta: delta, size: cryptsize });
      return id;
    } finally {
      close(fd.value);
    }
  },

  // Bytes [start, start + size) of a range decrypted by decrypt().
  read(id, start, size) {
    const mapping = mappings.get(id);
    return mapping.base.add(mapping.delta + start).readByteArray(size);
  },

  release(id) {
    const mapping = mappings.get(id);
    if (mapping) {
      munmap(mapping.base, mapping.length);
      mappings.delete(id);
    }
  },

  // Where the image whose path ends with suffix is loaded, with its CPU type, or null.
  // A process spawned suspended has no module list yet, but the kernel has already mapped
  // (and set up decryption for) its main executable.
  imageBase(suffix) {
    let base = null;
    const module = Process.enumerateModules().find((m) => m.path.endsWith(suffix));
    if (module) {
      base = module.base;
    } else {
      const range = Process.enumerateRanges('r--').find(
        (r) => r.file && r.file.offset === 0 && r.file.path.endsWith(suffix));
      if (range) {
        base = range.base;
      }
    }
    if (base === null) {
      return null;
    }
    return { base: base.toString(), cpu: base.add(4).readS32(), subtype: base.add(8).readS32() };
  },

  readAt(base, offset, size) {
    return ptr(base).add(offset).readByteArray(size);
  },

  // Ask the system to start an app extension, as a host does when it uses one. The caller has
  // spawn gating on, so the extension stops before running any code. Returns what was found.
  launchExtension(identifier) {
    const o = objcApi();
    const error = Memory.alloc(Process.pointerSize);
    const extension = o.send(['pointer', 'pointer'])(o.cls('NSExtension'), o.sel('extensionWithIdentifier:error:'),
      o.str(identifier), error);
    if (extension.isNull()) {
      return { found: false };
    }
    const items = o.send([])(o.cls('NSArray'), o.sel('array'));
    // Fails once the gated extension does not answer; by then it has been read.
    o.send(['pointer', 'pointer'])(extension, o.sel('beginExtensionRequestWithInputItems:error:'), items, error);
    return { found: true };
  },
};
