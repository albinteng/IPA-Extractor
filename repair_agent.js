// Frida agent for repair_worker.py: decrypts FairPlay-encrypted ranges of files on the device
// from inside the app's own process, where the kernel holds the app's keys.
//
// For each encrypted slice the range is mapped from the file and handed to mremap_encrypted(),
// which makes the kernel decrypt the pages exactly as it does when it loads code.
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

rpc.exports = {
  // Decrypt one slice in memory; returns an id for read()/release().
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

  // Bytes [start, start + size) of the decrypted range.
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
};
