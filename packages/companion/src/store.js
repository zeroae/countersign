import { mkdir, readFile, rename, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

// A single main process serializes changes and writes a fully encrypted
// replacement. The separate native pairing key never enters this store.
export class PairingStore {
  #queue = Promise.resolve();
  #records = new Map();

  constructor(directory, protection) {
    this.directory = directory;
    this.protection = protection;
    this.file = join(directory, 'pairings.v1');
  }

  #requireProtection() {
    if (!this.protection.isEncryptionAvailable() ||
        (process.platform === 'linux' &&
        ['unknown', 'basic_text'].includes(this.protection.getSelectedStorageBackend()))) {
      throw new Error('Unlock your operating system credential store to continue.');
    }
  }

  async load() {
    await mkdir(this.directory, { mode: 0o700, recursive: true });
    let bytes;
    try {
      bytes = await readFile(this.file);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    this.#requireProtection();
    const records = JSON.parse(this.protection.decryptString(bytes));
    if (records.version !== 1 || !Array.isArray(records.pairings)) throw new Error('Invalid pairing store.');
    this.#records = new Map(records.pairings.map(record => [record.id, record]));
  }

  list() { return structuredClone([...this.#records.values()]); }
  get(id) { return structuredClone(this.#records.get(id)); }

  update(id, change) {
    const run = this.#queue.then(async () => {
      this.#requireProtection();
      const next = new Map(this.#records);
      const record = change(this.get(id));
      if (record === null) next.delete(id);
      else {
        if (!record || record.id !== id) throw new Error('Pairing ID mismatch.');
        next.set(id, structuredClone(record));
      }
      const bytes = this.protection.encryptString(JSON.stringify({ version: 1, pairings: [...next.values()] }));
      const tmp = join(this.directory, randomUUID() + '.tmp');
      try {
        await writeFile(tmp, bytes, { flag: 'wx', mode: 0o600 });
        await rename(tmp, this.file);
      } finally {
        await rm(tmp, { force: true });
      }
      this.#records = next;
    });
    this.#queue = run.catch(() => {});
    return run;
  }
}
