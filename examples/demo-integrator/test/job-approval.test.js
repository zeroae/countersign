import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jobApproval } from '../job-approval.js';

// A Broker stand-in: `current` is the Workload's current approval, and
// `status` answers for any approval it has seen, as the real one does.
function broker() {
  const approvals = new Map();
  const b = {
    current: null,
    approve(id, sha256) { approvals.set(id, { id, state: 'approved', certificate: { sha256 } }); b.current = id; },
    replace(id) { approvals.get(id).state = 'replaced'; },
    lookups: 0,
    async lookup() { b.lookups++; if (!b.current) throw new Error('404'); return approvals.get(b.current); },
    async status(id) { return approvals.get(id); },
  };
  return b;
}
const job = fingerprint => JSON.stringify({ url: 'https://site.test:9444/', ok: true, fingerprint });

test('a job keeps the approval that was current when its result landed', async () => {
  const b = broker();
  let file = null;
  const jobs = jobApproval({ read: async () => file, current: b.lookup, status: b.status });
  b.approve('A', 'aaaa');
  file = job('aaaa');
  await jobs.landed();
  b.replace('A');
  b.approve('B', 'bbbb'); // a renewal approved with another certificate
  const { approval } = await jobs.forJob();
  assert.equal(approval.id, 'A');
  assert.equal(approval.certificate.sha256, 'aaaa');
  file = job('bbbb'); // the next job runs under B
  await jobs.landed();
  assert.equal((await jobs.forJob()).approval.id, 'B');
});

test('a job read before anything noticed it pins the approval current at that read', async () => {
  const b = broker();
  b.approve('A', 'aaaa');
  const jobs = jobApproval({ read: async () => job('aaaa'), current: b.lookup, status: b.status });
  assert.equal((await jobs.forJob()).approval.id, 'A');
  b.approve('B', 'bbbb');
  assert.equal((await jobs.forJob()).approval.id, 'A');
});

test('no job, or a Broker that could not answer, leaves nothing pinned for good', async () => {
  const b = broker();
  let file = null;
  const jobs = jobApproval({ read: async () => file, current: b.lookup, status: b.status });
  assert.deepEqual(await jobs.forJob(), { text: null, approval: null });
  assert.equal(b.lookups, 0);
  file = job('aaaa');
  await jobs.landed(); // no current approval: the lookup fails
  assert.equal((await jobs.forJob()).approval, null);
  b.approve('A', 'aaaa');
  assert.equal((await jobs.forJob()).approval.id, 'A', 'the next read tries again');
});
