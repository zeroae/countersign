// Pins the approval a job ran under: the Workload's current approval when the
// job's result lands. A renewal approved later, or a fresh request after the
// approval ends, then does not change which certificate the Job page compares.
//
// read()     the job result as { text, stamp }, where stamp changes each time
//            the result is written (its mtime), or null when there is none
// current()  the Workload's current approval (Broker approvals/current)
// status(id) that approval's status (Broker status), which keeps its
//            certificate after it is replaced or ends
export function jobApproval({ read, current, status }) {
  let pinned = null; // { text, stamp, id } for the job result last seen
  // A rerun can write the same text again, so a result is known by both.
  const same = job => job.text === pinned?.text && job.stamp === pinned.stamp;
  async function pin(job) {
    const approval = await current().catch(() => null);
    pinned = { text: job.text, stamp: job.stamp, id: approval?.id ?? null };
    return approval;
  }
  return {
    // Call when the job's result may have changed.
    async landed() {
      const job = await read();
      if (job !== null && !same(job)) await pin(job);
    },
    // The job's result text and the approval it ran under, or null when unknown.
    async forJob() {
      const job = await read();
      if (job === null) return { text: null, approval: null };
      // A job nobody pinned yet, or one whose lookup failed, pins at this read.
      if (!same(job) || !pinned.id) return { text: job.text, approval: await pin(job) };
      return { text: job.text, approval: await status(pinned.id).catch(() => null) };
    },
  };
}
