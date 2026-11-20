// Pins the approval a job ran under: the Workload's current approval when the
// job's result lands. A renewal approved later, or a fresh request after the
// approval ends, then does not change which certificate the Job page compares.
//
// read()     the job result's raw text, or null when there is none
// current()  the Workload's current approval (Broker approvals/current)
// status(id) that approval's status (Broker status), which keeps its
//            certificate after it is replaced or ends
export function jobApproval({ read, current, status }) {
  let pinned = null; // { text, id } for the job result last seen
  async function pin(text) {
    const approval = await current().catch(() => null);
    pinned = { text, id: approval?.id ?? null };
    return approval;
  }
  return {
    // Call when the job's result may have changed.
    async landed() {
      const text = await read();
      if (text !== null && text !== pinned?.text) await pin(text);
    },
    // The job's result and the approval it ran under, or null when unknown.
    async forJob() {
      const text = await read();
      if (text === null) return { text, approval: null };
      // A job nobody pinned yet, or one whose lookup failed, pins at this read.
      if (text !== pinned?.text || !pinned.id) return { text, approval: await pin(text) };
      return { text, approval: await status(pinned.id).catch(() => null) };
    },
  };
}
