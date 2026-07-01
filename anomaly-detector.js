/**
 * Anomaly Detector — Background Worker
 *
 * Maintains in-memory sets of all known msgIds for this node:
 *   - knownIds:       messages this node is party to (My Work)
 *   - knownLockerIds: messages this node stores on behalf of others (Locker / blind vault)
 *
 * Polls the SQLite vault on an interval, diffs against the sets,
 * and fires when rows vanish without a cryptographic deletion signature.
 */

const POLL_INTERVAL_MS = 5000;

/**
 * Start the anomaly detection loop.
 *
 * @param {object}   db             - better-sqlite3 database instance
 * @param {string}   nodeName       - this node's identifier (e.g. 'A')
 * @param {object}   io             - Socket.IO server instance
 * @param {function} onAnomaly      - callback(missingIds: string[]) triggered on My Work deletion
 * @param {function} onLockerAnomaly - callback(missingLockerIds: string[]) triggered on Locker deletion
 * @returns {{ track: (msgId: string) => void, trackLocker: (msgId: string) => void, stop: () => void }}
 */
function startAnomalyDetector(db, nodeName, io, onAnomaly, onLockerAnomaly) {
  // In-memory registry of every msgId this node has seen
  const knownIds = new Set();
  const knownLockerIds = new Set();

  // Prepared statements
  const myWorkStmt = db.prepare(
    'SELECT msgId FROM vault WHERE fromNode = ? OR toNode = ?'
  );
  const lockerStmt = db.prepare(
    'SELECT msgId FROM vault WHERE fromNode != ? AND toNode != ?'
  );

  // Seed the sets from whatever is already in the vault at startup
  const seedMyWork = myWorkStmt.all(nodeName, nodeName);
  for (const row of seedMyWork) {
    knownIds.add(row.msgId);
  }

  const seedLocker = lockerStmt.all(nodeName, nodeName);
  for (const row of seedLocker) {
    knownLockerIds.add(row.msgId);
  }

  console.log(
    `[Anomaly] Node ${nodeName}: seeded ${knownIds.size} My Work + ${knownLockerIds.size} Locker msgIds`
  );

  // Polling loop
  const timer = setInterval(() => {
    try {
      // --- My Work anomaly check ---
      const currentMyWork = myWorkStmt.all(nodeName, nodeName);
      const currentMyWorkIds = new Set(currentMyWork.map((r) => r.msgId));

      const missingMyWork = [];
      for (const id of knownIds) {
        if (!currentMyWorkIds.has(id)) {
          missingMyWork.push(id);
        }
      }

      if (missingMyWork.length > 0) {
        const event = {
          missingIds: missingMyWork,
          timestamp: Date.now(),
          node: nodeName,
        };

        console.log(
          `[Anomaly] Node ${nodeName}: DETECTED ${missingMyWork.length} missing My Work record(s) — ${missingMyWork.map((id) => id.slice(0, 8)).join(', ')}`
        );

        io.emit('ANOMALY_DETECTED', event);
        io.emit(
          'sys',
          `⚠️ ANOMALY: ${missingMyWork.length} My Work record(s) deleted without cryptographic signature`
        );

        onAnomaly(missingMyWork);

        // Remove from known set so we don't re-fire on next poll
        for (const id of missingMyWork) {
          knownIds.delete(id);
        }
      }

      // --- Locker anomaly check ---
      const currentLocker = lockerStmt.all(nodeName, nodeName);
      const currentLockerIds = new Set(currentLocker.map((r) => r.msgId));

      const missingLocker = [];
      for (const id of knownLockerIds) {
        if (!currentLockerIds.has(id)) {
          missingLocker.push(id);
        }
      }

      if (missingLocker.length > 0) {
        const event = {
          missingIds: missingLocker,
          timestamp: Date.now(),
          node: nodeName,
          type: 'locker',
        };

        console.log(
          `[Anomaly] Node ${nodeName}: DETECTED ${missingLocker.length} missing Locker record(s) — ${missingLocker.map((id) => id.slice(0, 8)).join(', ')}`
        );

        io.emit('LOCKER_ANOMALY', event);
        io.emit(
          'sys',
          `⚠️ LOCKER ANOMALY: ${missingLocker.length} blind vault record(s) deleted without cryptographic signature`
        );

        if (onLockerAnomaly) {
          onLockerAnomaly(missingLocker);
        }

        // Remove from known set so we don't re-fire
        for (const id of missingLocker) {
          knownLockerIds.delete(id);
        }
      }
    } catch (err) {
      console.error(`[Anomaly] Poll error:`, err.message);
    }
  }, POLL_INTERVAL_MS);

  return {
    /**
     * Call this every time a new My Work row is stored in the vault.
     */
    track(msgId) {
      knownIds.add(msgId);
    },

    /**
     * Call this every time a new Locker row is stored in the vault.
     */
    trackLocker(msgId) {
      knownLockerIds.add(msgId);
    },

    /**
     * Shut down the polling loop.
     */
    stop() {
      clearInterval(timer);
    },
  };
}

module.exports = { startAnomalyDetector };
