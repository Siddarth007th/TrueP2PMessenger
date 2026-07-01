/**
 * Rehydrator — Ciphertext Decryption & Row Re-Insertion
 *
 * When a recovery response arrives via the onion network, this module:
 * 1. Re-inserts the recovered ciphertext rows into the local SQLite vault
 * 2. Decrypts them using the ECDH-derived AES keys
 * 3. Emits RECOVERY_COMPLETE with plaintext for Phantom UI injection
 * 4. Emits REHYDRATION_STATS with success/failure counts
 */

const crypto = require('crypto');

/**
 * Decrypt a single vault row's ciphertext using the AES-256-GCM key.
 *
 * @param {Buffer} key   - 32-byte AES key derived from ECDH shared secret
 * @param {string} nonce - hex-encoded 12-byte nonce
 * @param {string} tag   - hex-encoded 16-byte auth tag
 * @param {string} val   - hex-encoded ciphertext
 * @returns {string|null} - decrypted plaintext, or null on failure
 */
function decryptRow(key, nonce, tag, val) {
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(nonce, 'hex')
    );
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    return decipher.update(val, 'hex', 'utf8') + decipher.final('utf8');
  } catch {
    return null;
  }
}

/**
 * Rehydrate the local vault with recovered rows.
 *
 * @param {object}   db       - better-sqlite3 database instance
 * @param {string}   nodeName - this node's identifier (e.g. 'A')
 * @param {object}   keys     - map of peerName → Buffer (32-byte AES keys)
 * @param {Array}    rows     - recovered vault rows: [{ msgId, fromNode, toNode, nonce, tag, val, ts }]
 * @param {object}   io       - Socket.IO server instance
 * @param {object}   detector - anomaly detector instance (to re-track rehydrated msgIds)
 * @returns {{ recovered: number, failed: number }}
 */
function rehydrate(db, nodeName, keys, rows, io, detector) {
  const insertStmt = db.prepare(
    'INSERT OR IGNORE INTO vault(msgId, fromNode, toNode, nonce, tag, val, ts) VALUES(?, ?, ?, ?, ?, ?, ?)'
  );

  let recovered = 0;
  let failed = 0;
  const recoveredMessages = [];

  const insertMany = db.transaction((rowList) => {
    for (const row of rowList) {
      try {
        // Re-insert the ciphertext row
        const result = insertStmt.run(
          row.msgId,
          row.fromNode,
          row.toNode,
          row.nonce,
          row.tag,
          row.val,
          row.ts || Date.now()
        );

        // Determine which peer's key to use for decryption
        const peer =
          row.fromNode === nodeName ? row.toNode : row.fromNode;
        const aesKey = keys[peer];

        let plaintext = null;
        if (aesKey) {
          plaintext = decryptRow(aesKey, row.nonce, row.tag, row.val);
        }

        if (result.changes > 0 || plaintext) {
          recovered++;

          // Re-register with the anomaly detector
          if (detector) {
            detector.track(row.msgId);
          }

          if (plaintext) {
            recoveredMessages.push({
              msgId: row.msgId,
              from: row.fromNode,
              to: row.toNode,
              text: plaintext,
              group: false,
            });
          }
        } else {
          // Row already existed (INSERT OR IGNORE hit a duplicate)
          recovered++;
        }
      } catch (err) {
        console.error(
          `[Rehydrator] Failed to restore ${row.msgId?.slice(0, 8)}:`,
          err.message
        );
        failed++;
      }
    }
  });

  insertMany(rows);

  const stats = {
    recovered,
    failed,
    timestamp: Date.now(),
    node: nodeName,
  };

  console.log(
    `[Rehydrator] Node ${nodeName}: restored ${recovered} row(s), ${failed} failed`
  );

  // Phantom UI injection — push recovered messages into the active chat
  if (recoveredMessages.length > 0) {
    io.emit('RECOVERY_COMPLETE', { recoveredMessages });
    io.emit(
      'sys',
      `✅ Recovery complete: ${recovered} record(s) restored via onion routing`
    );
  }

  // Stats for the dashboard
  io.emit('REHYDRATION_STATS', stats);

  return stats;
}

/**
 * Rehydrate LOCKER rows (blind vault copies).
 *
 * Unlike rehydrate(), this does NOT attempt decryption — the node
 * doesn't have the AES key for these conversations. It simply
 * re-inserts the ciphertext rows and re-registers them with the
 * anomaly detector's locker tracking.
 *
 * @param {object}   db       - better-sqlite3 database instance
 * @param {string}   nodeName - this node's identifier
 * @param {Array}    rows     - recovered locker rows
 * @param {object}   io       - Socket.IO server instance
 * @param {object}   detector - anomaly detector instance
 * @returns {{ recovered: number, failed: number }}
 */
function rehydrateLocker(db, nodeName, rows, io, detector) {
  const insertStmt = db.prepare(
    'INSERT OR IGNORE INTO vault(msgId, fromNode, toNode, nonce, tag, val, ts) VALUES(?, ?, ?, ?, ?, ?, ?)'
  );

  let recovered = 0;
  let failed = 0;

  const insertMany = db.transaction((rowList) => {
    for (const row of rowList) {
      try {
        const result = insertStmt.run(
          row.msgId,
          row.fromNode,
          row.toNode,
          row.nonce,
          row.tag,
          row.val,
          row.ts || Date.now()
        );

        if (result.changes > 0) {
          recovered++;
          // Re-register with the anomaly detector's locker tracking
          if (detector) {
            detector.trackLocker(row.msgId);
          }
        } else {
          // Already existed
          recovered++;
        }
      } catch (err) {
        console.error(
          `[Rehydrator] Locker restore failed for ${row.msgId?.slice(0, 8)}:`,
          err.message
        );
        failed++;
      }
    }
  });

  insertMany(rows);

  const stats = {
    recovered,
    failed,
    timestamp: Date.now(),
    node: nodeName,
    type: 'locker',
  };

  console.log(
    `[Rehydrator] Node ${nodeName}: locker restored ${recovered} row(s), ${failed} failed`
  );

  if (recovered > 0) {
    io.emit('LOCKER_RECOVERY_COMPLETE', {
      recovered,
      failed,
      timestamp: Date.now(),
    });
    io.emit(
      'sys',
      `✅ Locker recovery complete: ${recovered} blind vault record(s) restored`
    );
  }

  io.emit('REHYDRATION_STATS', stats);

  return stats;
}

module.exports = { rehydrate, rehydrateLocker, decryptRow };
