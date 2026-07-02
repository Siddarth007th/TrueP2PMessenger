/**
 * Automated E2E test for the Adaptive Vault Replication system.
 *
 * Tests the NEW lazy-replication model:
 * - Normal operation: only party nodes store messages (no blind vault)
 * - On threat: recovery via onion routing from the other party
 * - After recovery: replication spreads data to non-party nodes
 *
 * Flow:
 * 1. Connects to all 4 nodes (A, B, C, D) via Socket.IO
 * 2. Waits for full mesh-ready on Node A
 * 3. Sends DMs: A→B, A→C
 * 4. Verifies ONLY party nodes have data (C and D lockers empty)
 * 5. Simulates a SMART wipe on Node A
 * 6. Verifies anomaly detection fires
 * 7. Verifies onion-routed recovery restores data
 * 8. Verifies replication factor doubled
 * 9. Verifies non-party nodes (C, D) NOW have locker copies after replication
 */

const { io } = require('socket.io-client');

const TIMEOUT = 25000;
let passed = 0, failed = 0;

function assert(label, condition) {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}`);
    failed++;
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function run() {
  console.log('=== Adaptive Vault Replication E2E Test ===\n');

  const socketA = io('http://localhost:3001', { transports: ['websocket'] });
  const socketB = io('http://localhost:3002', { transports: ['websocket'] });
  const socketC = io('http://localhost:3003', { transports: ['websocket'] });
  const socketD = io('http://localhost:3004', { transports: ['websocket'] });

  let meshReadyA = false;
  let anomalyDetectedA = false;
  let recoveryCompleteA = false;
  let rehydrationStatsA = null;
  let recoveredMessagesA = [];
  let myWorkRowsA = [];
  let lockerRowsA = [];
  let myWorkRowsB = [];
  let lockerRowsC = [];
  let lockerRowsD = [];
  let replicationStatusA = null;
  let replicationSpreadA = null;
  let replicationReceivedC = null;
  let replicationReceivedD = null;

  // Node A listeners
  socketA.on('mesh-ready', () => { meshReadyA = true; });
  socketA.on('ANOMALY_DETECTED', (data) => {
    anomalyDetectedA = true;
    console.log(`  [A] ANOMALY_DETECTED: ${data.missingIds.length} My Work missing`);
  });
  socketA.on('RECOVERY_COMPLETE', (data) => {
    recoveryCompleteA = true;
    recoveredMessagesA = data.recoveredMessages || [];
    console.log(`  [A] RECOVERY_COMPLETE: ${recoveredMessagesA.length} message(s)`);
  });
  socketA.on('REHYDRATION_STATS', (data) => {
    rehydrationStatsA = data;
    console.log(`  [A] REHYDRATION_STATS: ${data.recovered} recovered [type: ${data.type || 'mywork'}]`);
  });
  socketA.on('REPLICATION_STATUS', (data) => { replicationStatusA = data; });
  socketA.on('REPLICATION_SPREAD', (data) => {
    replicationSpreadA = data;
    console.log(`  [A] REPLICATION_SPREAD: ×${data.factor}, ${data.rows} rows → ${data.peers} peers`);
  });
  socketA.on('mywork', (rows) => { myWorkRowsA = rows; });
  socketA.on('locker', (rows) => { lockerRowsA = rows; });
  socketA.on('sys', (msg) => { console.log(`  [A sys] ${msg}`); });

  // Node B listeners
  socketB.on('mywork', (rows) => { myWorkRowsB = rows; });

  // Node C listeners
  socketC.on('locker', (rows) => { lockerRowsC = rows; });
  socketC.on('REPLICATION_RECEIVED', (data) => {
    replicationReceivedC = data;
    console.log(`  [C] REPLICATION_RECEIVED: ${data.newStored} new + ${data.alreadySecured} verified`);
  });

  // Node D listeners
  socketD.on('locker', (rows) => { lockerRowsD = rows; });
  socketD.on('REPLICATION_RECEIVED', (data) => {
    replicationReceivedD = data;
    console.log(`  [D] REPLICATION_RECEIVED: ${data.newStored} new + ${data.alreadySecured} verified`);
  });

  // ────────────────────────────────────────────
  // 1. Wait for mesh-ready
  // ────────────────────────────────────────────
  console.log('1. Waiting for mesh-ready...');
  const start = Date.now();
  while (!meshReadyA && Date.now() - start < TIMEOUT) await sleep(300);
  assert('Mesh is ready (A has 3 peers)', meshReadyA);

  if (!meshReadyA) {
    console.log('\n  Cannot continue — mesh not ready');
    socketA.disconnect(); socketB.disconnect(); socketC.disconnect(); socketD.disconnect();
    process.exit(1);
  }

  // ────────────────────────────────────────────
  // 2. Send messages (A→B, A→C only)
  // ────────────────────────────────────────────
  console.log('\n2. Sending messages: A→B, A→C...');
  socketA.emit('send-dm', { to: 'B', text: 'LAZY_TEST_A2B' });
  socketA.emit('send-dm', { to: 'C', text: 'LAZY_TEST_A2C' });
  await sleep(2000);

  assert('A My Work has 2 rows (A→B, A→C)', myWorkRowsA.length >= 2);
  assert('B My Work has row (A→B)', myWorkRowsB.length >= 1);

  // ────────────────────────────────────────────
  // 3. Verify NO blind vault during normal operation
  // ────────────────────────────────────────────
  console.log('\n3. Verifying lazy storage (no blind vault in normal mode)...');
  assert('A Locker is EMPTY (no blind copies)', lockerRowsA.length === 0);
  assert('C Locker is EMPTY (C not party to A↔B)', lockerRowsC.length === 0);
  assert('D Locker is EMPTY (D not party to anything)', lockerRowsD.length === 0);

  // ────────────────────────────────────────────
  // 4. Simulate wipe on Node A
  // ────────────────────────────────────────────
  console.log('\n4. Simulating wipe on Node A...');
  const preWipeMW = myWorkRowsA.length;
  socketA.emit('simulate-wipe');

  // ────────────────────────────────────────────
  // 5. Wait for anomaly detection
  // ────────────────────────────────────────────
  console.log('\n5. Waiting for anomaly detection...');
  const aStart = Date.now();
  while (!anomalyDetectedA && Date.now() - aStart < 12000) await sleep(300);
  assert('My Work anomaly detected on A', anomalyDetectedA);

  // ────────────────────────────────────────────
  // 6. Wait for recovery
  // ────────────────────────────────────────────
  console.log('\n6. Waiting for onion-routed recovery...');
  const rStart = Date.now();
  while (!recoveryCompleteA && Date.now() - rStart < 12000) await sleep(300);
  assert('Recovery complete event received', recoveryCompleteA);
  assert('At least 1 message recovered', recoveredMessagesA.length >= 1);

  if (rehydrationStatsA) {
    assert('Rehydration recovered > 0', rehydrationStatsA.recovered > 0);
    assert('Rehydration failed === 0', rehydrationStatsA.failed === 0);
  }

  // ────────────────────────────────────────────
  // 7. Verify replication factor doubled
  // ────────────────────────────────────────────
  console.log('\n7. Checking replication factor...');
  await sleep(1000);
  assert('Replication status received', !!replicationStatusA);
  if (replicationStatusA) {
    assert('Replication factor >= 2 after threat', replicationStatusA.factor >= 2);
    console.log(`  Factor: ×${replicationStatusA.factor}`);
  }

  // ────────────────────────────────────────────
  // 8. Wait for replication to spread to non-party nodes
  // ────────────────────────────────────────────
  console.log('\n8. Waiting for vault replication to spread...');
  const repStart = Date.now();
  while (!replicationSpreadA && Date.now() - repStart < 12000) await sleep(300);
  assert('Replication spread event on A', !!replicationSpreadA);

  // Give time for onion payloads to reach C and D
  await sleep(4000);

  console.log(`  C Locker now: ${lockerRowsC.length} rows`);
  console.log(`  D Locker now: ${lockerRowsD.length} rows`);
  assert('C Locker populated AFTER replication (was empty before)', lockerRowsC.length > 0);
  assert('D Locker populated AFTER replication (was empty before)', lockerRowsD.length > 0);

  if (replicationReceivedC) {
    assert('C received NEW records (not just verified)', replicationReceivedC.newStored > 0);
  }
  if (replicationReceivedD) {
    assert('D received NEW records (not just verified)', replicationReceivedD.newStored > 0);
  }

  // ────────────────────────────────────────────
  // 9. Verify restored data on A
  // ────────────────────────────────────────────
  console.log('\n9. Verifying restored data on Node A...');
  await sleep(1000);
  const restoredA2B = myWorkRowsA.find(r => r.plaintext === 'LAZY_TEST_A2B');
  const restoredA2C = myWorkRowsA.find(r => r.plaintext === 'LAZY_TEST_A2C');
  assert('A→B message restored in A My Work', !!restoredA2B);
  assert('A→C message restored in A My Work', !!restoredA2C);

  // ────────────────────────────────────────────
  // Summary
  // ────────────────────────────────────────────
  console.log(`\n=============================`);
  console.log(`Passed: ${passed} | Failed: ${failed}`);
  console.log(`=============================`);

  socketA.disconnect(); socketB.disconnect(); socketC.disconnect(); socketD.disconnect();
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
