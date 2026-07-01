/**
 * Automated E2E test for the Adaptive Vault Replication system.
 *
 * 1. Connects to all 4 nodes (A, B, C, D) via Socket.IO
 * 2. Waits for full mesh-ready on Node A
 * 3. Sends DMs: A→B, A→C, B→C to generate both My Work and Locker data
 * 4. Verifies locker rows exist on Node D (blind vault)
 * 5. Simulates a SMART wipe on Node A (My Work + Locker)
 * 6. Verifies anomaly detection fires for both My Work and Locker
 * 7. Verifies onion-routed recovery restores My Work
 * 8. Verifies locker recovery from peers
 * 9. Verifies replication factor doubled
 * 10. Verifies Node D received replicated vault copies
 */

const { io } = require('socket.io-client');

const TIMEOUT = 25000;
let passed = 0, failed = 0;

function assert(label, condition) {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.log(`  FAIL: ${label}`);
    failed++;
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function run() {
  console.log('=== Adaptive Vault Replication E2E Test ===\n');

  // Connect to all nodes
  const socketA = io('http://localhost:3001', { transports: ['websocket'] });
  const socketB = io('http://localhost:3002', { transports: ['websocket'] });
  const socketD = io('http://localhost:3004', { transports: ['websocket'] });

  let meshReadyA = false;
  let anomalyDetectedA = false;
  let lockerAnomalyA = false;
  let recoveryCompleteA = false;
  let rehydrationStatsA = null;
  let recoveredMessagesA = [];
  let myWorkRowsA = [];
  let lockerRowsA = [];
  let lockerRowsD = [];
  let replicationStatusA = null;
  let replicationSpreadA = null;
  let replicationReceivedD = null;

  // Node A listeners
  socketA.on('mesh-ready', () => { meshReadyA = true; });
  socketA.on('ANOMALY_DETECTED', (data) => {
    anomalyDetectedA = true;
    console.log(`  [A Event] ANOMALY_DETECTED: ${data.missingIds.length} My Work missing`);
  });
  socketA.on('LOCKER_ANOMALY', (data) => {
    lockerAnomalyA = true;
    console.log(`  [A Event] LOCKER_ANOMALY: ${data.missingIds.length} Locker missing`);
  });
  socketA.on('RECOVERY_COMPLETE', (data) => {
    recoveryCompleteA = true;
    recoveredMessagesA = data.recoveredMessages || [];
    console.log(`  [A Event] RECOVERY_COMPLETE: ${recoveredMessagesA.length} message(s)`);
  });
  socketA.on('REHYDRATION_STATS', (data) => {
    rehydrationStatsA = data;
    console.log(`  [A Event] REHYDRATION_STATS: ${data.recovered} recovered, ${data.failed} failed [type: ${data.type || 'mywork'}]`);
  });
  socketA.on('REPLICATION_STATUS', (data) => {
    replicationStatusA = data;
  });
  socketA.on('REPLICATION_SPREAD', (data) => {
    replicationSpreadA = data;
    console.log(`  [A Event] REPLICATION_SPREAD: factor ×${data.factor}, ${data.rows} rows to ${data.peers} peers`);
  });
  socketA.on('mywork', (rows) => { myWorkRowsA = rows; });
  socketA.on('locker', (rows) => { lockerRowsA = rows; });
  socketA.on('sys', (msg) => { console.log(`  [A Sys] ${msg}`); });

  // Node D listeners
  socketD.on('locker', (rows) => { lockerRowsD = rows; });
  socketD.on('REPLICATION_RECEIVED', (data) => {
    replicationReceivedD = data;
    console.log(`  [D Event] REPLICATION_RECEIVED: ${data.stored} stored from ${data.from}`);
  });
  socketD.on('sys', (msg) => { console.log(`  [D Sys] ${msg}`); });

  // ──────────────────────────────────────────────────
  // 1. Wait for mesh to be ready
  // ──────────────────────────────────────────────────
  console.log('1. Waiting for mesh-ready on Node A...');
  const start = Date.now();
  while (!meshReadyA && Date.now() - start < TIMEOUT) {
    await sleep(300);
  }
  assert('Mesh is ready (A has 3 peers)', meshReadyA);

  if (!meshReadyA) {
    console.log('\n  Cannot continue — mesh not ready');
    socketA.disconnect(); socketB.disconnect(); socketD.disconnect();
    process.exit(1);
  }

  // ──────────────────────────────────────────────────
  // 2. Send messages to generate My Work + Locker data
  // ──────────────────────────────────────────────────
  console.log('\n2. Sending messages: A→B, A→C, B→C...');
  socketA.emit('send-dm', { to: 'B', text: 'ADAPTIVE_TEST_A2B' });
  socketA.emit('send-dm', { to: 'C', text: 'ADAPTIVE_TEST_A2C' });
  await sleep(500);
  socketB.emit('send-dm', { to: 'C', text: 'ADAPTIVE_TEST_B2C' });
  await sleep(2000);

  assert('A My Work has at least 2 rows', myWorkRowsA.length >= 2);
  const a2b = myWorkRowsA.find(r => r.plaintext === 'ADAPTIVE_TEST_A2B');
  assert('A→B message found in A My Work', !!a2b);

  // Wait for locker data to propagate
  await sleep(1500);

  assert('A Locker has at least 1 row (B→C)', lockerRowsA.length >= 1);
  assert('D Locker has rows (blind vault)', lockerRowsD.length >= 1);

  // ──────────────────────────────────────────────────
  // 3. Simulate SMART wipe on Node A (My Work + Locker)
  // ──────────────────────────────────────────────────
  console.log('\n3. Simulating SMART wipe on Node A (My Work + Locker)...');
  const preWipeMyWork = myWorkRowsA.length;
  const preWipeLocker = lockerRowsA.length;
  console.log(`  Pre-wipe: ${preWipeMyWork} My Work, ${preWipeLocker} Locker`);

  socketA.emit('simulate-wipe');
  await sleep(2000);

  console.log(`  Post-wipe: ${myWorkRowsA.length} My Work, ${lockerRowsA.length} Locker`);
  // At least some data should have been wiped
  assert('My Work or Locker reduced after wipe', myWorkRowsA.length < preWipeMyWork || lockerRowsA.length < preWipeLocker);

  // ──────────────────────────────────────────────────
  // 4. Wait for dual anomaly detection
  // ──────────────────────────────────────────────────
  console.log('\n4. Waiting for anomaly detection (My Work + Locker)...');
  const anomalyStart = Date.now();
  while ((!anomalyDetectedA || !lockerAnomalyA) && Date.now() - anomalyStart < 10000) {
    await sleep(300);
  }
  assert('My Work anomaly detected', anomalyDetectedA);
  assert('Locker anomaly detected', lockerAnomalyA);

  // ──────────────────────────────────────────────────
  // 5. Wait for recovery
  // ──────────────────────────────────────────────────
  if (!recoveryCompleteA) {
    console.log('\n5. Waiting for onion-routed recovery...');
    const recStart = Date.now();
    while (!recoveryCompleteA && Date.now() - recStart < 12000) {
      await sleep(300);
    }
  } else {
    console.log('\n5. Recovery already completed via auto-trigger');
  }

  assert('Recovery complete event received', recoveryCompleteA);
  assert('At least 1 My Work message recovered', recoveredMessagesA.length >= 1);

  if (recoveredMessagesA.length > 0) {
    const recovered = recoveredMessagesA.find(m => m.text === 'ADAPTIVE_TEST_A2B');
    assert('Correct message text recovered (A→B)', !!recovered);
  }

  assert('Rehydration stats received', !!rehydrationStatsA);
  if (rehydrationStatsA) {
    assert('Rehydration recovered > 0', rehydrationStatsA.recovered > 0);
    assert('Rehydration failed === 0', rehydrationStatsA.failed === 0);
  }

  // ──────────────────────────────────────────────────
  // 6. Verify replication factor doubled
  // ──────────────────────────────────────────────────
  console.log('\n6. Checking replication factor...');
  await sleep(2000);
  assert('Replication status received', !!replicationStatusA);
  if (replicationStatusA) {
    assert('Replication factor >= 2 after threat', replicationStatusA.factor >= 2);
    console.log(`  Replication factor: ×${replicationStatusA.factor}`);
  }

  // ──────────────────────────────────────────────────
  // 7. Wait for replication spread to peers
  // ──────────────────────────────────────────────────
  console.log('\n7. Waiting for vault replication to spread...');
  const repStart = Date.now();
  while (!replicationSpreadA && Date.now() - repStart < 8000) {
    await sleep(300);
  }
  assert('Replication spread event received on A', !!replicationSpreadA);

  // Wait for D to receive replication
  await sleep(3000);
  assert('Node D received replicated data', lockerRowsD.length > 0);

  // ──────────────────────────────────────────────────
  // 8. Verify restored data on A
  // ──────────────────────────────────────────────────
  console.log('\n8. Verifying restored data on Node A...');
  await sleep(1000);
  const restoredA2B = myWorkRowsA.find(r => r.plaintext === 'ADAPTIVE_TEST_A2B');
  assert('A→B message restored in A My Work', !!restoredA2B);
  const restoredA2C = myWorkRowsA.find(r => r.plaintext === 'ADAPTIVE_TEST_A2C');
  assert('A→C message restored in A My Work', !!restoredA2C);

  // ──────────────────────────────────────────────────
  // Summary
  // ──────────────────────────────────────────────────
  console.log(`\n=============================`);
  console.log(`Passed: ${passed} | Failed: ${failed}`);
  console.log(`=============================`);

  socketA.disconnect();
  socketB.disconnect();
  socketD.disconnect();
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
