/**
 * Onion Router — Multi-Hop Encryption Protocol
 *
 * Provides 3-layer AES-256-GCM onion wrapping and peeling.
 * Each layer encrypts the next-hop address inside, so intermediate
 * relays only learn the immediate next hop — never the origin or
 * final destination.
 */

const crypto = require('crypto');

/**
 * Encrypt a plaintext JSON object with AES-256-GCM.
 * @param {Buffer} key   - 32-byte AES key
 * @param {object} data  - object to encrypt
 * @returns {{ nonce: string, tag: string, val: string }}
 */
function aesEncrypt(key, data) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const plaintext = JSON.stringify(data);
  const val = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
  return {
    nonce: nonce.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    val,
  };
}

/**
 * Decrypt an AES-256-GCM ciphertext back to a JSON object.
 * @param {Buffer} key   - 32-byte AES key
 * @param {string} nonce - hex-encoded 12-byte nonce
 * @param {string} tag   - hex-encoded 16-byte auth tag
 * @param {string} val   - hex-encoded ciphertext
 * @returns {object|null} - decrypted object, or null on failure
 */
function aesDecrypt(key, nonce, tag, val) {
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(nonce, 'hex')
    );
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const plaintext =
      decipher.update(val, 'hex', 'utf8') + decipher.final('utf8');
    return JSON.parse(plaintext);
  } catch {
    return null;
  }
}

/**
 * Wrap a payload in 3 layers of onion encryption.
 *
 * @param {object} payload - the cleartext payload (e.g. { type, missingIds, originAddr })
 * @param {Array<{ key: Buffer, nextAddr: string }>} hops
 *   3-element array ordered [hop0, hop1, hop2] where hop2 is the final destination.
 *   - key: the AES-256-GCM shared key with that hop's node
 *   - nextAddr: the HTTP address of that hop (e.g. 'http://localhost:3002')
 *
 * @returns {{ ciphertext: { nonce, tag, val }, firstHop: string }}
 */
function wrapOnion(payload, hops) {
  if (hops.length < 1 || hops.length > 3) {
    throw new Error(`wrapOnion requires 1-3 hops, got ${hops.length}`);
  }

  // Build from the inside out.
  // Layer 3 (innermost): the actual payload, next = null (final destination)
  const layer3 = aesEncrypt(hops[hops.length - 1].key, {
    inner: payload,
    next: null,
  });

  if (hops.length === 1) {
    return { ciphertext: layer3, firstHop: hops[0].nextAddr };
  }

  // Layer 2: wraps layer3, next = hop[2]'s address
  const layer2 = aesEncrypt(hops[hops.length - 2].key, {
    inner: layer3,
    next: hops[hops.length - 1].nextAddr,
  });

  if (hops.length === 2) {
    return { ciphertext: layer2, firstHop: hops[0].nextAddr };
  }

  // Layer 1 (outermost): wraps layer2, next = hop[1]'s address
  const layer1 = aesEncrypt(hops[0].key, {
    inner: layer2,
    next: hops[1].nextAddr,
  });

  return { ciphertext: layer1, firstHop: hops[0].nextAddr };
}

/**
 * Peel one layer of onion encryption.
 *
 * @param {{ nonce: string, tag: string, val: string }} encryptedPayload
 * @param {Buffer} key - AES-256-GCM key for this layer
 * @returns {{ inner: object, next: string|null }} - inner blob + next hop (null = final dest)
 */
function peelOnion(encryptedPayload, key) {
  const decrypted = aesDecrypt(
    key,
    encryptedPayload.nonce,
    encryptedPayload.tag,
    encryptedPayload.val
  );

  if (!decrypted) {
    return null;
  }

  return {
    inner: decrypted.inner,
    next: decrypted.next,
  };
}

/**
 * Build a return-path onion (reverse route).
 * Same as wrapOnion but semantically used for the recovery response.
 *
 * @param {object} payload - the recovery response data
 * @param {Array<{ key: Buffer, nextAddr: string }>} reverseHops
 *   Hops in reverse order (final→origin), e.g. [C→B key, B→A key, A addr]
 * @returns {{ ciphertext: { nonce, tag, val }, firstHop: string }}
 */
function wrapReturnOnion(payload, reverseHops) {
  return wrapOnion(payload, reverseHops);
}

module.exports = { wrapOnion, peelOnion, wrapReturnOnion, aesEncrypt, aesDecrypt };
