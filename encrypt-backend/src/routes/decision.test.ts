// Cross-language fixture test for decisionCanonicalBytes.
//
// Pins the encrypt-backend digest computation to the shared
// `fixtures/fhe-decision-vectors.json` consumed by:
//   - gateway (Go):  gateway/internal/auth/fhe_decision_canonical_test.go
//   - contract (Rust): contracts/sbf-tests/tests/fhe_decision_canonical.rs
//
// Run with:
//   cd encrypt-backend && npm test
//
// Uses Node's built-in test runner (node --test). Loaded via tsx in the
// package.json `test` script so no extra dev dep is required.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { decisionCanonicalBytes } from './decision-canonical.js';

interface Vector {
  name: string;
  policy_hex: string;
  message_digest_hex: string;
  decision_created_slot: string;
  decision_authorize: number;
  expected_digest_hex: string;
}

interface Fixture {
  version: number;
  domain: string;
  vectors: Vector[];
}

function findFixture(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  let dir = here;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, 'fixtures', 'fhe-decision-vectors.json');
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`could not locate fixtures/fhe-decision-vectors.json from ${here}`);
}

function hexToBytes(s: string, expectedLen: number): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error(`bad hex: ${s}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  if (out.length !== expectedLen) {
    throw new Error(`hex ${s} decoded to ${out.length} bytes, want ${expectedLen}`);
  }
  return out;
}

describe('decisionCanonicalBytes — fixture parity', () => {
  const fixturePath = findFixture();
  const raw = readFileSync(fixturePath, 'utf8');
  const fixture = JSON.parse(raw) as Fixture;

  it('fixture metadata is sane', () => {
    assert.equal(fixture.version, 1);
    assert.equal(fixture.domain, 'andromeda::fhe-gated::decision::v1');
    assert.ok(fixture.vectors.length > 0, 'fixture must have vectors');
  });

  for (const v of fixture.vectors) {
    it(`vector: ${v.name}`, () => {
      const policy = hexToBytes(v.policy_hex, 32);
      const msg = hexToBytes(v.message_digest_hex, 32);
      const slot = BigInt(v.decision_created_slot);
      const got = decisionCanonicalBytes(policy, msg, slot, v.decision_authorize);
      const gotHex = Buffer.from(got).toString('hex');
      assert.equal(
        gotHex,
        v.expected_digest_hex,
        `vector ${v.name}: digest mismatch\n got:  ${gotHex}\n want: ${v.expected_digest_hex}`,
      );
    });
  }
});
