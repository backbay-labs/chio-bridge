import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import {
  canonicalizeJson,
  sha256Hex,
  signUtf8MessageEd25519,
  verifyReceipt,
  type ChioReceipt,
} from "@chio-protocol/sdk/invariants";
import { verifyReceiptValue } from "../dist/receipts.js";

function ed25519PublicHexFromSeed(seedHex: string): string {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pk = createPrivateKey({
    key: Buffer.concat([prefix, Buffer.from(seedHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(pk).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(12).toString("hex");
}

function buildSignedReceipt(seedHex: string): ChioReceipt {
  const parameters = { path: "/workspace/README.md" };
  const parameter_hash = sha256Hex(canonicalizeJson(parameters));
  const kernel_key = ed25519PublicHexFromSeed(seedHex);
  const body = {
    receipt_kind: "mediated_decision", boundary_class: "prevent", trust_level: "mediated",
    tool_origin: "caller_executed", redaction_mode: "none",
    id: "rcpt_" + sha256Hex("fixture").slice(0, 32),
    timestamp: 1_710_000_000,
    capability_id: "cap_test_001",
    tool_server: "fs",
    tool_name: "read_file",
    action: { parameters, parameter_hash },
    decision: { verdict: "allow" as const },
    content_hash: sha256Hex("test-content"),
    policy_hash: sha256Hex("test-policy"),
    kernel_key,
    evidence: [{ guard_name: "PathAllowlistGuard", verdict: true }],
  };
  const { id: _id, ...idInput } = body;
  body.id = sha256Hex(canonicalizeJson(idInput));
  const canonical = canonicalizeJson({ id: body.id, body: idInput });
  const signed = signUtf8MessageEd25519(canonical, seedHex);
  return { ...body, signature: signed.signature_hex } as ChioReceipt;
}

test("verifyReceipt returns true for a well-signed receipt", async () => {
  const seedHex = randomBytes(32).toString("hex");
  const receipt = buildSignedReceipt(seedHex);
  const v = verifyReceipt(receipt);
  assert.equal(v.signature_valid, true, "signature should verify");
  assert.equal(v.parameter_hash_valid, true, "parameter hash should match");
  assert.equal(await verifyReceiptValue(receipt), true);
  assert.equal(await verifyReceiptValue(JSON.stringify(receipt)), true);
});

test("verifyReceipt rejects tampered receipts", async () => {
  const seedHex = randomBytes(32).toString("hex");
  const receipt = buildSignedReceipt(seedHex);
  const tampered: ChioReceipt = {
    ...receipt,
    decision: { verdict: "deny", reason: "tampered" },
  };
  assert.equal(await verifyReceiptValue(tampered), false);
});

test("verifyReceipt rejects parameter_hash mismatches", async () => {
  const seedHex = randomBytes(32).toString("hex");
  const receipt = buildSignedReceipt(seedHex);
  const tampered: ChioReceipt = {
    ...receipt,
    action: { parameters: { path: "/other" }, parameter_hash: receipt.action.parameter_hash },
  };
  assert.equal(await verifyReceiptValue(tampered), false);
});
