import assert from "node:assert/strict";
import { test } from "node:test";
import { revokeAndClearLocalSession } from "../src/lib/logout.ts";
import type { EnterpriseSession } from "../src/lib/enterprise-api.ts";

const session = {
  access_token: "unit-test-token",
  token_type: "bearer",
  expires_in: 60,
  user: { id: "user-1", email: "user@example.test" },
  organizations: [],
} satisfies EnterpriseSession;

test("logout clears the local session and reports successful token revocation", async () => {
  const calls: string[] = [];
  const outcome = await revokeAndClearLocalSession(
    session,
    "org-1",
    async () => {
      calls.push("revoke");
    },
    () => calls.push("clear"),
  );

  assert.deepEqual(calls, ["clear", "revoke"]);
  assert.deepEqual(outcome, { revoked: true });
});

test("logout clears the local session and exposes server revocation failure", async () => {
  const calls: string[] = [];
  const revocationError = new Error("API unavailable");
  const outcome = await revokeAndClearLocalSession(
    session,
    "org-1",
    async () => {
      calls.push("revoke");
      throw revocationError;
    },
    () => calls.push("clear"),
  );

  assert.deepEqual(calls, ["clear", "revoke"]);
  assert.equal(outcome.revoked, false);
  if (!outcome.revoked) assert.equal(outcome.error, revocationError);
});
