import { test } from "node:test";
import assert from "node:assert/strict";
import { settleOwnership } from "../src/modules/deletion-steps.js";

/** In-memory member table with the adapter calls settleOwnership uses. */
function fakeDb(rows: { id: string; organizationId: string; userId: string; role: string; createdAt: Date }[]) {
  return {
    rows,
    findMany: async ({ where }: { where: { field: string; value: unknown }[] }) =>
      rows.filter((r) => where.every((w) => (r as Record<string, unknown>)[w.field] === w.value)),
    update: async ({ where, update }: { where: { value: unknown }[]; update: Record<string, unknown> }) => {
      const r = rows.find((x) => x.id === where[0].value)!;
      Object.assign(r, update);
      return r;
    },
  };
}
const t = (n: number) => new Date(2026, 0, n);

test("transfer: every organization is checked before any role changes", async () => {
  const db = fakeDb([
    { id: "a1", organizationId: "A", userId: "u", role: "owner", createdAt: t(1) },
    { id: "a2", organizationId: "A", userId: "x", role: "admin", createdAt: t(2) },
    { id: "b1", organizationId: "B", userId: "u", role: "owner", createdAt: t(1) },
    { id: "b2", organizationId: "B", userId: "y", role: "member", createdAt: t(2) },
  ]);
  await assert.rejects(settleOwnership(db, "u", "transfer_to_oldest_admin"), /ORG_OWNER_TRANSFER_REQUIRED|no admin/);
  assert.equal(db.rows.find((r) => r.id === "a2")!.role, "admin", "A untouched because B refused");
});

test("transfer: the admin who joined first becomes owner; co-owned and solo orgs need nothing", async () => {
  const db = fakeDb([
    { id: "a1", organizationId: "A", userId: "u", role: "owner", createdAt: t(1) },
    { id: "a2", organizationId: "A", userId: "late", role: "admin", createdAt: t(5) },
    { id: "a3", organizationId: "A", userId: "early", role: "member,admin", createdAt: t(3) },
    { id: "c1", organizationId: "C", userId: "u", role: "owner", createdAt: t(1) },
    { id: "c2", organizationId: "C", userId: "z", role: "owner", createdAt: t(2) },
    { id: "d1", organizationId: "D", userId: "u", role: "owner", createdAt: t(1) },
  ]);
  await settleOwnership(db, "u", "transfer_to_oldest_admin");
  assert.equal(db.rows.find((r) => r.id === "a3")!.role, "owner");
  assert.equal(db.rows.find((r) => r.id === "a2")!.role, "admin");
  assert.equal(db.rows.find((r) => r.id === "c2")!.role, "owner");
});

test("block: refused whenever another member remains without an owner", async () => {
  const db = fakeDb([
    { id: "a1", organizationId: "A", userId: "u", role: "owner", createdAt: t(1) },
    { id: "a2", organizationId: "A", userId: "x", role: "admin", createdAt: t(2) },
  ]);
  await assert.rejects(settleOwnership(db, "u", "block"), (e: { body?: { code?: string } }) => e.body?.code === "ORG_OWNER_TRANSFER_REQUIRED");
});
