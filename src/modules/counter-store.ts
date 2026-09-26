/**
 * Counters in Better Auth's rateLimit storage (the rateLimit table, or process
 * memory), with the conditional increment Better Auth itself uses so
 * concurrent requests cannot both pass. Used by boilauth/rate-limit (per
 * address) and the sign-in lockout (per source, per account).
 */
export type Decision = { allowed: boolean; retryAfter: number };
export const memory = new Map<string, { count: number; lastRequest: number }>();

export async function consumeMemory(key: string, max: number, windowS: number, now: number): Promise<Decision> {
  const row = memory.get(key);
  if (!row || now - row.lastRequest >= windowS * 1000) {
    memory.set(key, { count: 1, lastRequest: now });
    return { allowed: true, retryAfter: 0 };
  }
  if (row.count >= max) return { allowed: false, retryAfter: Math.ceil((row.lastRequest + windowS * 1000 - now) / 1000) };
  memory.set(key, { count: row.count + 1, lastRequest: now });
  return { allowed: true, retryAfter: 0 };
}

export async function consumeDatabase(db: any, key: string, max: number, windowS: number, now: number, depth = 0): Promise<Decision> {
  if (depth > 5) return { allowed: false, retryAfter: windowS };
  const read = async () => {
    const [row] = await db.findMany({ model: "rateLimit", where: [{ field: "key", value: key }] });
    if (row && typeof row.lastRequest === "bigint") row.lastRequest = Number(row.lastRequest);
    return row as { count: number; lastRequest: number } | undefined;
  };
  const row = await read();
  if (!row) {
    try {
      await db.create({ model: "rateLimit", data: { key, count: 1, lastRequest: now } });
      return { allowed: true, retryAfter: 0 };
    } catch {
      return consumeDatabase(db, key, max, windowS, now, depth + 1); // another request created it first
    }
  }
  const windowMs = windowS * 1000;
  if (now - row.lastRequest >= windowMs) {
    const reset = await db.incrementOne({
      model: "rateLimit",
      where: [{ field: "key", value: key }, { field: "lastRequest", operator: "lte", value: row.lastRequest }],
      increment: {},
      set: { count: 1, lastRequest: now },
    });
    return reset ? { allowed: true, retryAfter: 0 } : consumeDatabase(db, key, max, windowS, now, depth + 1);
  }
  // Counts up only while under max inside the window; the window start stays put.
  const ok = await db.incrementOne({
    model: "rateLimit",
    where: [
      { field: "key", value: key },
      { field: "lastRequest", operator: "gt", value: now - windowMs },
      { field: "count", operator: "lt", value: max },
    ],
    increment: { count: 1 },
  });
  if (ok) return { allowed: true, retryAfter: 0 };
  const fresh = await read();
  if (!fresh || now - fresh.lastRequest >= windowMs) return consumeDatabase(db, key, max, windowS, now, depth + 1);
  return { allowed: false, retryAfter: Math.ceil((fresh.lastRequest + windowMs - now) / 1000) };
}


export type Counter = { count: number; lastRequest: number };

/** The counter if it is inside its window, else null. Does not count. */
export async function peek(storage: "memory" | "database", db: any, key: string, windowS: number, now: number): Promise<Counter | null> {
  let row: Counter | undefined;
  if (storage === "memory") row = memory.get(key);
  else {
    [row] = await db.findMany({ model: "rateLimit", where: [{ field: "key", value: key }] });
    if (row && typeof row.lastRequest === "bigint") row.lastRequest = Number(row.lastRequest);
  }
  return row && now - row.lastRequest < windowS * 1000 ? row : null;
}

/** Counts one event, up to max inside the window. */
export function consume(storage: "memory" | "database", db: any, key: string, max: number, windowS: number, now: number): Promise<Decision> {
  return storage === "memory" ? consumeMemory(key, max, windowS, now) : consumeDatabase(db, key, max, windowS, now);
}

export async function reset(storage: "memory" | "database", db: any, key: string): Promise<void> {
  if (storage === "memory") memory.delete(key);
  else await db.deleteMany({ model: "rateLimit", where: [{ field: "key", value: key }] });
}
