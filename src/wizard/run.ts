/**
 * Runs QUESTIONS over existing answers. Keys already present in the answers
 * file are not asked again. `yes` never prompts and takes defaults.
 */
import { DEFAULT_ANSWERS, getPath, normalizeAnswers, setPath, validateAnswers, type Answers } from "./answers.js";
import { QUESTIONS, type Question } from "./questions.js";

export interface WizardOptions {
  yes: boolean;
  existing: Record<string, unknown> | null;
  /** key=value overrides from --set, never re-asked. */
  overrides?: Record<string, unknown>;
  /** Injected for tests; defaults to @clack/prompts. */
  ask?: (q: Question, current: unknown, answers: Answers) => Promise<unknown>;
}

export function parseOverride(raw: string): [string, unknown] {
  const i = raw.indexOf("=");
  if (i < 1) throw new Error(`--set expects key=value, got "${raw}"`);
  const key = raw.slice(0, i);
  const value = raw.slice(i + 1);
  const def = getPath(DEFAULT_ANSWERS, key);
  if (def === undefined) throw new Error(`unknown policy key "${key}"`);
  if (Array.isArray(def)) return [key, value === "" ? [] : value.split(",").map((s) => s.trim())];
  if (typeof def === "number") return [key, Number(value)];
  if (typeof def === "boolean") return [key, value === "true" || value === "yes"];
  return [key, value];
}

async function clackAsk(q: Question, current: unknown, answers: Answers): Promise<unknown> {
  const p = await import("@clack/prompts");
  const cancelled = (v: unknown) => {
    if (p.isCancel(v)) {
      p.cancel("cancelled");
      process.exit(1);
    }
    return v;
  };
  const options = (q.options ?? []).filter((o) => !q.hideOption?.(answers, o.value));
  switch (q.type) {
    case "select":
      return cancelled(await p.select({ message: q.message, options, initialValue: current as string }));
    case "multiselect":
      return cancelled(await p.multiselect({ message: q.message, options, initialValues: current as string[], required: false }));
    case "confirm":
      return cancelled(await p.confirm({ message: q.message, initialValue: Boolean(current) }));
    case "number": {
      const v = cancelled(
        await p.text({
          message: q.message,
          defaultValue: String(current),
          placeholder: String(current),
          validate: (s) => (s && Number.isNaN(Number(s)) ? "enter a number" : undefined),
        }),
      ) as string;
      return v === "" ? current : Number(v);
    }
    case "text": {
      const shown = Array.isArray(current) ? current.join(",") : String(current);
      const v = cancelled(await p.text({ message: q.message, defaultValue: shown, placeholder: shown })) as string;
      return q.parse ? q.parse(v || shown) : v || shown;
    }
  }
}

export async function runWizard(o: WizardOptions): Promise<Answers> {
  const raw: Record<string, unknown> = structuredClone(o.existing ?? {});
  for (const [k, v] of Object.entries(o.overrides ?? {})) setPath(raw, k, v);
  let answers = normalizeAnswers(raw);
  const ask = o.ask ?? clackAsk;
  let lastGroup = "";
  for (const q of QUESTIONS) {
    if (q.when && !q.when(answers)) continue;
    if (getPath(raw, q.key) !== undefined || o.yes) continue;
    if (!o.ask && q.group !== lastGroup) {
      const p = await import("@clack/prompts");
      p.log.step(q.group);
      lastGroup = q.group;
    }
    const value = await ask(q, getPath(answers, q.key), answers);
    setPath(raw, q.key, value);
    answers = normalizeAnswers(raw);
  }
  const errs = validateAnswers(answers);
  if (errs.length) throw new Error(`invalid answers:\n  ${errs.join("\n  ")}`);
  return answers;
}
