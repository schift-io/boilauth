/** Which schema modules a set of answers turns on (mirrors enabledModules()). */
import type { SchemaModule } from "../schema.js";
import type { Answers } from "../wizard/answers.js";

export function enabledModulesFor(a: Answers): SchemaModule[] {
  const out: SchemaModule[] = ["core"];
  if (a.roles.mode !== "none") out.push("admin");
  if (a.mfa.mode !== "off") out.push("two-factor");
  if (a.mfa.mode === "totp_required_admin") out.push("mfa-admin");
  if (a.roles.mode === "organizations") out.push("organization");
  if (a.deletion.mode === "soft") out.push("soft-delete");
  if (a.signIn.emailPassword && a.signIn.username) out.push("username");
  return out;
}
