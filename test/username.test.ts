import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_USERNAME_RULES,
  parseUsernameRules,
  usernamePluginOptions,
  usernameRulesYaml,
} from "../src/modules/username.js";

test("the rules file init writes parses back to the defaults", () => {
  assert.deepEqual(parseUsernameRules(usernameRulesYaml()), DEFAULT_USERNAME_RULES);
});

test("a bad rules file names every bad key", () => {
  assert.throws(() => parseUsernameRules("minLength: 9\nmaxLength: 3\npattern: '['\n"), /pattern: not a valid regular expression.*minLength/);
  assert.throws(() => parseUsernameRules("minLength: 3\nmaxLength: 30\npattern: '^a+$'\nlenght: 4\n"), /Unrecognized key.*lenght/);
  assert.throws(() => parseUsernameRules("minLength: three\nmaxLength: 30\npattern: '^a+$'\n"), /minLength/);
});

test("plugin options: pattern, reserved names in any casing, case rule", () => {
  const o = usernamePluginOptions({ ...DEFAULT_USERNAME_RULES, reserved: ["Admin"] });
  assert.equal(o.usernameValidator("alice_1"), true);
  assert.equal(o.usernameValidator("ADMIN"), false);
  assert.equal(o.usernameValidator("al ice"), false);
  assert.equal(typeof o.usernameNormalization, "function");
  const sensitive = usernamePluginOptions({ ...DEFAULT_USERNAME_RULES, caseInsensitive: false }).usernameNormalization;
  assert.equal(sensitive("Ａlice"), "Alice", "case kept, NFKC applied");
  assert.equal(o.usernameNormalization("Ａlice"), "alice");
  assert.equal(o.minUsernameLength, 3);
});
