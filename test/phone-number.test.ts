/** F18 (audit 2026-09-27): one phone line, one E.164 string. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { phoneNumberAllowed } from "../src/modules/phone.js";

test("F18: a national trunk 0 after the country code is refused (+82 010 ... is +82 10 ...)", () => {
  assert.equal(phoneNumberAllowed({}, "+821012345678"), true);
  assert.equal(phoneNumberAllowed({}, "+8201012345678"), false);
  assert.equal(phoneNumberAllowed({}, "+4407911123456"), false);
  assert.equal(phoneNumberAllowed({}, "+447911123456"), true);
  assert.equal(phoneNumberAllowed({}, "+14155550123"), true);
  assert.equal(phoneNumberAllowed({}, "+390612345678"), true, "Italy keeps its leading 0");
  assert.equal(phoneNumberAllowed({}, "+35312345678"), true, "3-digit country code");
  assert.equal(phoneNumberAllowed({}, "+353012345678"), false);
});
