/**
 * Phone number sign-in presets (spec B5) on Better Auth's `phoneNumber` plugin.
 *
 * createBoilAuth({ phone: { sendSms } }) adds the plugin with these presets:
 *   - numbers must be E.164 (+ and 8..15 digits),
 *   - 6-digit SMS codes, valid 5 minutes, 3 wrong tries spend the code,
 *   - phone + password sign-in only for a verified number.
 *
 * Paths: POST /phone-number/send-otp, POST /phone-number/verify (with
 * updatePhoneNumber: true to attach a number to the signed-in user; without
 * it, a verified code for a known number signs that user in), POST
 * /sign-in/phone-number (number + password; lockout covers it).
 *
 * An SMS-code sign-in has no second step, like magic link: it never
 * satisfies boilauth/mfa's admin requirement.
 */
import { phoneNumber } from "better-auth/plugins";

export interface SmsMessage {
  to: string;
  text: string;
}

export interface PhoneOptions {
  sendSms: (msg: SmsMessage) => Promise<void>;
}

export const E164 = /^\+[1-9]\d{7,14}$/;

export function phonePlugin(o: PhoneOptions) {
  return phoneNumber({
    otpLength: 6,
    expiresIn: 300,
    allowedAttempts: 3,
    requireVerification: true,
    phoneNumberValidator: (n: string) => E164.test(n),
    sendOTP: async ({ phoneNumber: to, code }) => o.sendSms({ to, text: `Your code is ${code}. It expires in 5 minutes.` }),
  });
}
