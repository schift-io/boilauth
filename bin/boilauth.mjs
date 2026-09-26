#!/usr/bin/env node
import { main } from "../dist/cli.js";
main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`boilauth: ${err.message}`);
    process.exit(1);
  },
);
