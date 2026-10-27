// SPDX-License-Identifier: Apache-2.0
export * from "../src/index.js";
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
