// SPDX-License-Identifier: Apache-2.0
// Sign In With QoreChain: an HTTP server that issues single-use nonces and
// verifies sign-ins against the ML-DSA-87 key registered on chain, plus a
// client that signs in to it.
//
//   QORE_MNEMONIC="<testnet mnemonic of an account with a registered key>" node index.mjs
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import {
  addressFromPublicKey,
  createSiwqMessage,
  deriveCanonicalPqKey,
  deriveClassicalKey,
  isQoreSignError,
  signSiwq,
} from "@qorechain/qoresign";
import { verifySiwqWithChain } from "@qorechain/qoresign/network";

const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const CHAIN_ID = process.env.QORE_CHAIN_ID ?? "qorechain-diana";
const PORT = Number(process.env.PORT ?? 8787);
const DOMAIN = `localhost:${PORT}`;

// --- server -----------------------------------------------------------------
const nonces = new Set();

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/nonce") {
    const nonce = randomBytes(12).toString("hex");
    nonces.add(nonce);
    return json(res, 200, { nonce });
  }
  if (req.method === "POST" && req.url === "/verify") {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const { address, message, signature } = JSON.parse(raw);
    const nonce = message.match(/^Nonce: (\S+)$/m)?.[1];
    if (!nonce || !nonces.delete(nonce)) return json(res, 401, { error: "unknown or used nonce" });
    try {
      const fields = await verifySiwqWithChain({
        rest: REST,
        address,
        message,
        signature,
        domain: req.headers.host,
        nonce,
        chainId: CHAIN_ID,
      });
      return json(res, 200, { signedIn: fields.address, possessionProven: fields.possessionProven });
    } catch (err) {
      return json(res, 401, { error: isQoreSignError(err) ? err.code : "error" });
    }
  }
  json(res, 404, {});
});

// --- client -----------------------------------------------------------------
async function signIn(mnemonic) {
  const classical = deriveClassicalKey({ mnemonic });
  const address = addressFromPublicKey(classical.publicKey, "secp256k1").bech32;
  const pqKey = deriveCanonicalPqKey({ mnemonic, address });
  const { nonce } = await (await fetch(`http://${DOMAIN}/nonce`)).json();
  const message = createSiwqMessage({
    scheme: "http",
    domain: DOMAIN,
    address,
    statement: "Sign in to the QoreSign example server.",
    uri: `http://${DOMAIN}/`,
    chainId: CHAIN_ID,
    nonce,
    issuedAt: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    expirationTime: new Date(Date.now() + 5 * 60_000).toISOString().replace(/\.\d+Z$/, "Z"),
  });
  console.log(message, "\n");
  const signature = signSiwq({ message, classicalKey: classical, pqKey });
  const post = (body) =>
    fetch(`http://${DOMAIN}/verify`, { method: "POST", body: JSON.stringify(body) }).then((r) => r.json());
  console.log("sign-in:", await post({ address, message, signature }));
  console.log("replay: ", await post({ address, message, signature }));
}

const mnemonic = process.env.QORE_MNEMONIC;
if (!mnemonic) throw new Error("set QORE_MNEMONIC to a testnet account with a registered ML-DSA-87 key");
server.listen(PORT, async () => {
  try {
    await signIn(mnemonic);
  } finally {
    server.close();
  }
});
