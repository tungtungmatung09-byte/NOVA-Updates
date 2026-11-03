const { verify, createHash } = require("node:crypto");
const { createReadStream } = require("node:fs");
const { stat } = require("node:fs/promises");
const PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxaZGqFzDfsbwcbSST8WKC9bolVHGedhRu6/pwcsbE8E=\n-----END PUBLIC KEY-----\n";
const REPOSITORY = "tungtungmatung09-byte/NOVA-Updates";
const POLICY_URL = `https://github.com/${REPOSITORY}/releases/latest/download/NOVA-Setup.exe.sig`;
function versionParts(version) {
  if (
    typeof version !== "string" ||
    !/^(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})\.(0|[1-9]\d{0,6})$/.test(version)
  )
    return null;
  return version.split(".").map(Number);
}
function older(a, b) {
  const x = versionParts(a),
    y = versionParts(b);
  if (!x || !y) return true;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i];
  return false;
}
function payload(manifest) {
  return JSON.stringify({
    version: manifest.version,
    sha256: manifest.sha256,
    size: manifest.size,
  });
}
function validate(manifest) {
  if (
    !manifest ||
    !versionParts(manifest.version) ||
    !/^[a-f0-9]{64}$/.test(manifest.sha256) ||
    !Number.isSafeInteger(manifest.size) ||
    manifest.size <= 0 ||
    manifest.size > 1024 * 1024 * 1024 ||
    typeof manifest.signature !== "string" ||
    manifest.signature.length > 150
  )
    throw Error("Invalid update policy");
  if (
    !verify(
      null,
      Buffer.from(payload(manifest)),
      PUBLIC_KEY,
      Buffer.from(manifest.signature, "base64"),
    )
  )
    throw Error("Update signature verification failed");
  return {
    version: manifest.version,
    sha256: manifest.sha256,
    size: manifest.size,
    signature: manifest.signature,
  };
}
async function fetchPolicy(request = fetch, url = POLICY_URL) {
  const response = await request(url, {
    signal: AbortSignal.timeout(5000),
    redirect: "follow",
  });
  if (response.status === 404) return null;
  if (!response.ok) throw Error("Update service unavailable");
  const reader = response.body.getReader();
  let total = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 4096) {
        await reader.cancel();
        throw Error("Update policy too large");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return validate(JSON.parse(Buffer.concat(chunks).toString("utf8")));
}
async function verifyInstaller(manifest, file) {
  validate(manifest);
  if ((await stat(file)).size !== manifest.size)
    throw Error("Update size mismatch");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  if (hash.digest("hex") !== manifest.sha256)
    throw Error("Update checksum mismatch");
}
module.exports = {
  PUBLIC_KEY,
  REPOSITORY,
  POLICY_URL,
  versionParts,
  older,
  payload,
  validate,
  fetchPolicy,
  verifyInstaller,
};
