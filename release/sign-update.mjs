import {readFile,writeFile,stat} from 'node:fs/promises';
import {createHash,sign,createPublicKey} from 'node:crypto';
import {createReadStream} from 'node:fs';
import releasePolicy from './release-policy.cjs';
const [file,version,keyPath]=process.argv.slice(2);
if(!file||!releasePolicy.versionParts(version)||!keyPath)throw Error('Usage: node scripts/sign-update.mjs installer.exe version private-key-file');
const key=keyPath==='env:NOVA_UPDATE_SIGNING_KEY'
  ? Buffer.from(process.env.NOVA_UPDATE_SIGNING_KEY || '') : await readFile(keyPath);
if(createPublicKey(key).export({type:'spki',format:'pem'}).trim()!==releasePolicy.PUBLIC_KEY.trim())throw Error('Signing key does not match NOVA public key');
const hash=createHash('sha256');for await(const chunk of createReadStream(file))hash.update(chunk);
const manifest={version,sha256:hash.digest('hex'),size:(await stat(file)).size};
manifest.signature=sign(null,Buffer.from(releasePolicy.payload(manifest)),key).toString('base64');
releasePolicy.validate(manifest);
await writeFile(file+'.sig',JSON.stringify(manifest,null,2)+'\n');
console.log('Signed update metadata created.');
