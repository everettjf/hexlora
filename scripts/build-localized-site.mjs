import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const docs=fileURLToPath(new URL('../docs/',import.meta.url));
for (const locale of ['', 'de','es','fr','it','ja','ko','pt-BR','ru','vi','zh-CN']) {
  const target=`https://atomsprout.com/hexlora/${locale ? locale+'/' : ''}`;
  const file=path.join(docs,locale,'index.html');fs.mkdirSync(path.dirname(file),{recursive:true});
  fs.writeFileSync(file,`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Hexlora — AtomSprout</title><meta name="robots" content="noindex"><link rel="canonical" href="${target}"><meta http-equiv="refresh" content="0;url=${target}"></head><body><a href="${target}">Continue to AtomSprout</a><script>location.replace(${JSON.stringify(target)}+location.search+location.hash)</script></body></html>`);
}
console.log('Legacy localized routes now redirect to the canonical company website.');
