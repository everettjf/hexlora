// Rebuild localized website pages from their README editions.
// cd docs && npm install && npm run build:locales
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'docs/package.json'));
const { Marked } = await import(process.env.HEXLORA_MARKED_MODULE || pathToFileURL(require.resolve('marked')).href);
const content = JSON.parse(await readFile(path.join(root, 'docs/locales/content.json'), 'utf8'));
const languages = [['en','English'],['zh-CN','简体中文'],['ja','日本語'],['ko','한국어'],['de','Deutsch'],['fr','Français'],['es','Español'],['it','Italiano'],['pt-BR','Português (Brasil)'],['ru','Русский'],['vi','Tiếng Việt']];
const escape = text => String(text).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const pageUrl = code => `https://xnu.app/hexlora/${code === 'en' ? '' : `${code}/`}`;
const readmeName = code => code === 'en' ? 'README.md' : `README.${code}.md`;
const alternates = languages.map(([code]) => `<link rel="alternate" hreflang="${code}" href="${pageUrl(code)}">`).join('\n  ') + '\n  <link rel="alternate" hreflang="x-default" href="https://xnu.app/hexlora/">';
function picker(code, prefix) {
  const label = content[code].language;
  return `<details class="language-picker"><summary>${escape(languages.find(([c]) => c === code)[1])}</summary><nav aria-label="${escape(label)}">${languages.map(([c, name]) => `<a href="${prefix}${c === 'en' ? '' : `${c}/`}" lang="${c}" hreflang="${c}"${c === code ? ' aria-current="page"' : ''}>${escape(name)}</a>`).join('')}</nav></details>`;
}
const marked = new Marked({ gfm:true, renderer: {
  heading({tokens,depth}) {
    const text = this.parser.parseInline(tokens);
    const slug = text.replace(/<[^>]+>/g,'').toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu,'').trim().replace(/\s+/g,'-');
    return `<h${depth} id="${escape(slug)}">${text}</h${depth}>\n`;
  }
}});
function rewriteUrl(url) {
  if (/^(https?:|mailto:|#)/.test(url)) return url;
  const [file, hash] = url.split('#');
  const language = languages.find(([code]) => readmeName(code) === file);
  if (language) {
    // Detailed English support references go to the canonical README, where the full matrix lives.
    if (hash) return `https://github.com/everettjf/hexlora/blob/main/${file}#${hash}`;
    return `../${language[0] === 'en' ? '' : `${language[0]}/`}`;
  }
  if (file.startsWith('docs/assets/')) return `../${file.slice(5)}`;
  return `https://github.com/everettjf/hexlora/blob/main/${url}`;
}
for (const [code, name] of languages.filter(([code]) => code !== 'en')) {
  const d = content[code];
  const readme = await readFile(path.join(root, readmeName(code)), 'utf8');
  const paragraphs = readme.split(/\n\n/);
  const about = paragraphs.find(p => p.startsWith('Hexlora'));
  if (!about) throw new Error(`Missing localized introduction: ${code}`);
  const description = about.replace(/\[([^\]]+)\]\([^)]*\)/g,'$1');
  // Remove the README title, language bar, community link and repository badges.
  const body = readme.slice(readme.indexOf(about) + about.length).trim();
  let article = marked.parse(body);
  article = article.replace(/(href|src)="([^"]+)"/g, (_, attr, url) => `${attr}="${escape(rewriteUrl(url.replace(/&amp;/g,'&')))}"`);
  article = article.replace(/<table>/g,'<div class="table-scroll"><table>').replace(/<\/table>/g,'</table></div>');
  const ui = JSON.parse(await readFile(path.join(root,'crates/hexlora-ui/locales',`${code}.json`),'utf8'));
  const shots = [['overview','Overview'],['executable','Headers'],['dependencies','Dependency Graph'],['strings','Strings'],['hex','Hex']];
  const gallery = `<div class="inspector carousel localized-gallery" id="gallery" aria-label="${escape(d.chooseScreenshot)}" aria-roledescription="carousel" data-slide-label="${escape(d.showScreenshot)}"><div class="slides" aria-live="polite">${shots.map(([file,key],i) => `<figure class="slide${i===0 ? ' active' : ''}"><img src="../assets/screenshots/${file}.jpg" alt="${escape(ui[key] || key)} · Hexlora"${i ? ' loading="lazy"' : ''}><figcaption><b>${escape(ui[key] || key)}</b></figcaption></figure>`).join('')}</div><button class="carousel-arrow previous" type="button" data-previous aria-label="${escape(d.previous)}">←</button><button class="carousel-arrow next" type="button" data-next aria-label="${escape(d.next)}">→</button><div class="carousel-dots" role="tablist" aria-label="${escape(d.chooseScreenshot)}"></div></div>`;
  article = article.replace(/<p><a href="[^"]*#gallery"><img[^>]*><\/a><\/p>/, gallery);
  const html = `<!doctype html>
<html lang="${code}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hexlora — ${escape(name)}</title>
  <meta name="description" content="${escape(description)}">
  <meta name="theme-color" content="#101415">
  <meta property="og:title" content="Hexlora — ${escape(name)}">
  <meta property="og:description" content="${escape(description)}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${pageUrl(code)}">
  <meta property="og:image" content="https://xnu.app/hexlora/assets/og.png">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="canonical" href="${pageUrl(code)}">
  ${alternates}
  <link rel="icon" type="image/png" href="../assets/icons/favicon-64.png">
  <link rel="apple-touch-icon" href="../assets/icons/apple-touch-icon.png">
  <link rel="stylesheet" href="../styles.css?v=languages-11">
  <link rel="stylesheet" href="../localized.css?v=languages-11">
</head>
<body class="localized-page">
  <header class="nav">
    <a class="brand" href="#top"><img class="brand-icon" src="../assets/icons/apple-touch-icon.png" alt=""><span>Hexlora</span></a>
    <div class="localized-nav"><a href="https://github.com/everettjf/hexlora/releases/latest">${escape(d.download)} ↗</a>${picker(code,'../')}</div>
  </header>
  <main class="shell localized-main" id="top">
    <section class="localized-intro"><p class="eyebrow">macOS · Windows · Linux</p><h1>Hexlora</h1><p class="lede">${escape(description)}</p><div class="actions"><a class="button primary" href="https://github.com/everettjf/hexlora/releases/latest">${escape(d.download)} ↗</a><a class="button" href="https://github.com/everettjf/hexlora/blob/main/${readmeName(code)}">${escape(d.readme)} ↗</a></div></section>
    <article class="localized-content">${article}</article>
  </main>
  <script src="../carousel.js" defer></script>
  <footer class="shell"><a class="brand" href="#top">Hexlora</a><p>${escape(d.footer)}</p><p><a href="https://discord.gg/eGzEaP6TzR">Discord</a> · © 2026 Hexlora · Apache-2.0</p></footer>
</body>
</html>
`;
  await mkdir(path.join(root,'docs',code),{recursive:true});
  await writeFile(path.join(root,'docs',code,'index.html'),html);
}
let english = await readFile(path.join(root,'docs/index.html'),'utf8');
english = english.replace(/\n  <!-- locale-alternates:start -->[\s\S]*?<!-- locale-alternates:end -->/,'');
english = english.replace('</head>',`  <!-- locale-alternates:start -->\n  <link rel="canonical" href="https://xnu.app/hexlora/">\n  ${alternates}\n  <link rel="stylesheet" href="localized.css?v=languages-11">\n  <!-- locale-alternates:end -->\n</head>`);
english = english.replace(/\s*<!-- locale-picker:start -->[\s\S]*?<!-- locale-picker:end -->/,'');
english = english.replace('  </header>',`    <!-- locale-picker:start -->${picker('en','./')}<!-- locale-picker:end -->\n  </header>`);
await writeFile(path.join(root,'docs/index.html'),english);
console.log('Built 10 localized pages and the 11-language selector on the English site.');
