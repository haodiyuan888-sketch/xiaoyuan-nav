/**
 * HTML 源码加密（域名锁定版 v5 — 多域名支持）
 *
 * 原理：
 *   body 用 baseKey 加密
 *   baseKey 分别用每个授权域名的 SHA256 加密存储
 *   解密时：当前域名 SHA256 尝试解密每个 baseKey 密文，成功则解密 body
 *
 *   复制到其他域名 → SHA256 不在列表中 → 无法解密 baseKey → 页面乱码
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const dir = __dirname;
const inputFile = path.join(dir, 'source.html');
const outputFile = path.join(dir, 'index.html');

const ALLOWED = [
  'xiaoyuan-nav.onrender.com',
  'haodiyuan888-sketch.github.io',
  'localhost',
  '127.0.0.1'
];

const html = fs.readFileSync(inputFile, 'utf8');
const hm = html.match(/<head>([\s\S]*?)<\/head>/);
if (!hm) { console.error('no <head>'); process.exit(1); }
const headContent = hm[1];
const bm = html.match(/<body>([\s\S]*?)<\/body>/);
if (!bm) { console.error('no <body>'); process.exit(1); }
const bodyContent = bm[1];

// 生成 32 字节基础密钥用于加密 body
const baseKey = crypto.randomBytes(32);

// 用 baseKey 加密 body
function xorEncrypt(text, key) {
  const tb = Buffer.from(text, 'utf8');
  const r = Buffer.alloc(tb.length);
  for (let i = 0; i < tb.length; i++) r[i] = tb[i] ^ key[i % key.length];
  return r.toString('base64');
}
const cipher = xorEncrypt(bodyContent, baseKey);

// 为每个授权域名加密 baseKey：encKey_i = baseKey XOR SHA256(domain_i)
const keyEntries = ALLOWED.map(d => {
  const dh = crypto.createHash('sha256').update(d).digest();
  const encKey = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) encKey[i] = baseKey[i] ^ dh[i];
  return encKey.toString('base64');
});

// 混淆存储域名列表
const allowedXor = crypto.randomBytes(8);
const allowedEnc = ALLOWED.map(d => {
  const db = Buffer.from(d, 'utf8');
  const enc = Buffer.alloc(db.length);
  for (let i = 0; i < db.length; i++) enc[i] = db[i] ^ allowedXor[i % 8];
  return enc.toString('base64') + '|' + db.length;
});
const allowedXorB64 = Buffer.from(allowedXor).toString('base64');

// 校验和
function checksum(str) {
  let h1 = 0, h2 = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = ((h1 << 5) - h1 + c) | 0;
    h2 = ((h2 << 7) - h2 + c) | 0;
  }
  return (h1 ^ h2) >>> 0;
}
const csum = checksum(bodyContent);

const decoder = `
(function(){
var _c="${cipher}";
var _ks=[${keyEntries.map(k => JSON.stringify(k)).join(',')}];
var _cs=${csum};
var _al=[${allowedEnc.map(e => { const [enc, len] = e.split('|'); return `["${enc}",${len}]`; }).join(',')}];
var _ak="${allowedXorB64}";

function _b2a(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
function _a2b(a){return String.fromCharCode.apply(null,a)}
function _sh(d){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(d))}
function _xor(a,b){var r=new Uint8Array(32);for(var i=0;i<32;i++)r[i]=a[i]^b[i%a.length];return r}
function _x(t,k){var a=atob(t),b=new Uint8Array(a.length);for(var i=0;i<a.length;i++)b[i]=a.charCodeAt(i)^k[i%k.length];return new TextDecoder('utf-8').decode(b)}
function _csum(s){var h1=0,h2=0;for(var i=0;i<s.length;i++){var c=s.charCodeAt(i);h1=((h1<<5)-h1+c)|0;h2=((h2<<7)-h2+c)|0}return(h1^h2)>>>0}
function _cd(h){var ak=_b2a(_ak);for(var i=0;i<_al.length;i++){var d=_al[i][0],l=_al[i][1];var db=_b2a(d);for(var j=0;j<l;j++)db[j]^=ak[j%ak.length];var dd=_a2b(db.slice(0,l));if(h===dd||h.endsWith('.'+dd))return i}return -1}

(async function(){
var h=window.location.hostname||'';
var di=_cd(h);
var dh=await _sh(h);dh=new Uint8Array(dh);
var html='';
// 尝试用当前域名哈希解密 baseKey
var bk=null;
if(di>=0){
  // 授权域名：从加密的 baseKey 列表中解密
  var ek=_b2a(_ks[di]);
  bk=_xor(ek,dh);
}
if(!bk){
  // 非授权域名：遍历尝试（理论上不会成功）
  for(var i=0;i<_ks.length;i++){
    var ek=_b2a(_ks[i]);
    bk=_xor(ek,dh);
    html=_x(_c,bk);
    if(_csum(html)===_cs)break;
    bk=null;
  }
}
if(bk){html=_x(_c,bk)}
if(!bk||_csum(html)!==_cs){
document.write('<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><style>body{margin:0;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;font-family:-apple-system,sans-serif}</style></head><body><div style=\"text-align:center;padding:40px\"><div style=\"font-size:64px\">&#128274;</div><h1 style=\"font-size:22px;margin:20px 0 8px\">'+'\\u8bbf\\u95ee\\u53d7\\u9650'+'</h1><p style=\"color:#8b949e;font-size:14px\">'+'\\u6b64\\u9875\\u9762\\u4ec5\\u9650\\u6388\\u6743\\u57df\\u540d\\u8bbf\\u95ee'+'<br>'+'\\u590d\\u5236\\u5230\\u5176\\u4ed6\\u57df\\u540d\\u65e0\\u6cd5\\u4f7f\\u7528'+'</p></div></body></html>');
return}
document.write(html);
})();
})();`;

const newHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>${headContent}</head>
<body>
<script>${decoder}</script>
</body>
</html>`;

fs.writeFileSync(outputFile, newHtml, 'utf8');

const os = Buffer.byteLength(html, 'utf8');
const ns = Buffer.byteLength(newHtml, 'utf8');
console.log('OK:', (os/1024).toFixed(1), 'KB ->', (ns/1024).toFixed(1), 'KB');
console.log('Domains:', ALLOWED.join(', '));
