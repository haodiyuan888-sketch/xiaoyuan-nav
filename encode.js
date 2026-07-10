/**
 * HTML 源码加密构建脚本
 * 域名锁定 + 反调试 + 防保存
 *
 * 构建方式: 使用字符串拼接代替模板字面量+注释，避免压缩时 // 注释吞掉代码
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

const baseKey = crypto.randomBytes(32);

function xorEncrypt(text, key) {
  const tb = Buffer.from(text, 'utf8');
  const r = Buffer.alloc(tb.length);
  for (let i = 0; i < tb.length; i++) r[i] = tb[i] ^ key[i % key.length];
  return r.toString('base64');
}
const cipher = xorEncrypt(bodyContent, baseKey);

const keyEntries = ALLOWED.map(d => {
  const dh = crypto.createHash('sha256').update(d).digest();
  const encKey = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) encKey[i] = baseKey[i] ^ dh[i];
  return encKey.toString('base64');
});

const allowedXor = crypto.randomBytes(8);
const allowedEnc = ALLOWED.map(d => {
  const db = Buffer.from(d, 'utf8');
  const enc = Buffer.alloc(db.length);
  for (let i = 0; i < db.length; i++) enc[i] = db[i] ^ allowedXor[i % 8];
  return enc.toString('base64') + '|' + db.length;
});
const allowedXorB64 = Buffer.from(allowedXor).toString('base64');

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

const keyEntriesJson = keyEntries.map(k => JSON.stringify(k)).join(',');
const allowedEncJson = allowedEnc.map(e => {
  const parts = e.split('|');
  return JSON.stringify([parts[0], parseInt(parts[1])]);
}).join(',');

// 使用字符串拼接构建解码器，完全避免 // 注释问题
var d = '';
d += '(function(){';
d += 'var _c=' + JSON.stringify(cipher) + ';';
d += 'var _ks=[' + keyEntriesJson + '];';
d += 'var _cs=' + csum + ';';
d += 'var _al=[' + allowedEncJson + '];';
d += 'var _ak=' + JSON.stringify(allowedXorB64) + ';';
d += 'function _b2a(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}';
d += 'function _a2b(a){return String.fromCharCode.apply(null,a)}';
d += 'function _sh(d){return crypto.subtle.digest("SHA-256",new TextEncoder().encode(d))}';
d += 'function _xor(a,b){var r=new Uint8Array(32);for(var i=0;i<32;i++)r[i]=a[i]^b[i%a.length];return r}';
d += 'function _x(t,k){var a=atob(t),b=new Uint8Array(a.length);for(var i=0;i<a.length;i++)b[i]=a.charCodeAt(i)^k[i%k.length];return new TextDecoder("utf-8").decode(b)}';
d += 'function _csum(s){var h1=0,h2=0;for(var i=0;i<s.length;i++){var c=s.charCodeAt(i);h1=((h1<<5)-h1+c)|0;h2=((h2<<7)-h2+c)|0}return(h1^h2)>>>0}';
d += 'function _cd(h){var ak=_b2a(_ak);for(var i=0;i<_al.length;i++){var d=_al[i][0],l=_al[i][1];var db=_b2a(d);for(var j=0;j<l;j++)db[j]^=ak[j%ak.length];var dd=_a2b(db.slice(0,l));if(h===dd||h.endsWith("."+dd))return i}return -1}';

// 立即键盘拦截
d += '(function(){';
d += 'function _kb(e){';
d += 'if(e.key==="F12"||(e.ctrlKey&&(e.key==="s"||e.key==="S"||e.key==="u"||e.key==="U"))||(e.ctrlKey&&e.shiftKey&&(e.key==="I"||e.key==="i"||e.key==="C"||e.key==="c"||e.key==="J"||e.key==="j"))||(e.metaKey&&e.altKey&&(e.key==="I"||e.key==="i"||e.key==="J"||e.key==="j"))){';
d += 'e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();return false;';
d += '}';
d += '}';
d += 'document.addEventListener("keydown",_kb,true);';
d += 'document.addEventListener("keyup",_kb,true);';
d += 'document.addEventListener("keypress",_kb,true);';
d += 'document.addEventListener("contextmenu",function(e){e.preventDefault();return false},true);';
d += '})();';

// 异步解密 IIFE
d += '(async function(){';
d += 'var h=window.location.hostname||"";';
d += 'var di=_cd(h);';
d += 'var dh=await _sh(h);dh=new Uint8Array(dh);';
d += 'var html="";';
d += 'var bk=null;';
d += 'if(di>=0){var ek=_b2a(_ks[di]);bk=_xor(ek,dh)}';
d += 'if(!bk){for(var i=0;i<_ks.length;i++){var ek=_b2a(_ks[i]);bk=_xor(ek,dh);html=_x(_c,bk);if(_csum(html)===_cs)break;bk=null}}';
d += 'if(bk){html=_x(_c,bk)}';
d += 'if(!bk||_csum(html)!==_cs){';
d += 'document.write(\'<!DOCTYPE html><html><head><meta charset="UTF-8"><style>body{margin:0;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;font-family:-apple-system,sans-serif}</style></head><body><div style="text-align:center;padding:40px"><div style="font-size:64px">&#128274;</div><h1 style="font-size:22px;margin:20px 0 8px">\\u8bbf\\u95ee\\u53d7\\u9650</h1><p style="color:#8b949e;font-size:14px">\\u6b64\\u9875\\u9762\\u4ec5\\u9650\\u6388\\u6743\\u57df\\u540d\\u8bbf\\u95ee<br>\\u590d\\u5236\\u5230\\u5176\\u4ed6\\u57df\\u540d\\u65e0\\u6cd5\\u4f7f\\u7528</p></div></body></html>\');';
d += 'return}';
d += 'document.write(html);';
d += '})();';

// DevTools 检测（延迟执行）
d += 'setTimeout(function(){';
d += 'var _p=0,_o=null;';
d += 'function _dt(){var s=performance.now();debugger;var e=performance.now();return(e-s>100)||(window.outerWidth-window.innerWidth>160)||(window.outerHeight-window.innerHeight>160)}';
d += 'function _so(){if(_o)return;_o=document.createElement("div");_o.id="_px_protect";_o.style.cssText="position:fixed;z-index:2147483647;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.95);display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif";_o.innerHTML=\'<div style="text-align:center;color:#c9d1d9;padding:40px"><div style="font-size:72px;margin-bottom:24px">&#128737;</div><h2 style="font-size:22px;margin:0 0 12px;color:#f85149">\\u5b89\\u5168\\u8b66\\u544a</h2><p style="font-size:14px;color:#8b949e;line-height:1.8">\\u68c0\\u6d4b\\u5230\\u5f00\\u53d1\\u8005\\u5de5\\u5177\\u5df2\\u6253\\u5f00<br>\\u8bf7\\u5173\\u95ed\\u5f00\\u53d1\\u8005\\u5de5\\u5177\\u540e\\u5237\\u65b0\\u9875\\u9762</p></div>\';document.body&&document.body.appendChild(_o)}';
d += 'function _ho(){if(_o){_o.remove();_o=null}}';
d += 'function _dbg(){if(!_dt()){_ho();_p=0;return}_p++;_so();if(_p<3)return;debugger;debugger;debugger;}';
d += 'setInterval(_dbg,800);';
d += '["log","info","debug","warn","error","clear"].forEach(function(k){console[k]=function(){}});';
d += 'setInterval(function(){["log","info","debug","warn","error","clear"].forEach(function(k){console[k]=function(){};});},5000);';
d += 'document.addEventListener("keydown",function(e){if(e.key==="F12"||(e.ctrlKey&&(e.key==="s"||e.key==="S"||e.key==="u"||e.key==="U"))||(e.ctrlKey&&e.shiftKey&&(e.key==="I"||e.key==="i"||e.key==="J"||e.key==="j"))){e.preventDefault();e.stopPropagation();return false;}},true);';
d += '},1500);';

// beforeunload 清空 body（防浏览器菜单保存）
d += 'window.addEventListener("beforeunload",function(){try{if(document.body&&document.body.children.length>0)document.body.innerHTML=""}catch(e){}});';

d += '})();';

const newHtml = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>' + headContent + '</head>\n<body>\n<script>' + d + '</script>\n</body>\n</html>';

fs.writeFileSync(outputFile, newHtml, 'utf8');

const os = Buffer.byteLength(html, 'utf8');
const ns = Buffer.byteLength(newHtml, 'utf8');
console.log('OK:', (os/1024).toFixed(1), 'KB ->', (ns/1024).toFixed(1), 'KB');
console.log('Domains:', ALLOWED.join(', '));
