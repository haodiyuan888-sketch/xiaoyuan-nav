/**
 * HTML 源码加密构建脚本
 * 将页面正文内容和脚本进行 XOR + Base64 加密，防止直接查看源码
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const dir = __dirname;
const inputFile = path.join(dir, 'index.html');
const outputFile = path.join(dir, 'index.html');

// 读取原始 HTML
const html = fs.readFileSync(inputFile, 'utf8');

// 生成随机密钥
const key = crypto.randomBytes(16).toString('hex');

// 提取 head 部分（保留原样用于正常渲染）
const headMatch = html.match(/<head>([\s\S]*?)<\/head>/);
if (!headMatch) { console.error('未找到 <head> 标签'); process.exit(1); }
const headContent = headMatch[1];

// 提取 body 内容
const bodyMatch = html.match(/<body>([\s\S]*?)<\/body>/);
if (!bodyMatch) { console.error('未找到 <body> 标签'); process.exit(1); }
const bodyContent = bodyMatch[1];

// XOR 加密
function xorEncrypt(text, key) {
  const keyBytes = Buffer.from(key, 'utf8');
  const textBytes = Buffer.from(text, 'utf8');
  const result = Buffer.alloc(textBytes.length);
  for (let i = 0; i < textBytes.length; i++) {
    result[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return result.toString('base64');
}

const encryptedBody = xorEncrypt(bodyContent, key);

// 将 key 拆分成多个部分，运行时拼接以增加逆向难度
const keyParts = [];
for (let i = 0; i < key.length; i += 4) {
  keyParts.push(key.substring(i, Math.min(i + 4, key.length)));
}
const keyPartsStr = keyParts.map(p => JSON.stringify(p)).join('+');

// 解码逻辑（使用 TextDecoder 正确处理 UTF-8 多字节字符）
const decoderScript = `
(function(){
var _k=${keyPartsStr};
var _d=document;
var _c="${encryptedBody}";
function _x(t,k){
var a=atob(t),b=new Uint8Array(a.length);
for(var i=0;i<a.length;i++){
b[i]=a.charCodeAt(i)^k.charCodeAt(i%k.length);
}
return new TextDecoder('utf-8').decode(b);
}
_d.write(_x(_c,_k));
})();`;

// 构建新的 HTML
const newHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>${headContent}</head>
<body>
<script>${decoderScript}</script>
</body>
</html>`;

// 写入文件
fs.writeFileSync(outputFile, newHtml, 'utf8');

// 计算压缩比
const origSize = Buffer.byteLength(html, 'utf8');
const newSize = Buffer.byteLength(newHtml, 'utf8');
console.log('Done! Original:', (origSize / 1024).toFixed(1), 'KB -> Encrypted:', (newSize / 1024).toFixed(1), 'KB');
