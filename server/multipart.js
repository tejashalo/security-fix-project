'use strict';
/** Minimal multipart/form-data parser for a buffered body. */
function parseMultipart(body, boundary) {
  const parts = [];
  const delim = Buffer.from(`--${boundary}`);
  let pos = body.indexOf(delim);
  if (pos === -1) return parts;
  while (true) {
    pos += delim.length;
    if (body[pos] === 0x2d && body[pos + 1] === 0x2d) break; // closing "--"
    if (body[pos] === 0x0d && body[pos + 1] === 0x0a) pos += 2;
    const headerEnd = body.indexOf('\r\n\r\n', pos);
    if (headerEnd === -1) break;
    const headers = body.slice(pos, headerEnd).toString('utf8');
    const next = body.indexOf(delim, headerEnd + 4);
    if (next === -1) break;
    let end = next;
    if (body[end - 2] === 0x0d && body[end - 1] === 0x0a) end -= 2;
    const disp = /content-disposition:\s*form-data;([^\r\n]*)/i.exec(headers);
    if (disp) {
      const name = (/\bname="([^"]*)"/i.exec(disp[1]) || [])[1];
      const filename = (/\bfilename="([^"]*)"/i.exec(disp[1]) || [])[1];
      if (name && parts.length < 10) parts.push({ name, filename, data: body.slice(headerEnd + 4, end) });
    }
    pos = next;
  }
  return parts;
}
module.exports = { parseMultipart };
