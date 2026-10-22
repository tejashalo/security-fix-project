'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

function tmp(prefix = 'vg-test-') { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

function project(files) {
  const root = tmp();
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

const read = (root, rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const j = (...p) => p.join(''); // build fake secrets at runtime

module.exports = { tmp, project, read, j };
