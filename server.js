const express = require('express');
const multer = require('multer');
const unzipper = require('unzipper');
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/', limits: { fileSize: 200 * 1024 * 1024 } });

function sessionDir(id) {
  return path.join(__dirname, 'workspace', id);
}

function cleanId(id) {
  return id.replace(/[^a-zA-Z0-9_-]/g, '');
}

function newSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// Blocks loopback/private/link-local ranges so /upload-url can't be used to
// reach internal services (SSRF) via a supplied URL or its redirect chain.
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168);
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('::ffff:')) {
      const v4 = lower.slice(7);
      if (net.isIPv4(v4)) return isPrivateAddress(v4);
    }
    return false;
  }
  return true; // unknown family - block
}

const MAX_REDIRECTS = 5;
const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024;

async function safeFetch(startUrl) {
  let current = startUrl;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const u = new URL(current);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Blocked protocol');
    const { address } = await dns.lookup(u.hostname);
    if (isPrivateAddress(address)) throw new Error('Refusing to fetch a private/internal address');

    const res = await fetch(current, { redirect: 'manual' });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error('Redirect with no Location header');
      current = new URL(loc, current).toString();
      continue;
    }
    const len = res.headers.get('content-length');
    if (len && Number(len) > MAX_DOWNLOAD_BYTES) throw new Error('File too large');
    return res;
  }
  throw new Error('Too many redirects');
}

// Fetch APK from URL
app.post('/upload-url', async (req, res) => {
  const { url } = req.body;
  if (!url || !/^https?:\/\/.+/i.test(url)) return res.status(400).json({ error: 'Invalid URL' });

  let fetchRes;
  try {
    fetchRes = await safeFetch(url);
    if (!fetchRes.ok) return res.status(400).json({ error: `Download failed: HTTP ${fetchRes.status}` });
  } catch (e) {
    return res.status(400).json({ error: 'Could not reach URL: ' + e.message });
  }

  const id = newSessionId();
  const dir = sessionDir(id);
  fs.mkdirSync(dir, { recursive: true });

  const contentDisposition = fetchRes.headers.get('content-disposition') || '';
  let originalName = 'app.apk';
  const cdMatch = contentDisposition.match(/filename\*?=(?:UTF-8''|"?)([^";\r\n]+)/i);
  if (cdMatch) originalName = decodeURIComponent(cdMatch[1].replace(/"/g, ''));
  else {
    const urlName = new URL(url).pathname.split('/').pop();
    if (urlName && urlName.endsWith('.apk')) originalName = urlName;
  }
  // sanitize: strips path separators and header-breaking chars before it's ever
  // written into a Content-Disposition header on /download
  originalName = originalName.replace(/[\\/"\r\n]/g, '_').slice(0, 200) || 'app.apk';

  const tmpPath = path.join(__dirname, 'uploads', id + '.apk');
  fs.mkdirSync(path.dirname(tmpPath), { recursive: true });

  try {
    const buf = Buffer.from(await fetchRes.arrayBuffer());
    if (buf.length > MAX_DOWNLOAD_BYTES) throw new Error('File too large');
    fs.writeFileSync(tmpPath, buf);
  } catch (e) {
    return res.status(500).json({ error: 'Failed to save APK: ' + e.message });
  }

  try {
    await fs.createReadStream(tmpPath)
      .pipe(unzipper.Extract({ path: dir }))
      .promise();
  } catch (e) {
    fs.unlinkSync(tmpPath);
    return res.status(500).json({ error: 'Failed to extract APK: ' + e.message });
  }

  fs.writeFileSync(path.join(dir, '.apkname'), originalName);

  let info = { name: originalName, version: '', package: '' };
  try {
    const out = execSync(`aapt dump badging "${tmpPath}" 2>/dev/null`).toString();
    const pkgMatch = out.match(/package: name='([^']+)'/);
    const verMatch = out.match(/versionName='([^']+)'/);
    const labelMatch = out.match(/application-label:'([^']+)'/);
    if (pkgMatch) info.package = pkgMatch[1];
    if (verMatch) info.version = verMatch[1];
    if (labelMatch) info.name = labelMatch[1];
  } catch (_) {}

  fs.unlinkSync(tmpPath);
  res.json({ id, info });
});

// Upload APK
app.post('/upload', upload.single('apk'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const id = newSessionId();
  const dir = sessionDir(id);
  fs.mkdirSync(dir, { recursive: true });

  const apkPath = req.file.path;
  const originalName = (req.file.originalname || 'app.apk').replace(/[\\/"\r\n]/g, '_').slice(0, 200) || 'app.apk';

  // Extract APK (it's a ZIP)
  try {
    await fs.createReadStream(apkPath)
      .pipe(unzipper.Extract({ path: dir }))
      .promise();
  } catch (e) {
    return res.status(500).json({ error: 'Failed to extract APK: ' + e.message });
  }

  // Save original name
  fs.writeFileSync(path.join(dir, '.apkname'), originalName);

  // Get APK info with aapt
  let info = { name: originalName, version: '', package: '' };
  try {
    const out = execSync(`aapt dump badging "${apkPath}" 2>/dev/null`).toString();
    const pkgMatch = out.match(/package: name='([^']+)'/);
    const verMatch = out.match(/versionName='([^']+)'/);
    const labelMatch = out.match(/application-label:'([^']+)'/);
    if (pkgMatch) info.package = pkgMatch[1];
    if (verMatch) info.version = verMatch[1];
    if (labelMatch) info.name = labelMatch[1];
  } catch (_) {}

  fs.unlinkSync(apkPath);

  res.json({ id, info });
});

// List files in session
app.get('/files/:id', (req, res) => {
  const id = cleanId(req.params.id);
  const dir = sessionDir(id);
  if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Session not found' });

  function walk(d, base) {
    const entries = fs.readdirSync(d, { withFileTypes: true });
    const result = [];
    for (const e of entries) {
      if (e.name.startsWith('.')) continue;
      const rel = base ? base + '/' + e.name : e.name;
      if (e.isDirectory()) {
        result.push({ name: rel, type: 'dir', children: walk(path.join(d, e.name), rel) });
      } else {
        const size = fs.statSync(path.join(d, e.name)).size;
        result.push({ name: rel, type: 'file', size });
      }
    }
    return result;
  }

  res.json(walk(dir, ''));
});

// Read file
app.get('/file/:id', (req, res) => {
  const id = cleanId(req.params.id);
  const filePath = req.query.path || '';
  const dir = sessionDir(id);
  const full = path.resolve(dir, filePath);

  if (full !== dir && !full.startsWith(dir + path.sep)) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'File not found' });

  const stat = fs.statSync(full);
  if (stat.size > 512 * 1024) return res.json({ content: null, binary: true });

  const buf = fs.readFileSync(full);
  const isText = !buf.slice(0, 512).some(b => b === 0);
  if (!isText) return res.json({ content: null, binary: true });

  res.json({ content: buf.toString('utf8'), binary: false });
});

// Save file
app.post('/file/:id', (req, res) => {
  const id = cleanId(req.params.id);
  const filePath = req.body.path || '';
  const content = req.body.content || '';
  const dir = sessionDir(id);
  const full = path.resolve(dir, filePath);

  if (full !== dir && !full.startsWith(dir + path.sep)) return res.status(403).json({ error: 'Access denied' });
  if (!fs.existsSync(path.dirname(full))) return res.status(404).json({ error: 'Directory not found' });

  fs.writeFileSync(full, content, 'utf8');
  res.json({ ok: true });
});

// Download APK (repackage)
app.get('/download/:id', (req, res) => {
  const id = cleanId(req.params.id);
  const dir = sessionDir(id);
  if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Session not found' });

  const apkName = fs.existsSync(path.join(dir, '.apkname'))
    ? fs.readFileSync(path.join(dir, '.apkname'), 'utf8').trim()
    : 'app.apk';

  res.setHeader('Content-Disposition', `attachment; filename="${apkName}"`);
  res.setHeader('Content-Type', 'application/vnd.android.package-archive');

  const archive = archiver('zip', { zlib: { level: 0 } });
  archive.on('error', err => res.status(500).end(err.message));
  archive.pipe(res);

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name.startsWith('.')) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      archive.directory(full, e.name);
    } else {
      archive.file(full, { name: e.name });
    }
  }

  archive.finalize();
});

// Delete session
app.delete('/session/:id', (req, res) => {
  const id = cleanId(req.params.id);
  const dir = sessionDir(id);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`APK Web running on port ${PORT}`));
