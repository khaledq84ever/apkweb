const express = require('express');
const multer = require('multer');
const unzipper = require('unzipper');
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: 'uploads/' });

function sessionDir(id) {
  return path.join(__dirname, 'workspace', id);
}

function cleanId(id) {
  return id.replace(/[^a-zA-Z0-9_-]/g, '');
}

// Fetch APK from URL
app.post('/upload-url', async (req, res) => {
  const { url } = req.body;
  if (!url || !/^https?:\/\/.+/i.test(url)) return res.status(400).json({ error: 'Invalid URL' });

  let fetchRes;
  try {
    fetchRes = await fetch(url, { redirect: 'follow' });
    if (!fetchRes.ok) return res.status(400).json({ error: `Download failed: HTTP ${fetchRes.status}` });
  } catch (e) {
    return res.status(400).json({ error: 'Could not reach URL: ' + e.message });
  }

  const id = Date.now().toString();
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

  const tmpPath = path.join(__dirname, 'uploads', id + '.apk');
  fs.mkdirSync(path.dirname(tmpPath), { recursive: true });

  try {
    const buf = Buffer.from(await fetchRes.arrayBuffer());
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

  const id = Date.now().toString();
  const dir = sessionDir(id);
  fs.mkdirSync(dir, { recursive: true });

  const apkPath = req.file.path;
  const originalName = req.file.originalname || 'app.apk';

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
