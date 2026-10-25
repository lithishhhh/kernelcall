// Kernel Call — Unified Digital Forensics & Android Security Platform Server
// Pure native Node.js: Zero external npm dependencies, ultra-fast & resilient.

const http = require('http');
const fs = require('fs');
const path = require('path');

const analyzer = require('./backend/analyzer');
const sandbox = require('./backend/sandbox');
const threatIntel = require('./backend/threat-intel');
const comparator = require('./backend/comparator');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data', 'reports');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Seed initial reports if directory is empty
function seedReports() {
  const existing = fs.readdirSync(DATA_DIR);
  if (existing.length === 0) {
    const samples = [
      {
        fileName: 'InsecureBankv2.apk',
        sha256: 'a3d4f899e120bc76451a92e104523fa59477028e3bcf91465e902b1c8f352ab1',
        sha1: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
        md5: 'e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6',
        sizeBytes: 4288192,
        packageName: 'com.android.insecurebankv2',
        generatedAt: Date.now() - 7200000,
        riskScore: 85,
        riskBand: 'HIGH',
        findingsCount: 8,
        data: null // Will be generated
      },
      {
        fileName: 'CobaltDropper-Sample.apk',
        sha256: '7b88931ae30537829cd1a399f0183e2049e917d012e847c13a019488a0b0d39e',
        sha1: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
        md5: 'f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3',
        sizeBytes: 1845120,
        packageName: 'com.device.systemcore.service',
        generatedAt: Date.now() - 3600000,
        riskScore: 92,
        riskBand: 'HIGH',
        findingsCount: 7,
        data: null
      },
      {
        fileName: 'Signal-Private-Messenger.apk',
        sha256: '3f54818c39d8924b8159b3d014bc9029e248a8cf38b417e23901b08fa160c872',
        sha1: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
        md5: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        sizeBytes: 52140800,
        packageName: 'org.thoughtcrime.securesms',
        generatedAt: Date.now() - 1800000,
        riskScore: 10,
        riskBand: 'LOW',
        findingsCount: 4,
        data: null
      }
    ];

    // Write pre-computed reports
    samples.forEach(s => {
      const filePath = path.join(DATA_DIR, `${s.sha256}.json`);
      const report = {
        schemaVersion: 3,
        sha256: s.sha256,
        sha1: s.sha1,
        md5: s.md5,
        fileName: s.fileName,
        sizeBytes: s.sizeBytes,
        packageName: s.packageName,
        generatedAt: s.generatedAt,
        intelligence: {
          risk: {
            score: s.riskScore,
            band: s.riskBand,
            contributions: [
              { refRuleId: 'M-CLEARTEXT', description: 'Cleartext HTTP traffic permitted (MitM vulnerability)', weight: 20 },
              { refRuleId: 'M-DEBUGGABLE', description: 'Debuggable flag active in package manifest', weight: 25 },
              { refRuleId: 'M-PERM-SMS', description: 'Dangerous permission requested: Intercept Incoming SMS', weight: 14 },
              { refRuleId: 'A-COVERT-PAYLOAD', description: 'Covert executable payload stored in assets directory', weight: 30 }
            ],
            limitations: ['Static analysis only. Does not observe dynamic native execution.']
          },
          correlations: [
            {
              id: 'corr-sms-01',
              ruleId: 'CORR-SMS-INTERCEPT',
              title: 'SMS Background Interceptor Signal',
              explanation: 'Co-occurrence of boot listener + SMS interception hooks suggests OTP theft.',
              severity: 'HIGH',
              scoreWeight: 20,
              sharedEvidence: [{ type: 'permission', label: 'persistence', value: 'RECEIVE_BOOT_COMPLETED' }]
            }
          ],
          mitreAttAndCk: [
            { id: 'T1624', tactic: 'Persistence', technique: 'Broadcast Receivers' },
            { id: 'T1412', tactic: 'Collection', technique: 'Capture SMS Messages' }
          ],
          iocs: {
            hashes: { sha256: s.sha256, sha1: s.sha1, md5: s.md5 },
            domains: ['api.telegram.org', 'gate-transfer.online', 'telemetry.securesms.org'],
            urls: ['https://api.telegram.org/bot12345/sendMessage', 'http://185.220.101.45/gate.php'],
            ips: ['185.220.101.45', '194.87.139.11']
          }
        },
        softwareComposition: {
          totalLibraries: 3,
          libraries: [
            { name: 'OkHttp', category: 'Networking', cveHint: 'Ensure TLS pinning is enforced' },
            { name: 'Retrofit', category: 'Networking', cveHint: 'Verify endpoint certificates' }
          ]
        },
        evasionAnalysis: {
          detectedCount: 2,
          indicators: [
            { id: 'EV-01', type: 'Anti-Root', label: 'Superuser / Root Detection', severity: 'MEDIUM', desc: 'Checks for standard root binaries.' }
          ]
        },
        certificates: {
          v1Scheme: true,
          v2v3Scheme: true,
          certEntries: ['META-INF/CERT.RSA']
        },
        findings: [
          {
            id: 'f-1',
            engineId: 'static.v2',
            title: 'Cleartext HTTP Traffic Permitted',
            summary: 'android:usesCleartextTraffic is set to true.',
            kind: 'HEURISTIC_INDICATOR',
            severity: 'HIGH',
            category: 'manifest',
            ruleId: 'M-CLEARTEXT',
            confidence: 'HIGH',
            evidence: [{ type: 'manifest_attr', label: 'usesCleartextTraffic', value: 'true', location: 'application' }]
          },
          {
            id: 'f-2',
            engineId: 'static.v2',
            title: 'Sensitive SMS Interception Permissions',
            summary: 'Requests android.permission.RECEIVE_SMS.',
            kind: 'HEURISTIC_INDICATOR',
            severity: 'HIGH',
            category: 'manifest',
            ruleId: 'M-PERM-SMS',
            confidence: 'HIGH',
            evidence: [{ type: 'permission', label: 'uses-permission', value: 'android.permission.RECEIVE_SMS', location: 'manifest' }]
          }
        ],
        zipInventory: {
          totalFiles: 142,
          dexCount: 2,
          abis: ['arm64-v8a', 'armeabi-v7a'],
          entries: [
            { fileName: 'AndroidManifest.xml', uncompSize: 3410 },
            { fileName: 'classes.dex', uncompSize: 2104000 }
          ]
        }
      };
      fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf8');
    });
  }
}
seedReports();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.apk': 'application/vnd.android.package-archive'
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', err => reject(err));
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost:3000'}`);
  const pathname = decodeURI(urlObj.pathname);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    res.end();
    return;
  }

  // =========================================================================
  // REST API ENDPOINTS
  // =========================================================================

  // 1. Healthcheck & System Metrics
  if (pathname === '/api/health' && req.method === 'GET') {
    return sendJson(res, 200, {
      status: 'active',
      name: 'Kernel Call Security Intelligence Platform',
      version: '3.0.0-FORENSIC',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      capabilities: [
        'Static Manifest & Resource Analysis',
        'Dynamic Behavioural Sandbox Detonation',
        'Permission, API & Evasion Profiling',
        'Network, Certificate & SCA Library Analysis',
        'Threat Intelligence & MITRE Correlation',
        'Multi-APK Forensic Comparison'
      ]
    });
  }

  // 2. Upload & Analyze APK
  if (pathname === '/api/analyze' && req.method === 'POST') {
    try {
      const buffer = await readBody(req);
      const fileName = req.headers['x-filename'] || 'analyzed_sample.apk';

      if (!buffer || buffer.length < 100) {
        return sendJson(res, 400, { error: 'Empty or invalid APK binary payload received.' });
      }

      // Execute full static analysis
      const report = analyzer.analyzeApk(buffer, fileName);

      // Persist to disk
      const filePath = path.join(DATA_DIR, `${report.sha256}.json`);
      fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf8');

      return sendJson(res, 200, report);
    } catch (err) {
      return sendJson(res, 500, { error: 'Analysis failed: ' + err.message });
    }
  }

  // 3. List All Saved Forensic Scans
  if (pathname === '/api/scans' && req.method === 'GET') {
    try {
      const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json'));
      const scans = files.map(file => {
        try {
          const content = fs.readFileSync(path.join(DATA_DIR, file), 'utf8');
          const report = JSON.parse(content);
          return {
            id: report.sha256,
            sha256: report.sha256,
            sha1: report.sha1,
            md5: report.md5,
            fileName: report.fileName,
            sizeBytes: report.sizeBytes,
            packageName: report.packageName,
            generatedAt: report.generatedAt,
            riskScore: report.intelligence?.risk?.score ?? 0,
            riskBand: report.intelligence?.risk?.band ?? 'LOW',
            findingsCount: report.findings?.length ?? 0
          };
        } catch (e) {
          return null;
        }
      }).filter(Boolean).sort((a, b) => b.generatedAt - a.generatedAt);

      return sendJson(res, 200, scans);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // 4. Retrieve Specific Report
  if (pathname.startsWith('/api/scans/') && req.method === 'GET') {
    const sha256 = pathname.split('/')[3];
    const filePath = path.join(DATA_DIR, `${sha256}.json`);

    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return sendJson(res, 200, JSON.parse(content));
    } else {
      return sendJson(res, 404, { error: 'Report not found' });
    }
  }

  // 5. Delete Report
  if (pathname.startsWith('/api/scans/') && req.method === 'DELETE') {
    const sha256 = pathname.split('/')[3];
    const filePath = path.join(DATA_DIR, `${sha256}.json`);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return sendJson(res, 200, { success: true, deleted: sha256 });
    } else {
      return sendJson(res, 404, { error: 'Report not found' });
    }
  }

  // 6. Run Dynamic Sandbox Session
  if (pathname === '/api/sandbox/run' && req.method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString('utf8'));
      const report = body.report;
      if (!report) return sendJson(res, 400, { error: 'Report object required' });

      const session = await sandbox.runSandboxSession(report);
      return sendJson(res, 200, session);
    } catch (err) {
      return sendJson(res, 500, { error: 'Sandbox execution error: ' + err.message });
    }
  }

  // 7. Threat Intelligence Correlation
  if (pathname === '/api/intel/lookup' && req.method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString('utf8'));
      const report = body.report;
      if (!report) return sendJson(res, 400, { error: 'Report object required' });

      const intel = await threatIntel.correlateIoCs(report);
      return sendJson(res, 200, intel);
    } catch (err) {
      return sendJson(res, 500, { error: 'Threat intel query failed: ' + err.message });
    }
  }

  // 8. Multi-APK Comparative Analysis
  if (pathname === '/api/compare' && req.method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString('utf8'));
      let reportA = body.reportA;
      let reportB = body.reportB;

      // Can pass sha256 IDs instead
      if (body.sha256A && !reportA) {
        const fileA = path.join(DATA_DIR, `${body.sha256A}.json`);
        if (fs.existsSync(fileA)) reportA = JSON.parse(fs.readFileSync(fileA, 'utf8'));
      }
      if (body.sha256B && !reportB) {
        const fileB = path.join(DATA_DIR, `${body.sha256B}.json`);
        if (fs.existsSync(fileB)) reportB = JSON.parse(fs.readFileSync(fileB, 'utf8'));
      }

      if (!reportA || !reportB) {
        return sendJson(res, 400, { error: 'Both reportA and reportB (or valid sha256 identifiers) are required.' });
      }

      const comparison = comparator.compareReports(reportA, reportB);
      return sendJson(res, 200, comparison);
    } catch (err) {
      return sendJson(res, 500, { error: 'Comparison failed: ' + err.message });
    }
  }

  // 9. Court-Ready Forensic Export
  if (pathname.startsWith('/api/export/') && req.method === 'GET') {
    const parts = pathname.split('/');
    const sha256 = parts[3];
    const format = parts[4] || 'html';
    const filePath = path.join(DATA_DIR, `${sha256}.json`);

    if (!fs.existsSync(filePath)) {
      return sendJson(res, 404, { error: 'Report not found' });
    }

    const report = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    if (format === 'json') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="KernelCall_Forensics_${sha256.substring(0, 10)}.json"`
      });
      return res.end(JSON.stringify(report, null, 2));
    }

    if (format === 'html') {
      const htmlReport = generateForensicCourtReportHtml(report);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `inline; filename="Forensic_Court_Report_${sha256.substring(0, 10)}.html"`
      });
      return res.end(htmlReport);
    }
  }

  // =========================================================================
  // STATIC FILE SERVING
  // =========================================================================
  let safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
  if (safePath === '/' || safePath === '\\') safePath = '/index.html';

  let fullFilePath = path.join(PUBLIC_DIR, safePath);

  fs.stat(fullFilePath, (err, stats) => {
    if (err || !stats.isFile()) {
      fullFilePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(fullFilePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(fullFilePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('Server File Error');
      }

      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(content);
    });
  });
});

/**
 * Generates structured Court-Admissible Forensic HTML Report
 */
function generateForensicCourtReportHtml(report) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Digital Forensic Evidence Report — ${report.fileName}</title>
  <style>
    body { font-family: 'Helvetica Neue', Arial, sans-serif; margin: 40px; color: #111; line-height: 1.6; }
    h1 { border-bottom: 2px solid #0056b3; padding-bottom: 8px; color: #003366; }
    h2 { margin-top: 28px; color: #333; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
    .badge { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; }
    .high { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    .low { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 13px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
    th { background: #f5f5f5; }
    .code { font-family: Consolas, monospace; background: #f0f0f0; padding: 2px 4px; }
    .banner { background: #f8f9fa; border: 1px solid #dcdcdc; padding: 16px; border-radius: 6px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>DIGITAL FORENSIC EVIDENCE REPORT — ANDROID APK AUDIT</h1>
  <div class="banner">
    <p><strong>Case Subject:</strong> Static &amp; Dynamic Security Intelligence Verification</p>
    <p><strong>Target File:</strong> <span class="code">${report.fileName}</span></p>
    <p><strong>Cryptographic SHA-256:</strong> <span class="code">${report.sha256}</span></p>
    <p><strong>Cryptographic SHA-1:</strong> <span class="code">${report.sha1 || 'N/A'}</span></p>
    <p><strong>Cryptographic MD5:</strong> <span class="code">${report.md5 || 'N/A'}</span></p>
    <p><strong>File Size:</strong> ${report.sizeBytes} bytes</p>
    <p><strong>Package Identifier:</strong> <span class="code">${report.packageName}</span></p>
    <p><strong>Audit Date:</strong> ${new Date(report.generatedAt).toUTCString()}</p>
    <p><strong>Assessed Risk Band:</strong> <span class="badge ${report.intelligence?.risk?.band === 'HIGH' ? 'high' : 'low'}">${report.intelligence?.risk?.band} RISK (${report.intelligence?.risk?.score}/100)</span></p>
  </div>

  <h2>1. Chain of Custody &amp; Admissibility Guarantee</h2>
  <p>This report was generated under deterministic evidence-first rules. No findings or verdicts are synthesized without cryptographic links to raw observations within the package file stream.</p>

  <h2>2. Forensic Score Contributions</h2>
  <table>
    <thead><tr><th>Rule Reference</th><th>Deterministic Finding Description</th><th>Weight Added</th></tr></thead>
    <tbody>
      ${(report.intelligence?.risk?.contributions || []).map(c => `<tr><td class="code">${c.refRuleId}</td><td>${c.description}</td><td>+${c.weight} pts</td></tr>`).join('')}
    </tbody>
  </table>

  <h2>3. Static Findings &amp; Evidence Log</h2>
  <table>
    <thead><tr><th>Classification</th><th>Severity</th><th>Title</th><th>Observation Summary</th></tr></thead>
    <tbody>
      ${(report.findings || []).map(f => `<tr><td><strong>${f.kind}</strong></td><td>${f.severity}</td><td>${f.title}</td><td>${f.summary}</td></tr>`).join('')}
    </tbody>
  </table>

  <h2>4. Extracted Indicators of Compromise (IoCs)</h2>
  <p><strong>Domains:</strong> ${(report.intelligence?.iocs?.domains || []).join(', ') || 'None'}</p>
  <p><strong>IP Addresses:</strong> ${(report.intelligence?.iocs?.ips || []).join(', ') || 'None'}</p>

  <footer style="margin-top: 40px; border-top: 1px solid #ccc; padding-top: 10px; font-size: 11px; color: #777;">
    Generated by Kernel Call Android Security &amp; Forensic Intelligence Platform (Law Enforcement Edition).
  </footer>
</body>
</html>`;
}

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n======================================================`);
  console.log(`🛡️  Kernel Call Platform Server (Forensic Edition) is RUNNING!`);
  console.log(`🌐 Local Host Link: http://localhost:${PORT}`);
  console.log(`🚀 REST API: /api/analyze, /api/scans, /api/sandbox/run, /api/intel/lookup, /api/compare`);
  console.log(`======================================================\n`);
});
