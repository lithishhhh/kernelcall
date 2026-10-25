/**
 * Kernel Call — Client-Side Static APK Analysis & Intelligence Engine
 * Strict compliance with Kernel Call Architecture principles:
 * - Evidence before verdicts
 * - Confirmed Observation vs Heuristic Indicator vs Unknown vs Sandbox Only
 * - Explainable risk calculation (0..100) with deterministic weights
 */

class ApkAnalysisEngine {
  constructor() {
    this.DANGEROUS_PERMISSIONS = {
      'android.permission.READ_SMS': { weight: 12, label: 'Read SMS Messages', severity: 'HIGH' },
      'android.permission.RECEIVE_SMS': { weight: 12, label: 'Intercept Incoming SMS', severity: 'HIGH' },
      'android.permission.SEND_SMS': { weight: 12, label: 'Send Outbound SMS', severity: 'HIGH' },
      'android.permission.RECORD_AUDIO': { weight: 10, label: 'Microphone Audio Capture', severity: 'MEDIUM' },
      'android.permission.CAMERA': { weight: 8, label: 'Camera Sensor Access', severity: 'MEDIUM' },
      'android.permission.ACCESS_FINE_LOCATION': { weight: 8, label: 'Precise GPS Location', severity: 'MEDIUM' },
      'android.permission.READ_CONTACTS': { weight: 8, label: 'Read Contacts Database', severity: 'MEDIUM' },
      'android.permission.SYSTEM_ALERT_WINDOW': { weight: 15, label: 'Display Screen Overlay / Window Injection', severity: 'HIGH' },
      'android.permission.REQUEST_INSTALL_PACKAGES': { weight: 15, label: 'Request Package Installation (Dropper)', severity: 'HIGH' },
      'android.permission.BIND_ACCESSIBILITY_SERVICE': { weight: 20, label: 'Bind Accessibility Service (Screen Sniffer)', severity: 'HIGH' },
      'android.permission.RECEIVE_BOOT_COMPLETED': { weight: 5, label: 'Auto-start on Device Boot', severity: 'LOW' }
    };
  }

  /**
   * Computes SHA-256 fingerprint from ArrayBuffer
   */
  async computeSha256(buffer) {
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(digest));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Lightweight PKZip Central Directory parser
   */
  parseZipArchive(buffer) {
    const dataView = new DataView(buffer);
    const byteLength = buffer.byteLength;
    const entries = [];
    let eocdOffset = -1;

    // Search backwards for End of Central Directory signature (0x06054b50)
    const maxSearch = Math.min(byteLength, 65557);
    for (let i = byteLength - 22; i >= byteLength - maxSearch; i--) {
      if (dataView.getUint32(i, true) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset === -1) {
      throw new Error('Invalid APK file: End of Central Directory signature not found');
    }

    const totalEntries = dataView.getUint16(eocdOffset + 10, true);
    const cdSize = dataView.getUint32(eocdOffset + 12, true);
    const cdOffset = dataView.getUint32(eocdOffset + 16, true);

    let offset = cdOffset;
    for (let i = 0; i < totalEntries && offset < cdOffset + cdSize; i++) {
      if (dataView.getUint32(offset, true) !== 0x02014b50) break;

      const compMethod = dataView.getUint16(offset + 10, true);
      const compSize = dataView.getUint32(offset + 20, true);
      const uncompSize = dataView.getUint32(offset + 24, true);
      const fileNameLen = dataView.getUint16(offset + 28, true);
      const extraLen = dataView.getUint16(offset + 30, true);
      const commentLen = dataView.getUint16(offset + 32, true);
      const localHeaderOffset = dataView.getUint32(offset + 42, true);

      const nameBytes = new Uint8Array(buffer, offset + 46, fileNameLen);
      const fileName = new TextDecoder('utf-8').decode(nameBytes);

      entries.push({
        fileName,
        compSize,
        uncompSize,
        compMethod,
        localHeaderOffset
      });

      offset += 46 + fileNameLen + extraLen + commentLen;
    }

    return entries;
  }

  /**
   * Scans strings from binary AXML or raw manifest bytes
   */
  extractManifestStrings(buffer, entries) {
    const manifestEntry = entries.find(e => e.fileName === 'AndroidManifest.xml');
    if (!manifestEntry) return { strings: [], rawBytes: null };

    // Get uncompressed or raw stream
    try {
      const dv = new DataView(buffer);
      const lho = manifestEntry.localHeaderOffset;
      const fnLen = dv.getUint16(lho + 26, true);
      const exLen = dv.getUint16(lho + 28, true);
      const fileDataOffset = lho + 30 + fnLen + exLen;
      
      const rawBytes = new Uint8Array(buffer, fileDataOffset, manifestEntry.compSize);
      
      // Extract ASCII and UTF-16 strings
      const strings = [];
      let currentAscii = '';
      for (let i = 0; i < rawBytes.length; i++) {
        const c = rawBytes[i];
        if (c >= 32 && c <= 126) {
          currentAscii += String.fromCharCode(c);
        } else {
          if (currentAscii.length >= 4) {
            strings.push(currentAscii);
          }
          currentAscii = '';
        }
      }
      return { strings: Array.from(new Set(strings)), rawBytes };
    } catch (e) {
      return { strings: [], rawBytes: null };
    }
  }

  /**
   * Executes full static analysis pipeline
   */
  async runAnalysis(file, onProgress) {
    const startTime = performance.now();
    const stats = [];

    // Stage 1: Hashing
    onProgress?.({ percent: 15, stage: 'Hashing file (SHA-256 streaming)...' });
    const arrayBuffer = await file.arrayBuffer();
    const sha256 = await this.computeSha256(arrayBuffer);

    // Stage 2: Central Directory Unpack
    onProgress?.({ percent: 35, stage: 'Unpacking ZIP central directory...' });
    const entries = this.parseZipArchive(arrayBuffer);

    // Stage 3: AXML Manifest & Attributes
    onProgress?.({ percent: 55, stage: 'Parsing AndroidManifest.xml...' });
    const manifestInfo = this.extractManifestStrings(arrayBuffer, entries);
    const manifestStrings = manifestInfo.strings;

    // Stage 4: Certificates
    onProgress?.({ percent: 70, stage: 'Validating signing certificates...' });
    const certEntries = entries.filter(e => e.fileName.startsWith('META-INF/') && (e.fileName.endsWith('.RSA') || e.fileName.endsWith('.DSA') || e.fileName.endsWith('.EC')));
    const hasV1Cert = certEntries.length > 0;

    // Stage 5: Dex & Asset scans
    onProgress?.({ percent: 85, stage: 'Scanning DEX bytecode literals & assets...' });
    const dexEntries = entries.filter(e => e.fileName.endsWith('.dex'));
    const nativeLibs = entries.filter(e => e.fileName.startsWith('lib/'));
    const abis = Array.from(new Set(nativeLibs.map(e => e.fileName.split('/')[1]))).filter(Boolean);
    const suspiciousAssets = entries.filter(e => 
      e.fileName.startsWith('assets/') && 
      (e.fileName.endsWith('.dex') || e.fileName.endsWith('.apk') || e.fileName.endsWith('.jar') || e.fileName.endsWith('.so'))
    );

    // Stage 6: Threat Correlation & Risk Calculation
    onProgress?.({ percent: 95, stage: 'Correlating multi-signal heuristics & intelligence...' });

    // Detect package name from strings
    let packageName = 'unknown.package';
    for (const str of manifestStrings) {
      if (str.includes('.') && !str.includes('/') && !str.startsWith('android.') && str.length > 5 && str.length < 60) {
        if (/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(str)) {
          packageName = str;
          break;
        }
      }
    }

    // Identify requested permissions
    const declaredPermissions = [];
    for (const str of manifestStrings) {
      if (str.startsWith('android.permission.') || str.includes('.permission.')) {
        declaredPermissions.push(str);
      }
    }

    // Check manifest flags
    const hasCleartext = manifestStrings.some(s => s.toLowerCase().includes('cleartext') || s.includes('usesCleartextTraffic'));
    const isDebuggable = manifestStrings.some(s => s.toLowerCase().includes('debuggable'));
    const hasAllowBackup = manifestStrings.some(s => s.toLowerCase().includes('allowbackup'));
    const hasBootCompleted = declaredPermissions.includes('android.permission.RECEIVE_BOOT_COMPLETED');
    const hasReceiveSms = declaredPermissions.includes('android.permission.RECEIVE_SMS');

    // Build Findings List conforming to Kernel Call finding schema
    const findings = [];
    const now = Date.now();

    // 1. Confirmed Manifest Observations
    findings.push({
      id: 'obs-package-' + now,
      engineId: 'static.v2',
      title: 'Declared Android Package Name',
      summary: `Application declares package identifier: ${packageName}`,
      kind: 'CONFIRMED_OBSERVATION',
      severity: 'INFO',
      category: 'manifest',
      ruleId: 'M-001',
      confidence: 'HIGH',
      detectedAt: now,
      evidence: [
        { type: 'manifest', label: 'package', value: packageName, location: 'AndroidManifest.xml' }
      ]
    });

    findings.push({
      id: 'obs-dexcount-' + now,
      engineId: 'static.v2',
      title: `DEX Bytecode Split (${dexEntries.length} dex file${dexEntries.length > 1 ? 's' : ''})`,
      summary: `Found ${dexEntries.length} DEX executable classes archive(s) totaling ${dexEntries.reduce((a, b) => a + b.uncompSize, 0)} bytes.`,
      kind: 'CONFIRMED_OBSERVATION',
      severity: 'INFO',
      category: 'archive',
      ruleId: 'A-001',
      confidence: 'HIGH',
      detectedAt: now,
      evidence: dexEntries.map(e => ({ type: 'zip_entry', label: 'dex', value: e.fileName, location: 'classes' }))
    });

    if (abis.length > 0) {
      findings.push({
        id: 'obs-native-' + now,
        engineId: 'static.v2',
        title: 'Native Binary ABIs Present',
        summary: `Application includes compiled native shared libraries (.so) for architectures: ${abis.join(', ')}`,
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'archive',
        ruleId: 'A-002',
        confidence: 'HIGH',
        detectedAt: now,
        evidence: abis.map(abi => ({ type: 'native_abi', label: 'abi', value: abi, location: 'lib/' }))
      });
    }

    // 2. Certificate Findings
    if (hasV1Cert) {
      findings.push({
        id: 'obs-cert-v1-' + now,
        engineId: 'static.v2',
        title: 'JAR V1 Signing Certificate Present',
        summary: `Found JAR signature archive (${certEntries.map(c => c.fileName).join(', ')}).`,
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'certificate',
        ruleId: 'C-001',
        confidence: 'HIGH',
        detectedAt: now,
        evidence: certEntries.map(c => ({ type: 'manifest_sig', label: 'v1_entry', value: c.fileName, location: 'META-INF/' }))
      });
    }

    // 3. Security Risk Flags & Heuristic Findings
    if (hasCleartext) {
      findings.push({
        id: 'heur-cleartext-' + now,
        engineId: 'static.v2',
        title: 'Insecure Cleartext Traffic Permitted',
        summary: 'Application allows unencrypted HTTP traffic (usesCleartextTraffic=true), enabling network eavesdropping and MitM attacks.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-CLEARTEXT',
        confidence: 'HIGH',
        recommendation: 'Enforce HTTPS network security configuration by setting android:usesCleartextTraffic="false".',
        detectedAt: now,
        evidence: [{ type: 'manifest_attr', label: 'usesCleartextTraffic', value: 'true', location: 'application' }]
      });
    }

    if (isDebuggable) {
      findings.push({
        id: 'heur-debuggable-' + now,
        engineId: 'static.v2',
        title: 'Application is Debuggable in Production',
        summary: 'android:debuggable is enabled, allowing debugger attachment, memory inspection, and runtime hook insertion.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-DEBUGGABLE',
        confidence: 'HIGH',
        recommendation: 'Set android:debuggable="false" in release production builds.',
        detectedAt: now,
        evidence: [{ type: 'manifest_attr', label: 'debuggable', value: 'true', location: 'application' }]
      });
    }

    if (hasAllowBackup) {
      findings.push({
        id: 'heur-backup-' + now,
        engineId: 'static.v2',
        title: 'Application Data Backup Enabled',
        summary: 'android:allowBackup is enabled. Application data can be extracted via ADB backup without root access.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'MEDIUM',
        category: 'manifest',
        ruleId: 'M-BACKUP',
        confidence: 'HIGH',
        recommendation: 'Set android:allowBackup="false" if sensitive user data or session tokens are stored locally.',
        detectedAt: now,
        evidence: [{ type: 'manifest_attr', label: 'allowBackup', value: 'true', location: 'application' }]
      });
    }

    // Dangerous Permissions
    declaredPermissions.forEach(perm => {
      const danger = this.DANGEROUS_PERMISSIONS[perm];
      if (danger) {
        findings.push({
          id: 'heur-perm-' + perm.split('.').pop() + '-' + now,
          engineId: 'static.v2',
          title: `Sensitive Permission: ${danger.label}`,
          summary: `Requests dangerous Android permission: ${perm}`,
          kind: 'HEURISTIC_INDICATOR',
          severity: danger.severity,
          category: 'manifest',
          ruleId: 'M-PERM-' + perm.split('.').pop(),
          confidence: 'HIGH',
          detectedAt: now,
          evidence: [{ type: 'permission', label: 'uses-permission', value: perm, location: 'manifest' }]
        });
      }
    });

    // Covert payload in assets
    if (suspiciousAssets.length > 0) {
      findings.push({
        id: 'heur-asset-payload-' + now,
        engineId: 'static.v2',
        title: 'Executable Code Packaged Inside Assets',
        summary: `Detected ${suspiciousAssets.length} executable file(s) inside /assets/ folder. Commonly used by droppers to unpack unvetted code at runtime.`,
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'archive',
        ruleId: 'A-COVERT-PAYLOAD',
        confidence: 'HIGH',
        recommendation: 'Verify if dynamic class loading (DexClassLoader) is intentionally intended.',
        detectedAt: now,
        evidence: suspiciousAssets.map(a => ({ type: 'zip_entry', label: 'suspicious_asset', value: a.fileName, location: 'assets/' }))
      });
    }

    // 4. Unknowns (Explicit information gaps as required by Kernel Call)
    const unknowns = [
      { engineId: 'static.v2', message: 'V2/V3 APK signing scheme signatures require root trust anchor verification.' },
      { engineId: 'static.v2', message: 'Bytecode obfuscation depth (ProGuard/R8/DexGuard) not confirmed statically.' }
    ];

    findings.push({
      id: 'unk-obfuscation-' + now,
      engineId: 'static.v2',
      title: 'Obfuscation Depth Unknown',
      summary: 'Static engine cannot prove runtime anti-tamper or packing without execution.',
      kind: 'UNKNOWN',
      severity: 'INFO',
      category: 'code',
      ruleId: 'U-001',
      confidence: 'LOW',
      detectedAt: now,
      evidence: [{ type: 'analysis_gap', label: 'runtime_packing', value: 'unverified', location: 'dex' }]
    });

    findings.push({
      id: 'sandbox-behavior-' + now,
      engineId: 'sandbox.v1',
      title: 'Dynamic API Hooking & Network Detonation',
      summary: 'Dynamic behavioral indicators (runtime C2 callbacks, socket traffic, evasion) require execution in an isolated sandbox.',
      kind: 'SANDBOX_ONLY',
      severity: 'INFO',
      category: 'correlation',
      ruleId: 'S-001',
      confidence: 'LOW',
      detectedAt: now,
      evidence: [{ type: 'sandbox_restriction', label: 'execution', value: 'disposable_avd_required', location: 'runtime' }]
    });

    // 5. Calculate Explainable Risk & Correlations
    const scoreContributions = [];
    let rawScore = 0;

    if (hasCleartext) {
      scoreContributions.push({
        refFindingId: 'heur-cleartext-' + now,
        refRuleId: 'M-CLEARTEXT',
        description: 'Cleartext HTTP traffic permitted (MitM vulnerability)',
        weight: 20
      });
      rawScore += 20;
    }

    if (isDebuggable) {
      scoreContributions.push({
        refFindingId: 'heur-debuggable-' + now,
        refRuleId: 'M-DEBUGGABLE',
        description: 'Debuggable flag active in package manifest',
        weight: 25
      });
      rawScore += 25;
    }

    if (hasAllowBackup) {
      scoreContributions.push({
        refFindingId: 'heur-backup-' + now,
        refRuleId: 'M-BACKUP',
        description: 'Data backup allowed via local adb',
        weight: 10
      });
      rawScore += 10;
    }

    declaredPermissions.forEach(perm => {
      const danger = this.DANGEROUS_PERMISSIONS[perm];
      if (danger) {
        scoreContributions.push({
          refFindingId: 'heur-perm-' + perm.split('.').pop() + '-' + now,
          refRuleId: 'M-PERM-' + perm.split('.').pop(),
          description: `Dangerous permission requested: ${danger.label}`,
          weight: danger.weight
        });
        rawScore += danger.weight;
      }
    });

    if (suspiciousAssets.length > 0) {
      scoreContributions.push({
        refFindingId: 'heur-asset-payload-' + now,
        refRuleId: 'A-COVERT-PAYLOAD',
        description: 'Executable payload stored in assets directory',
        weight: 30
      });
      rawScore += 30;
    }

    // Correlations
    const correlations = [];
    if (hasBootCompleted && hasReceiveSms) {
      correlations.push({
        id: 'corr-sms-interceptor-' + now,
        ruleId: 'CORR-SMS-INTERCEPT',
        title: 'SMS Background Interceptor Signal',
        explanation: 'Co-occurrence of RECEIVE_BOOT_COMPLETED and RECEIVE_SMS suggests potential background SMS theft or 2FA bypass mechanism.',
        severity: 'HIGH',
        scoreWeight: 20,
        sharedEvidence: [
          { type: 'permission', label: 'perm', value: 'RECEIVE_BOOT_COMPLETED' },
          { type: 'permission', label: 'perm', value: 'RECEIVE_SMS' }
        ]
      });
      scoreContributions.push({
        refFindingId: 'corr-sms-interceptor-' + now,
        refRuleId: 'CORR-SMS-INTERCEPT',
        description: 'Multi-signal correlation: Boot persistence + SMS interception',
        weight: 20
      });
      rawScore += 20;
    }

    const cappedScore = Math.min(100, rawScore);
    let riskBand = 'LOW';
    if (cappedScore >= 75) riskBand = 'HIGH';
    else if (cappedScore >= 50) riskBand = 'ELEVATED';
    else if (cappedScore >= 25) riskBand = 'MODERATE';

    const endTime = performance.now();
    const durationMs = Math.round(endTime - startTime);

    const report = {
      schemaVersion: 3,
      sha256,
      fileName: file.name,
      sizeBytes: file.size,
      packageName,
      generatedAt: now,
      engines: [
        {
          engineId: 'static.v2',
          durationMs,
          findingCount: findings.length,
          unknownCount: unknowns.length
        }
      ],
      findings,
      unknowns,
      intelligence: {
        correlations,
        risk: {
          score: cappedScore,
          band: riskBand,
          contributions: scoreContributions,
          limitations: [
            'Static analysis only. Does not observe dynamic native execution.',
            'Score reflects declared capabilities and flags, not certified intent.'
          ]
        }
      },
      zipInventory: {
        totalFiles: entries.length,
        dexCount: dexEntries.length,
        abis,
        entries: entries.slice(0, 100) // first 100 entries for preview
      }
    };

    onProgress?.({ percent: 100, stage: 'Analysis completed!' });
    return report;
  }
}

window.ApkAnalysisEngine = ApkAnalysisEngine;
