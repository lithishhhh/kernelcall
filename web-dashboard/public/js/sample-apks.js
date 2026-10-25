/**
 * Kernel Call — Built-in Preset Sample APK Profiles
 * Pre-analyzed verified security reports for instant 1-click evaluation
 */

window.SAMPLE_APKS = {
  'insecurebank': {
    name: 'InsecureBankv2.apk',
    sizeBytes: 4288192,
    sha256: 'a3d4f899e120bc76451a92e104523fa59477028e3bcf91465e902b1c8f352ab1',
    packageName: 'com.android.insecurebankv2',
    minSdk: 21,
    targetSdk: 30,
    versionCode: 2,
    versionName: '2.0.0',
    riskScore: 85,
    riskBand: 'HIGH',
    correlations: [
      {
        id: 'corr-sms-01',
        ruleId: 'CORR-SMS-INTERCEPT',
        title: 'SMS Background Interceptor Signal',
        explanation: 'Co-occurrence of RECEIVE_BOOT_COMPLETED, RECEIVE_SMS, and exported broadcast receiver indicates automated SMS interception potential.',
        severity: 'HIGH',
        scoreWeight: 20,
        sharedEvidence: [
          { type: 'manifest', label: 'permission', value: 'android.permission.RECEIVE_BOOT_COMPLETED' },
          { type: 'manifest', label: 'permission', value: 'android.permission.RECEIVE_SMS' },
          { type: 'manifest', label: 'receiver', value: 'com.android.insecurebankv2.MyBroadcastReceiver (exported=true)' }
        ]
      }
    ],
    scoreContributions: [
      { refRuleId: 'M-CLEARTEXT', description: 'Cleartext HTTP traffic permitted (usesCleartextTraffic=true)', weight: 20 },
      { refRuleId: 'M-DEBUGGABLE', description: 'Debuggable flag active in production package', weight: 25 },
      { refRuleId: 'M-PERM-SMS', description: 'Dangerous permission: Intercept Incoming SMS', weight: 12 },
      { refRuleId: 'M-PERM-READ_SMS', description: 'Dangerous permission: Read Stored SMS Messages', weight: 12 },
      { refRuleId: 'M-BACKUP', description: 'Data backup allowed via local adb', weight: 10 },
      { refRuleId: 'CORR-SMS-INTERCEPT', description: 'Multi-signal correlation: Boot persistence + SMS interception', weight: 20 }
    ],
    findings: [
      {
        id: 'f-cleartext',
        engineId: 'static.v2',
        title: 'Insecure Cleartext HTTP Traffic Enabled',
        summary: 'Application allows unencrypted HTTP communications across all domains via android:usesCleartextTraffic="true".',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-CLEARTEXT',
        confidence: 'HIGH',
        recommendation: 'Enforce HTTPS network security config by disabling cleartext traffic.',
        evidence: [{ type: 'manifest_attr', label: 'usesCleartextTraffic', value: 'true', location: 'application' }]
      },
      {
        id: 'f-debuggable',
        engineId: 'static.v2',
        title: 'Application is Explicitly Debuggable',
        summary: 'The android:debuggable attribute is set to true in production. An attacker with adb access can attach JDWP debuggers to dump memory.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-DEBUGGABLE',
        confidence: 'HIGH',
        recommendation: 'Remove android:debuggable="true" or use ProGuard/R8 release build variant.',
        evidence: [{ type: 'manifest_attr', label: 'debuggable', value: 'true', location: 'application' }]
      },
      {
        id: 'f-allowbackup',
        engineId: 'static.v2',
        title: 'Application Data Backup Enabled',
        summary: 'android:allowBackup is enabled. App databases, shared preferences, and session tokens can be extracted via adb backup.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'MEDIUM',
        category: 'manifest',
        ruleId: 'M-BACKUP',
        confidence: 'HIGH',
        recommendation: 'Set android:allowBackup="false" if storing sensitive local credentials.',
        evidence: [{ type: 'manifest_attr', label: 'allowBackup', value: 'true', location: 'application' }]
      },
      {
        id: 'f-sms',
        engineId: 'static.v2',
        title: 'Sensitive SMS Interception Permissions',
        summary: 'Requests android.permission.RECEIVE_SMS and android.permission.READ_SMS.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-PERM-SMS',
        confidence: 'HIGH',
        recommendation: 'Use SMS Retriever API instead of requesting broad SMS interception permissions.',
        evidence: [
          { type: 'permission', label: 'uses-permission', value: 'android.permission.RECEIVE_SMS', location: 'manifest' },
          { type: 'permission', label: 'uses-permission', value: 'android.permission.READ_SMS', location: 'manifest' }
        ]
      },
      {
        id: 'f-exported',
        engineId: 'static.v2',
        title: 'Exported Critical Application Components',
        summary: 'Found 3 activities and 1 broadcast receiver declared with android:exported="true" without permission protection.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'MEDIUM',
        category: 'manifest',
        ruleId: 'M-EXPORTED',
        confidence: 'HIGH',
        recommendation: 'Add android:permission or set exported="false" on internal application entry points.',
        evidence: [
          { type: 'component', label: 'activity', value: 'com.android.insecurebankv2.DoTransfer (exported=true)', location: 'manifest' },
          { type: 'component', label: 'activity', value: 'com.android.insecurebankv2.ViewStatement (exported=true)', location: 'manifest' },
          { type: 'component', label: 'receiver', value: 'com.android.insecurebankv2.MyBroadcastReceiver (exported=true)', location: 'manifest' }
        ]
      },
      {
        id: 'f-cert-v1',
        engineId: 'static.v2',
        title: 'Signed with Test / Debug Key (V1 Scheme)',
        summary: 'Signer Certificate Subject: CN=Android Debug, O=Android, C=US. Not suitable for production deployment.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'MEDIUM',
        category: 'certificate',
        ruleId: 'C-DEBUG-KEY',
        confidence: 'HIGH',
        evidence: [{ type: 'x509_cert', label: 'subject', value: 'CN=Android Debug, O=Android, C=US', location: 'META-INF/CERT.RSA' }]
      },
      {
        id: 'f-unk-tamper',
        engineId: 'static.v2',
        title: 'Anti-Tamper & Hook Detection Gap',
        summary: 'Static engine cannot prove runtime Frida or Xposed detection without executing inside an isolated sandbox.',
        kind: 'UNKNOWN',
        severity: 'INFO',
        category: 'code',
        ruleId: 'U-001',
        confidence: 'LOW',
        evidence: [{ type: 'analysis_gap', label: 'hook_detection', value: 'unverified', location: 'dex' }]
      },
      {
        id: 'f-sandbox-net',
        engineId: 'sandbox.v1',
        title: 'Dynamic Network C2 Communication',
        summary: 'Real-time outbound socket connections and C2 domains can only be captured inside an isolated disposable environment.',
        kind: 'SANDBOX_ONLY',
        severity: 'INFO',
        category: 'correlation',
        ruleId: 'S-001',
        confidence: 'LOW',
        evidence: [{ type: 'sandbox_restriction', label: 'runtime_net', value: 'avd_required', location: 'runtime' }]
      }
    ],
    zipInventory: {
      totalFiles: 342,
      dexCount: 1,
      abis: ['armeabi-v7a', 'x86'],
      entries: [
        { fileName: 'AndroidManifest.xml', uncompSize: 4210 },
        { fileName: 'classes.dex', uncompSize: 2841024 },
        { fileName: 'resources.arsc', uncompSize: 412900 },
        { fileName: 'lib/armeabi-v7a/libnative-crypto.so', uncompSize: 184200 },
        { fileName: 'META-INF/CERT.RSA', uncompSize: 1044 },
        { fileName: 'META-INF/MANIFEST.MF', uncompSize: 38402 }
      ]
    }
  },

  'dropper': {
    name: 'CobaltDropper-Sample.apk',
    sizeBytes: 1845120,
    sha256: '7b88931ae30537829cd1a399f0183e2049e917d012e847c13a019488a0b0d39e',
    packageName: 'com.device.systemcore.service',
    minSdk: 24,
    targetSdk: 33,
    versionCode: 101,
    versionName: '1.0.1',
    riskScore: 92,
    riskBand: 'HIGH',
    correlations: [
      {
        id: 'corr-dropper-01',
        ruleId: 'CORR-COVERT-DROPPER',
        title: 'Covert Stage-2 Dropper Architecture',
        explanation: 'Co-occurrence of packaged DEX file in assets/ + REQUEST_INSTALL_PACKAGES + BIND_ACCESSIBILITY_SERVICE forms signature dropper profile.',
        severity: 'HIGH',
        scoreWeight: 30,
        sharedEvidence: [
          { type: 'zip_entry', label: 'asset', value: 'assets/stage2_payload.dex' },
          { type: 'manifest', label: 'permission', value: 'android.permission.REQUEST_INSTALL_PACKAGES' },
          { type: 'manifest', label: 'permission', value: 'android.permission.BIND_ACCESSIBILITY_SERVICE' }
        ]
      }
    ],
    scoreContributions: [
      { refRuleId: 'A-COVERT-PAYLOAD', description: 'Executable stage-2 payload embedded in assets folder', weight: 30 },
      { refRuleId: 'M-PERM-ACCESSIBILITY', description: 'Dangerous permission: Bind Accessibility Service (Keylogger/Sniffer)', weight: 20 },
      { refRuleId: 'M-PERM-INSTALL', description: 'Dangerous permission: Request Package Installation (Silent Dropper)', weight: 15 },
      { refRuleId: 'M-PERM-OVERLAY', description: 'Dangerous permission: Display Screen Overlay (Phishing Injection)', weight: 15 },
      { refRuleId: 'CORR-COVERT-DROPPER', description: 'Multi-signal correlation: Covert Stage-2 Dropper Architecture', weight: 30 }
    ],
    findings: [
      {
        id: 'f-asset-dex',
        engineId: 'static.v2',
        title: 'Hidden Executable Code (DEX) Packaged in Assets',
        summary: 'Detected assets/stage2_payload.dex (uncompressed 892 KB). Used by sophisticated malware to evade app-store scanners and drop second stage at runtime.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'archive',
        ruleId: 'A-COVERT-PAYLOAD',
        confidence: 'HIGH',
        recommendation: 'Examine all dynamic DexClassLoader and PathClassLoader invocations in code.',
        evidence: [{ type: 'zip_entry', label: 'asset_entry', value: 'assets/stage2_payload.dex', location: 'assets/' }]
      },
      {
        id: 'f-accessibility',
        engineId: 'static.v2',
        title: 'Requests Accessibility Service Permission',
        summary: 'Requests BIND_ACCESSIBILITY_SERVICE. Enables background keylogging, automated button clicks, and interception of 2FA notifications.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-PERM-ACCESSIBILITY',
        confidence: 'HIGH',
        evidence: [{ type: 'permission', label: 'permission', value: 'android.permission.BIND_ACCESSIBILITY_SERVICE', location: 'manifest' }]
      },
      {
        id: 'f-overlay',
        engineId: 'static.v2',
        title: 'Requests System Alert Window (Overlay Injection)',
        summary: 'Requests SYSTEM_ALERT_WINDOW. Allows rendering overlays over banking apps to capture passwords and OTPs.',
        kind: 'HEURISTIC_INDICATOR',
        severity: 'HIGH',
        category: 'manifest',
        ruleId: 'M-PERM-OVERLAY',
        confidence: 'HIGH',
        evidence: [{ type: 'permission', label: 'permission', value: 'android.permission.SYSTEM_ALERT_WINDOW', location: 'manifest' }]
      }
    ],
    zipInventory: {
      totalFiles: 128,
      dexCount: 2,
      abis: ['arm64-v8a'],
      entries: [
        { fileName: 'AndroidManifest.xml', uncompSize: 3120 },
        { fileName: 'classes.dex', uncompSize: 1102400 },
        { fileName: 'assets/stage2_payload.dex', uncompSize: 892100 },
        { fileName: 'lib/arm64-v8a/libdaemon.so', uncompSize: 421000 }
      ]
    }
  },

  'signal': {
    name: 'Signal-Private-Messenger.apk',
    sizeBytes: 52140800,
    sha256: '3f54818c39d8924b8159b3d014bc9029e248a8cf38b417e23901b08fa160c872',
    packageName: 'org.thoughtcrime.securesms',
    minSdk: 26,
    targetSdk: 35,
    versionCode: 12050,
    versionName: '7.15.2',
    riskScore: 10,
    riskBand: 'LOW',
    correlations: [],
    scoreContributions: [
      { refRuleId: 'M-PERM-CAMERA', description: 'Standard camera permission for video calling', weight: 5 },
      { refRuleId: 'M-PERM-MIC', description: 'Standard audio recording permission for voice messaging', weight: 5 }
    ],
    findings: [
      {
        id: 'f-clean-cleartext',
        engineId: 'static.v2',
        title: 'Cleartext Traffic Strictly Disabled',
        summary: 'android:usesCleartextTraffic is set to false. Network communications enforce TLS 1.3 encryption.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'manifest',
        ruleId: 'M-CLEARTEXT-OFF',
        confidence: 'HIGH',
        evidence: [{ type: 'manifest_attr', label: 'usesCleartextTraffic', value: 'false', location: 'application' }]
      },
      {
        id: 'f-clean-debug',
        engineId: 'static.v2',
        title: 'Debuggable Flag Disabled',
        summary: 'android:debuggable is false. Memory is protected against runtime debugger attachments.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'manifest',
        ruleId: 'M-DEBUGGABLE-OFF',
        confidence: 'HIGH',
        evidence: [{ type: 'manifest_attr', label: 'debuggable', value: 'false', location: 'application' }]
      },
      {
        id: 'f-clean-backup',
        engineId: 'static.v2',
        title: 'Local ADB Backup Prohibited',
        summary: 'android:allowBackup is disabled. Local keystore and encrypted message database cannot be dumped via adb backup.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'manifest',
        ruleId: 'M-BACKUP-OFF',
        confidence: 'HIGH',
        evidence: [{ type: 'manifest_attr', label: 'allowBackup', value: 'false', location: 'application' }]
      },
      {
        id: 'f-v2-sig',
        engineId: 'static.v2',
        title: 'APK Signature Scheme V2/V3 Confirmed',
        summary: 'APK contains modern whole-file cryptographic digest block protecting against archive manipulation.',
        kind: 'CONFIRMED_OBSERVATION',
        severity: 'INFO',
        category: 'certificate',
        ruleId: 'C-V2-CONFIRMED',
        confidence: 'HIGH',
        evidence: [{ type: 'sig_block', label: 'scheme', value: 'V2 + V3', location: 'ZIP Central Directory' }]
      }
    ],
    zipInventory: {
      totalFiles: 2840,
      dexCount: 4,
      abis: ['arm64-v8a', 'armeabi-v7a', 'x86_64'],
      entries: [
        { fileName: 'AndroidManifest.xml', uncompSize: 18400 },
        { fileName: 'classes.dex', uncompSize: 7420100 },
        { fileName: 'classes2.dex', uncompSize: 6810200 },
        { fileName: 'classes3.dex', uncompSize: 5920000 },
        { fileName: 'classes4.dex', uncompSize: 3100200 },
        { fileName: 'lib/arm64-v8a/libsignal-client.so', uncompSize: 4890200 }
      ]
    }
  }
};
