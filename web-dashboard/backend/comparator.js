/**
 * Kernel Call — Multi-APK Comparative & Forensic Diff Engine
 * Addresses Requirement #6:
 * "Support rapid analysis of multiple APKs, comparison of findings, behavioural insights,
 * IoC visualisation, and structured forensic reports with supporting evidence."
 */

class ApkComparator {
  compareReports(reportA, reportB) {
    if (!reportA || !reportB) {
      throw new Error('Both reportA and reportB are required for comparative analysis.');
    }

    // Permission comparison
    const permsA = this.extractPermissions(reportA);
    const permsB = this.extractPermissions(reportB);

    const addedPermissions = permsB.filter(p => !permsA.includes(p));
    const removedPermissions = permsA.filter(p => !permsB.includes(p));
    const commonPermissions = permsA.filter(p => permsB.includes(p));

    // Findings comparison
    const ruleIdsA = (reportA.findings || []).map(f => f.ruleId).filter(Boolean);
    const ruleIdsB = (reportB.findings || []).map(f => f.ruleId).filter(Boolean);

    const newThreatRules = (reportB.findings || []).filter(f => !ruleIdsA.includes(f.ruleId));
    const resolvedThreatRules = (reportA.findings || []).filter(f => !ruleIdsB.includes(f.ruleId));

    // Score Delta
    const scoreA = reportA.intelligence?.risk?.score ?? 0;
    const scoreB = reportB.intelligence?.risk?.score ?? 0;
    const scoreDelta = scoreB - scoreA;

    return {
      comparedAt: Date.now(),
      baseApk: {
        fileName: reportA.fileName,
        sha256: reportA.sha256,
        sizeBytes: reportA.sizeBytes,
        packageName: reportA.packageName,
        score: scoreA,
        riskBand: reportA.intelligence?.risk?.band
      },
      targetApk: {
        fileName: reportB.fileName,
        sha256: reportB.sha256,
        sizeBytes: reportB.sizeBytes,
        packageName: reportB.packageName,
        score: scoreB,
        riskBand: reportB.intelligence?.risk?.band
      },
      metricsDelta: {
        scoreDelta,
        scoreIncreased: scoreDelta > 0,
        sizeDifferenceBytes: reportB.sizeBytes - reportA.sizeBytes,
        findingsCountDelta: (reportB.findings?.length || 0) - (reportA.findings?.length || 0)
      },
      permissionCreep: {
        addedCount: addedPermissions.length,
        removedCount: removedPermissions.length,
        added: addedPermissions,
        removed: removedPermissions,
        retained: commonPermissions
      },
      threatFindingsDelta: {
        newThreatsIntroduced: newThreatRules,
        remediatedThreats: resolvedThreatRules
      },
      forensicVerdict: scoreDelta > 15
        ? `HIGH RISK ELEVATION: Target APK introduced ${addedPermissions.length} new permissions and ${newThreatRules.length} high-severity findings (Risk increased by +${scoreDelta} pts).`
        : scoreDelta < -15
        ? `HARDENED VARIANT: Target APK remediated ${resolvedThreatRules.length} security flags and dropped ${removedPermissions.length} permissions.`
        : 'COMPARABLE POSTURE: Minimal divergence in permission scope and threat indicators.'
    };
  }

  extractPermissions(report) {
    const list = [];
    (report.findings || []).forEach(f => {
      (f.evidence || []).forEach(e => {
        if (e.type === 'permission') list.push(e.value);
      });
    });
    return Array.from(new Set(list));
  }
}

module.exports = new ApkComparator();
