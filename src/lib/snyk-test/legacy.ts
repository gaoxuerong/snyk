import * as _ from 'lodash';
import * as depGraphLib from '@snyk/dep-graph';

export {
  convertTestDepGraphResultToLegacy,
};

interface VulnInfo {
  id: string;
  packageName: string;
  moduleName?: string;
  semver: {
    vulnerable: string | string[];
    vulnerableHashes?: string[];
    vulnerableByDistro?: {
      [distroNameAndVersion: string]: string[];
    }
  };
  patches: object[];
  description: string;
}

interface AnnotatedIssue extends VulnInfo {
  name: string;
  version: string;
  from: Array<string | boolean>;
  upgradePath: Array<string | boolean>;
  isUpgradable: boolean;
  isPatchable: boolean;
}

interface LegacyVulnApiResult {
  vulnerabilities: any[]; // TODO: type
  ok: boolean;
  dependencyCount: number;
  org: string;
  policy: string;
  isPrivate: boolean;
  licensesPolicy: object;
  packageManager: string;
  ignoreSettings: object;
  summary: string;
  severityThreshold: string;
}

const SEVERITIES = [ 'low', 'medium', 'high' ];

function convertTestDepGraphResultToLegacy(
    res, depGraph: depGraphLib.DepGraph, packageManager: string, severityThreshold: string): LegacyVulnApiResult {

  const result = res.result;

  // TODO: make sure the way you handle null versions is the same here and in vuln
  const upgradePathsMap = [];
  Object.keys(result.affectedPkgs).forEach((pkgId) => {
    const issues = result.affectedPkgs[pkgId].issues;
    Object.keys(issues).forEach((issueId) => {
      if (issues[issueId].fixInfo) {
        issues[issueId].fixInfo.upgradePaths.forEach((upgradePath) => {
          const key = getIssueWithVulnPathStr(
            issueId,
            upgradePath.path.map(toLegacyPkgId));
          // TODO: check if key already exists in upgradePathsMap?
          upgradePathsMap[key] = toLegacyUpgradePath(upgradePath.path);
        });
      }
    });
  });

  let vulnerabilities: AnnotatedIssue[] = [];
  Object.keys(result.affectedPkgs).forEach((pkgId) => {
    const pkg = result.affectedPkgs[pkgId].pkg;
    const depIssues = result.affectedPkgs[pkgId].issues;
    const vulnPaths = depGraph.pkgPathsToRoot(pkg);
    vulnPaths.forEach((vulnPath) => {
      Object.keys(depIssues).forEach((issueId) => {
        const fromPath = getLegacyFromPath(vulnPath);
        const key = getIssueWithVulnPathStr(issueId, fromPath);

        // TODO: we don't need the vuln issue data for all expect '--json'
        //   and it increases the chance of OOM ...
        //   need to see how to not allocate to much but still create a full `--json` output

        const issueData: VulnInfo = result.issues[issueId];

        const upgradePath = upgradePathsMap[key] || [];
        const annotatedIssue: AnnotatedIssue = Object.assign({}, issueData, {
          // note: keep the same key order as legacy
          from: fromPath,
          upgradePath,
          version: pkg.version,
          name: pkg.name,
          isUpgradable: !!upgradePath[0] || !!upgradePath[1],
          isPatchable: depIssues[issueId].fixInfo.isPatchable, // TODO: test this
        });

        vulnerabilities.push(annotatedIssue);
      });
    });
  });

  if (severityThreshold) {
    vulnerabilities = filterVulnsBySeverityThreshold(vulnerabilities, severityThreshold).vulns;
  }

  const meta = res.meta || {};

  const legacyRes: LegacyVulnApiResult = {
    vulnerabilities,
    ok: vulnerabilities.length === 0,
    dependencyCount: depGraph.getPkgs().length - 1,
    org: meta.org,
    policy: meta.policy,
    isPrivate: !meta.isPublic,
    licensesPolicy: meta.licensesPolicy,
    packageManager, // TODO: seems /vuln API returns `maven` for `gradle` here?
    ignoreSettings: meta.ignoreSettings,
    summary: getSummary(vulnerabilities, severityThreshold),
    severityThreshold,
  };

  return legacyRes;
}

function getIssueWithVulnPathStr(issueId, vulnPath) {
  const issueWithVulnPath = {
    issueId,
    vulnPath,
  };
  return JSON.stringify(issueWithVulnPath);
}

// TODO: rename
function getLegacyFromPath(vulnPath) {
  return vulnPath.slice().reverse().map((pkg) => {
    return toLegacyPkgId(pkg);
  });
}

function toLegacyUpgradePath(upgradePath) {
  return upgradePath
    .filter((item) => !item.isDropped)
    .map((item) => {
      if (!item.newVersion) {
        return false;
      }

      return `${item.name}@${item.newVersion}`;
    });
}

function toLegacyPkgId(pkg) {
  return `${pkg.name}@${pkg.version || '*'}`;
}

function getSummary(vulns: object[], severityThreshold: string): string {
  const count = vulns.length;
  let countText = '' + count;
  const severityFilters: string[] = [];

  if (severityThreshold) {
    SEVERITIES.slice(SEVERITIES.indexOf(severityThreshold)).forEach((sev) => {
      severityFilters.push(sev);
    });
  }

  if (!count) {
    if (severityFilters.length) {
      return `No ${severityFilters.join(' or ')} severity vulnerabilities`;
    }
    return 'No known vulnerabilities';
  }

  if (severityFilters.length) {
    countText += ' ' + severityFilters.join(' or ') + ' severity';
  }

  return `${countText} vulnerable dependency ${pl('path', count)}`;
}

function pl(word, count) {
  const ext = {
    y: 'ies',
    default: 's',
  };

  const last = word.split('').pop();

  if (count > 1) {
    return word.slice(0, -1) + (ext[last] || last + ext.default);
  }

  return word;
}

function filterVulnsBySeverityThreshold(vulns, severityThreshold) {
  if (!severityThreshold || severityThreshold === SEVERITIES[0]) {
    // no filtering necessary
    return { vulns };
  }
  // TODO(michael-go): fail here
  // if (!validateSeverityThreshold(severityThreshold)) {
  //   logger.warn({}, `Invalid severity threshold: ${severityThreshold}`);
  //   throw new BadRequestError('Invalid severity threshold.');
  // }

  const severities = SEVERITIES.slice(SEVERITIES.indexOf(severityThreshold));
  const filteredVulns = _.filter(vulns, (vuln) => {
    return (severities.indexOf(vuln.severity) > -1);
  });

  return { vulns: filteredVulns, severityThreshold };
}
