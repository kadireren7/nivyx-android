#!/usr/bin/env python3
"""Generate a minimal SPDX 2.3 JSON SBOM from Cargo.lock and the Gradle version catalog."""
import json, re, sys, datetime, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
version = sys.argv[1] if len(sys.argv) > 1 else "0.0.0"
out = sys.argv[2] if len(sys.argv) > 2 else f"nivyx-android-v{version}.spdx.json"
pkgs = []
lock = (root / "Cargo.lock").read_text()
for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"(?:\nsource = "([^"]+)")?', lock):
    name, ver, src = m.groups()
    pkgs.append({"name": name, "versionInfo": ver, "supplier": "NOASSERTION", "downloadLocation": src or "NOASSERTION",
                 "licenseConcluded": "NOASSERTION", "filesAnalyzed": False,
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:cargo/{name}@{ver}"}]})
cat = (root / "gradle/libs.versions.toml").read_text()
versions = dict(re.findall(r'^(\w+) = "([^"]+)"', cat, re.M))
for alias, module, ref in re.findall(r'^([\w-]+) = \{ module = "([^"]+)"(?:, version\.ref = "(\w+)")? \}', cat, re.M):
    ver = versions.get(ref, "BOM-managed")
    pkgs.append({"name": module, "versionInfo": ver, "supplier": "NOASSERTION", "downloadLocation": "NOASSERTION",
                 "licenseConcluded": "NOASSERTION", "filesAnalyzed": False,
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:maven/{module.replace(':','/')}@{ver}"}]})
for i, p in enumerate(pkgs):
    p["SPDXID"] = f"SPDXRef-Package-{i}"
doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
       "name": f"nivyx-android-{version}", "documentNamespace": f"https://github.com/kadireren7/nivyx-android/sbom/{version}",
       "creationInfo": {"created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: make-sbom.py"]},
       "packages": [{"SPDXID": "SPDXRef-Nivyx", "name": "nivyx-android", "versionInfo": version, "downloadLocation": "https://github.com/kadireren7/nivyx-android",
                     "licenseConcluded": "MIT", "licenseDeclared": "MIT", "filesAnalyzed": False, "supplier": "Person: Kadir Eren Altintas"}] + pkgs,
       "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Nivyx"}]}
pathlib.Path(out).write_text(json.dumps(doc, indent=2))
print(f"wrote {out}: {len(pkgs)} packages")
