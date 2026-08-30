#!/usr/bin/env python3
"""Fail-closed authority audit for every remaining v2 core retention candidate."""
import argparse, ast, hashlib, json, re, tomllib
from pathlib import Path

MAPPINGS={
 "crates/habitat-abi/":("ABI-001","ABI-002","ABI-004"),
 "crates/habitat-authority/":("AUTH-001","AUTH-002","AUTH-003","AUTH-004"),
 "crates/habitat-context/":("CTX-001","CTX-002","CTX-003","CTX-004"),
 "crates/habitat-execution/":("AUTH-004","EXEC-001","EXEC-002","SYS-004"),
 "crates/habitat-effects/":("EFFECT-001","EFFECT-002","EFFECT-003","EFFECT-004","EFFECT-005"),
 "crates/habitat-models/":("ABI-003","EXEC-003"),
 "crates/habitat-provider-transport/":("AUTH-004",),
 "crates/habitat-packages/":("PKG-001","PKG-002","PKG-003"),
 "crates/habitat-harnesses/":("ABI-003","EXEC-003"),
 "src/habitat_state/":("STATE-001","STATE-002","STATE-003","STATE-004"),
}
FIXTURE_MAPPING={"tests/fixtures/proto-contracts/":("ABI-001","ABI-004"),
 "tests/fixtures/schema-contracts/":("PKG-001",)}
TEST_MAPPINGS={
 "tests/test_proto_contracts.py":("ABI-001","ABI-004"),"tests/test_schema_contracts.py":("PKG-001",),
 "tests/test_v2_authority_effect_evidence.py":("AUTH-001","AUTH-002","AUTH-003","EFFECT-001","EFFECT-002","EFFECT-003","EFFECT-004","EFFECT-005"),
 "tests/test_v2_contract_derivation.py":("SCOPE-001","SCOPE-002","SCOPE-003"),
 "tests/test_v2_rebuild_frontier.py":("SCOPE-001","SCOPE-002","SCOPE-003"),
 "tests/test_v2_scope_classification.py":("SCOPE-001","SCOPE-002","SCOPE-003"),
 "tests/test_v2_scope_removal.py":("SCOPE-001","SCOPE-002"),"tests/test_w00_qualification.py":("SCOPE-001","SCOPE-002","SCOPE-003"),
 "tests/test_w01_profile.py":("SYS-004",),"tests/test_w02_state.py":("STATE-001","STATE-003","STATE-004"),
 "tests/test_w05_lifecycle.py":("CORE-002","STATE-002"),"tests/test_v2_core_audit.py":("VERIFY-001",),
}
CARGO_ALLOWED={
 "crates/habitat-abi/":{"hyper-util","prost","prost-types","serde","serde_json","sha2","tokio","tokio-stream","tonic","tonic-prost","tower","tempfile","tonic-prost-build"},
 "crates/habitat-authority/":{"serde","serde_json","sha2","libc","tempfile"},
 "crates/habitat-context/":{"serde","serde_json","sha2"},"crates/habitat-execution/":{"serde","serde_json"},
 "crates/habitat-effects/":{"habitat-authority","serde","serde_json","sha2","tempfile"},
 "crates/habitat-models/":{"serde","serde_json"},"crates/habitat-provider-transport/":{"serde_json","sha2"},
 "crates/habitat-packages/":{"ed25519-dalek","serde","serde_json","sha2"},
 "crates/habitat-harnesses/":{"habitat-models","serde","serde_json"},
}
PYTHON_ALLOWED={"__future__","base64","boto3","botocore","concurrent","dataclasses","datetime","domain","enum",
 "habitat_state","hashlib","json","jsonschema","lifecycle","os","pathlib","psycopg","re","shutil","store",
 "subprocess","sys","tempfile","tools","unittest","uuid"}
FORBIDDEN=re.compile(r"CredentialBroker|authorization\s*:|habitat_authority|habitat_effects|std::net|UnixStream|TcpStream|reqwest|Command::new|\bcurl\b|Authorization",re.I)
AMBIENT=re.compile(r"\bcurl\b|Authorization|reqwest|TcpStream|std::net",re.I)
API=re.compile(r"^\s*pub(?:\([^)]*\))?\s+(?:(?:async|const|unsafe)\s+)*(?:struct|enum|trait|type|const|static|mod|fn)\s+([A-Za-z_][A-Za-z0-9_]*)")
BRANCH=re.compile(r"\b(?:if|match)\b|=>")
TEST=re.compile(r"(?:#\[test\]\s*)?(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
REQUIREMENT_DETAILS={}
SEMANTIC_RULES=(
 ("crates/habitat-harnesses/",r"CapabilityProxy",("AUTH-004","EXEC-003")),
 ("crates/habitat-harnesses/",r"HarnessRuntime|RuntimeStatus|RuntimeOutcome",("EXEC-003",)),
 ("crates/habitat-harnesses/",r"Backend|Checkpoint|Adapter|translate|HarnessOutput|DurableIdentity",("ABI-003",)),
 ("crates/habitat-harnesses/",r"PreparedActivation|HarnessAdapter",("ABI-003","EXEC-003")),
 ("crates/habitat-models/",r"Capability|DispositionValidator|ModelDriver|ActivationEnvelope",("ABI-003","EXEC-003")),
 ("crates/habitat-models/",r"Adapter|Disposition|Candidate|ModelEvidence|DecisionArtifact",("ABI-003",)),
 ("crates/habitat-authority/",r"Peer|Identity|Invocation|bind|evaluate",("AUTH-001",)),
 ("crates/habitat-authority/",r"Policy|Decision|deny",("AUTH-002",)),
 ("crates/habitat-authority/",r"Grant|Revocation|delegate|revoke",("AUTH-003",)),
 ("crates/habitat-execution/",r"Profile|Capacity|Resource",("SYS-004","EXEC-002")),
 ("crates/habitat-execution/",r"Boundary|Isolation|admit",("AUTH-004","EXEC-001")),
)

def mapping(path):
    value=path.as_posix()
    for prefix,requirements in MAPPINGS.items():
        if value.startswith(prefix): return requirements
    for prefix,requirements in FIXTURE_MAPPING.items():
        if value.startswith(prefix): return requirements
    if value in TEST_MAPPINGS:return TEST_MAPPINGS[value]
    return None

def semantic_requirements(kind,identity,source,defaults):
    if kind=="public_interface":
        for prefix,pattern,requirements in SEMANTIC_RULES:
            if source.startswith(prefix) and re.search(pattern,identity,re.I):return requirements
    return defaults

def record(kind,identity,requirements,source):
    result={"kind":kind,"identity":identity,"requirement_ids":list(requirements),
      "authority":[f"contracts/v2.0.1/nix-ai-v2.0.1.contract.json#/requirements/{value}" for value in requirements],
      "binding":{"semantic":identity,"class":kind,"requirement_ids":list(requirements),
          "decision":"retained only under the cited trigger, boundary, failure, and enforcement"},
      "source":source}
    if kind=="dependency":result["binding"]["necessity"]="declared source/build edge for this retained unit; any undeclared edge is rejected"
    return result

def audit(root):
    global REQUIREMENT_DETAILS
    contract=json.loads((root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
    REQUIREMENT_DETAILS={item["id"]:item for item in contract["requirements"]}
    records=[];files=[];unresolved=[]
    candidates=[]
    for top in ("crates","src"):
        candidates.extend(path for path in (root/top).rglob("*") if path.is_file()
            and "__pycache__" not in path.parts and path.suffix!=".pyc")
    candidates.extend(path for path in (root/"tests/fixtures").rglob("*") if path.is_file())
    candidates.extend(path for path in (root/"tests").glob("test_*.py") if path.is_file())
    for path in sorted(set(candidates)):
        relative=path.relative_to(root);requirements=mapping(relative)
        if not requirements: unresolved.append(relative.as_posix());continue
        files.append(relative.as_posix());suffix=path.suffix
        try: content=path.read_text()
        except UnicodeDecodeError: content=""
        if suffix in {".rs",".py"}:
            lines=content.splitlines();pending_test=False;enum_depth=0;current_requirements=requirements
            for number,line in enumerate(lines,1):
                opened_enum=False
                match=API.search(line)
                if match:
                    identity=f"{relative}:{number}:{match.group(1)}"
                    current_requirements=semantic_requirements("public_interface",identity,relative.as_posix(),requirements)
                    records.append(record("public_interface",identity,current_requirements,relative.as_posix()))
                    if re.search(r"\bpub\s+enum\b",line):
                        opened_enum=True
                        enum_depth=line.count("{")-line.count("}")
                        same_line=re.search(r"\{(.*)\}",line)
                        if same_line:
                            for variant in re.findall(r"(?:^|,)\s*([A-Z][A-Za-z0-9_]*)",same_line.group(1)):
                                records.append(record("public_interface",f"{relative}:{number}:enum-variant:{variant}",current_requirements,relative.as_posix()))
                elif enum_depth and (variant:=re.match(r"\s*([A-Z][A-Za-z0-9_]*)\s*(?:[({=,]|$)",line)):
                    records.append(record("public_interface",f"{relative}:{number}:enum-variant:{variant.group(1)}",current_requirements,relative.as_posix()))
                if enum_depth and not opened_enum:
                    enum_depth+=line.count("{")-line.count("}")
                    if enum_depth<=0: enum_depth=0
                if BRANCH.search(line) and not line.lstrip().startswith("//"):
                    records.append(record("branch",f"{relative}:{number}",current_requirements,relative.as_posix()))
                if "#[test]" in line:
                    inline=TEST.search(line)
                    if inline: records.append(record("test",f"{relative}:{number}:{inline.group(1)}",requirements,relative.as_posix()))
                    else: pending_test=True
                    continue
                if pending_test:
                    test=TEST.search(line)
                    if test: records.append(record("test",f"{relative}:{number}:{test.group(1)}",requirements,relative.as_posix()));pending_test=False
                if suffix==".py" and re.match(r"\s*def\s+test_[A-Za-z0-9_]+\s*\(",line):
                    name=line.split("def ",1)[1].split("(",1)[0]
                    records.append(record("test",f"{relative}:{number}:{name}",requirements,relative.as_posix()))
            if suffix==".py":
                tree=ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and not node.name.startswith("_"):
                        records.append(record("public_interface",f"{relative}:{node.lineno}:{node.name}",requirements,relative.as_posix()))
                    if isinstance(node,(ast.If,ast.Match,ast.Try)):
                        records.append(record("branch",f"{relative}:{node.lineno}:{type(node).__name__}",requirements,relative.as_posix()))
                    names=[]
                    if isinstance(node,ast.Import):names=[value.name.split('.')[0] for value in node.names]
                    elif isinstance(node,ast.ImportFrom) and node.module:names=[node.module.split('.')[0]]
                    for dependency in names:
                        records.append(record("dependency",f"{relative}:{node.lineno}:python-import:{dependency}",requirements,relative.as_posix()))
                        if dependency not in PYTHON_ALLOWED:unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
            if relative.as_posix().startswith(("crates/habitat-models/","crates/habitat-harnesses/")):
                found=FORBIDDEN.search(content)
                if found: unresolved.append(f"forbidden-adapter-path:{relative}:{found.group(0)}")
        elif relative.as_posix().startswith(("crates/habitat-models/","crates/habitat-harnesses/")):
            found=FORBIDDEN.search(content)
            if found: unresolved.append(f"forbidden-adapter-path:{relative}:{found.group(0)}")
        production_source=(relative.as_posix().startswith("src/") or "/src/" in relative.as_posix())
        found=AMBIENT.search(content)
        if production_source and found and not relative.as_posix().startswith("crates/habitat-provider-transport/"):
            unresolved.append(f"ambient-core-path:{relative}:{found.group(0)}")
        if production_source and re.search(rb"transcript",path.read_bytes(),re.I):
            unresolved.append(f"provider-transcript-authority-surface:{relative}")
        if path.name=="Cargo.toml":
            data=tomllib.loads(path.read_text())
            for section in ("dependencies","dev-dependencies","build-dependencies"):
                for dependency in sorted(data.get(section,{})):
                    records.append(record("dependency",f"{relative}:{section}:{dependency}",requirements,relative.as_posix()))
                    allowed=next((values for prefix,values in CARGO_ALLOWED.items() if relative.as_posix().startswith(prefix)),set())
                    if dependency not in allowed:unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
        if relative.as_posix().startswith("tests/fixtures/"):
            records.append(record("fixture",relative.as_posix(),requirements,relative.as_posix()))
    known={item["id"] for item in contract["requirements"]}
    unresolved.extend(f"unknown-requirement:{value}" for item in records for value in item["requirement_ids"] if value not in known)
    profile=json.loads((root/"nix/profiles/qemu-x86_64-conformance.json").read_text())
    canonical_profiles=set(contract["canonical_model"]["hardware_profiles"])
    profile_ok=(profile.get("profile_id") in canonical_profiles and profile.get("gpu",{}).get("status")=="absent"
      and profile.get("devices")==[] and bool(profile.get("capacity")) and bool(profile.get("kernel",{}).get("digest"))
      and bool(profile.get("firmware",{}).get("digest")) and bool(profile.get("drivers",{}).get("digest"))
      and profile.get("isolation",{}).get("default")=="DENY" and bool(profile.get("isolation",{}).get("enforcement")))
    if not profile_ok: unresolved.append("hardware-profile-missing-capacity-or-explicit-absence")
    digest=hashlib.sha256()
    for relative in files:
        content=(root/relative).read_bytes();digest.update(relative.encode()+b"\0"+content+b"\0")
    counts={kind:sum(item["kind"]==kind for item in records) for kind in ("public_interface","branch","dependency","test","fixture")}
    return {"schema_version":1,"runner":{"name":"audit-v2-core","version":1},"scope_digest":digest.hexdigest(),
      "authority_catalog":{value:{key:REQUIREMENT_DETAILS[value][key] for key in
          ("source_authority","source_reference","trigger","shall","boundary","failure","enforcement")}
          for value in sorted({requirement for item in records for requirement in item["requirement_ids"]})},
      "counts":counts,"candidate_file_count":len(files),"unresolved_candidates":sorted(set(unresolved)),
      "untrusted_candidates":sorted(set(unresolved)),"provider_transcripts":"diagnostic-only","adapter_direct_path_count":sum(value.startswith("forbidden-adapter-path:") for value in unresolved),
      "hardware_profile":{"profile_id":profile.get("profile_id"),"capacity_declared":bool(profile.get("capacity")),"gpu":profile.get("gpu",{}).get("status"),"devices":profile.get("devices")},
      "records":records,"valid":not unresolved}

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--root",type=Path,required=True);parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();report=audit(args.root.resolve());args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({key:report[key] for key in ("valid","counts","candidate_file_count","unresolved_candidates")},sort_keys=True))
    raise SystemExit(0 if report["valid"] else 1)
if __name__=="__main__":main()
