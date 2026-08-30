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
 "crates/habitat-provider-transport/":("ABI-003",),
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
 "subprocess","sys","tempfile","tools","unittest","uuid","argparse","ast","tomllib","fnmatch","secrets",
 "socket","time","signal","typing","yaml","inventory_v2","proto_contracts"}
FORBIDDEN=re.compile(r"CredentialBroker|authorization\s*:|habitat_authority|habitat_effects|std::net|UnixStream|TcpStream|reqwest|Command::new|\bcurl\b|Authorization",re.I)
AMBIENT=re.compile(r"(?i:\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bsocat\b|Authorization[\"']?\s*[:=]|reqwest|TcpStream|std::net|socket\.)|\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b")
AMBIENT_EXEMPT={
 "crates/habitat-abi/src/bin/server.rs":re.compile(r"socket\.",re.I),
 "tools/qualify_w05.py":re.compile(r"socket\.",re.I),
 "tools/qualify_w02.py":re.compile(r"socket\.|HABITAT_TEST_S3_(?:ACCESS_KEY|SECRET_KEY)",re.I),
 "tools/qualify_w06.py":re.compile(r"AWS_SECRET_ACCESS_KEY"),
 "tools/test_w01.py":re.compile(r"socket\.",re.I),
}
SECRET_REFERENCE=re.compile(r"(?:std::env::var|os\.environ(?:\.get)?|\$\{?|secrets\.)[^\n]{0,120}(?:key|token|secret|password)|(?:key|token|secret|password)[^\n]{0,120}(?:std::env::var|os\.environ(?:\.get)?|secrets\.)",re.I)
EXTERNAL_EFFECT=re.compile(r"std::(?:net|process|env)|Command::new|/dev/tcp|os\.environ|os\.system|subprocess|socket\.|urllib|requests?\.|python\s+(?:-[A-Za-z]*c\b|-c\b)|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bsocat\b|reqwest|TcpStream",re.I)
COMBINED_EXEMPT={"tools/qualify_w02.py","tools/qualify_w06.py"}
PROVIDER_FORBIDDEN=re.compile(r"\bstd::|\bcore::|\bunsafe\b|\bextern\b|\basm!|Command::new|/dev/tcp|os\.environ|subprocess|socket\.|reqwest|Authorization|Bearer",re.I)
RUST_QUALIFIERS=r"(?:(?:async|const|unsafe)\s+|extern\s+\"[^\"]+\"\s+)*"
API=re.compile(rf"\bpub(?:\([^)]*\))?\s+{RUST_QUALIFIERS}(?:struct|enum|trait|type|const|static|mod|fn)\s+([A-Za-z_][A-Za-z0-9_]*)")
BRANCH=re.compile(r"\b(?:if|match|for|while|loop)\b|=>")
SCRIPT_BRANCH=re.compile(r"(?:^|\s)(?:if|elif|while|for|case|assert)(?=\s)|\bthen\b|&&|\|\||^\s*if\s*:",re.I)
TEST=re.compile(r"(?:#\[test\]\s*)?(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION=re.compile(rf"(?:pub(?:\([^)]*\))?\s+)?{RUST_QUALIFIERS}fn\s+([A-Za-z_][A-Za-z0-9_]*)")
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
REPOSITORY_SCOPES=(
 ("crates/",("SCOPE-001",)),("src/",("SCOPE-001",)),("tests/",("VERIFY-001",)),
 ("tools/",("VERIFY-001",)),("evidence/",("VERIFY-001",)),("contracts/",("SCOPE-003",)),
 ("generated/",("ABI-001","SCOPE-003")),("nix/",("SYS-001","SYS-004")),
 ("docs/",("SCOPE-001",)),
)
ROOT_SCOPES={".gitignore":("SCOPE-001",),"AGENTS.md":("SCOPE-001",),"README.md":("SCOPE-001",),
 "CODEX-BUILD-SPEC.md":("SCOPE-003",),"Cargo.toml":("SCOPE-001",),"Cargo.lock":("SCOPE-003",),
 "flake.nix":("SYS-001","SYS-004"),"flake.lock":("SCOPE-003",),"pyproject.toml":("SCOPE-001",),
 "buf.yaml":("ABI-001",),"buf.gen.yaml":("ABI-001",)}
DEPENDENCY_PURPOSES={
 "serde":"canonical record encoding","serde_json":"typed JSON boundary encoding","sha2":"content identity digests",
 "libc":"Linux peer credential and process identity checks","tempfile":"isolated persistence and boundary tests",
 "prost":"protobuf message ABI","prost-types":"protobuf well-known ABI types","tonic":"gRPC transport boundary",
 "tonic-prost":"gRPC protobuf codec","tonic-prost-build":"deterministic protobuf build","hyper-util":"gRPC connector runtime",
 "tokio":"asynchronous transport runtime","tokio-stream":"Unix listener stream adaptation","tower":"transport service adaptation",
 "ed25519-dalek":"package signature verification","habitat-authority":"current authority evaluation at effect boundaries",
 "habitat-models":"normalized cognition ABI consumed by harness adapters",
}

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

def repository_scope(path):
    value=path.as_posix()
    if value in ROOT_SCOPES:return ROOT_SCOPES[value]
    return next((requirements for prefix,requirements in REPOSITORY_SCOPES if value.startswith(prefix)),None)

def record(kind,identity,requirements,source,necessity=None):
    result={"kind":kind,"identity":identity,"requirement_ids":list(requirements),
      "authority":[f"contracts/v2.0.1/nix-ai-v2.0.1.contract.json#/requirements/{value}" for value in requirements],
      "binding":{"semantic":identity,"class":kind,"requirement_ids":list(requirements),
          "decision":"retained only under the cited trigger, boundary, failure, and enforcement"},
      "source":source}
    if kind=="dependency":result["binding"]["necessity"]=necessity or "missing dependency necessity proof"
    return result

def rust_blocks(content,header):
    """Yield syntactic brace bodies while respecting nested struct variants and methods."""
    for match in re.finditer(header,content,re.S):
        opening=content.find("{",match.end())
        if opening<0:continue
        depth=0
        for position in range(opening,len(content)):
            if content[position]=="{":depth+=1
            elif content[position]=="}":
                depth-=1
                if depth==0:
                    yield match,opening+1,position
                    break

def top_level_rust_items(body):
    start=0;depth=0
    for position,value in enumerate(body):
        if value in "{([<":depth+=1
        elif value in "})]>" and depth:depth-=1
        elif value=="," and depth==0:
            yield start,body[start:position];start=position+1
    yield start,body[start:]

def audit(root):
    global REQUIREMENT_DETAILS
    contract=json.loads((root/"contracts/v2.0.1/nix-ai-v2.0.1.contract.json").read_text())
    REQUIREMENT_DETAILS={item["id"]:item for item in contract["requirements"]}
    records=[];files=[];unresolved=[]
    ignored={".git","target","__pycache__",".pytest_cache"};self_artifact="evidence/v2-rebuild/core-retention-audit.json"
    repository_files=[]
    for path in sorted(root.rglob("*")):
        relative=path.relative_to(root)
        if any(part in ignored for part in relative.parts):continue
        if path.is_symlink():
            unresolved.append(f"symlink-repository-unit:{relative}");continue
        if not path.is_file():continue
        if relative.as_posix()==self_artifact:continue
        requirements=repository_scope(relative)
        if not requirements:unresolved.append(f"unmapped-repository-unit:{relative}");continue
        repository_files.append(relative.as_posix())
        records.append(record("repository_unit",relative.as_posix(),requirements,relative.as_posix()))
    candidates=[root/relative for relative in repository_files]
    for path in sorted(set(candidates)):
        relative=path.relative_to(root);specific=mapping(relative);requirements=specific or repository_scope(relative)
        if not specific and relative.as_posix().startswith(("crates/","src/","tests/fixtures/")):
            unresolved.append(f"unmapped-semantic-unit:{relative}")
        if not requirements: unresolved.append(relative.as_posix());continue
        files.append(relative.as_posix());suffix=path.suffix
        if relative.as_posix().startswith("crates/") and not (suffix==".rs" or path.name=="Cargo.toml"):
            unresolved.append(f"unsupported-core-source-class:{relative}")
        if relative.as_posix().startswith("src/") and suffix!=".py":
            unresolved.append(f"unsupported-core-source-class:{relative}")
        try: content=path.read_text()
        except UnicodeDecodeError:
            content=""
            if relative.as_posix().startswith(("crates/","src/","tools/","tests/","nix/")):
                unresolved.append(f"undecodable-semantic-source:{relative}")
        if suffix in {".rs",".py"}:
            lines=content.splitlines();pending_test=False;current_requirements=requirements
            current_scope="module";brace_depth=0;scope_depth=None
            if suffix==".rs":
                for match in API.finditer(content):
                    number=content[:match.start()].count("\n")+1
                    identity=f"{relative}:{number}:{match.group(1)}"
                    bound=semantic_requirements("public_interface",identity,relative.as_posix(),requirements)
                    records.append(record("public_interface",identity,bound,relative.as_posix()))
            for number,line in enumerate(lines,1):
                function=FUNCTION.search(line)
                if function:
                    current_scope=function.group(1);scope_depth=brace_depth
                    scope_identity=f"{relative}:{number}:{current_scope}"
                    current_requirements=semantic_requirements("public_interface",scope_identity,relative.as_posix(),requirements)
                branch_source=re.sub(r'"(?:\\.|[^"\\])*"', '""', line.split("//",1)[0])
                if BRANCH.search(branch_source):
                    records.append(record("branch",f"{relative}:{number}:scope:{current_scope}",current_requirements,relative.as_posix()))
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
                brace_depth+=line.count("{")-line.count("}")
                if scope_depth is not None and brace_depth<=scope_depth:
                    current_scope="module";current_requirements=requirements;scope_depth=None
            if suffix==".rs":
                for enum,start,end in rust_blocks(content,r"\bpub\s+enum\s+([A-Za-z_][A-Za-z0-9_]*)[^\{;]*"):
                    name=enum.group(1);body=content[start:end]
                    for offset,item in top_level_rust_items(body):
                        variant=re.match(r"\s*([A-Z][A-Za-z0-9_]*)",item)
                        if not variant:continue
                        line=content[:start+offset].count("\n")+1
                        identity=f"{relative}:{line}:enum-variant:{name}.{variant.group(1)}"
                        bound=semantic_requirements("public_interface",identity,relative.as_posix(),requirements)
                        records.append(record("public_interface",identity,bound,relative.as_posix()))
                for container,start,end in rust_blocks(content,r"\bpub\s+(struct|trait)\s+([A-Za-z_][A-Za-z0-9_]*)[^\{;]*"):
                    kind,name=container.groups();body=content[start:end];base=content[:start].count("\n")+1
                    pattern=r"pub\s+([a-z_][A-Za-z0-9_]*)\s*:" if kind=="struct" else r"(?:type|fn|const)\s+([A-Za-z_][A-Za-z0-9_]*)"
                    for member in re.finditer(pattern,body):
                        line=base+body[:member.start()].count("\n")
                        identity=f"{relative}:{line}:{kind}-member:{name}.{member.group(1)}"
                        bound=semantic_requirements("public_interface",identity,relative.as_posix(),requirements)
                        records.append(record("public_interface",identity,bound,relative.as_posix()))
                for export in re.finditer(r"\bpub\s+use\s+([^;]+);",content):
                    line=content[:export.start()].count("\n")+1
                    records.append(record("public_interface",f"{relative}:{line}:re-export:{export.group(1).strip()}",requirements,relative.as_posix()))
                for invocation in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)!\s*[\(\{\[]\s*([A-Z][A-Za-z0-9_]*)\b",content):
                    macro,name=invocation.groups()
                    if re.search(rf"macro_rules!\s*{re.escape(macro)}\b",content) and "pub struct $name" in content:
                        line=content[:invocation.start()].count("\n")+1
                        records.append(record("public_interface",f"{relative}:{line}:macro-public-type:{name}",requirements,relative.as_posix()))
                        definition=content[content.find(f"macro_rules! {macro}"):invocation.start()]
                        for method in re.findall(r"pub\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)",definition):
                            records.append(record("public_interface",f"{relative}:{line}:macro-method:{name}.{method}",requirements,relative.as_posix()))
            if suffix==".py":
                tree=ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and not node.name.startswith("_"):
                        records.append(record("public_interface",f"{relative}:{node.lineno}:{node.name}",requirements,relative.as_posix()))
                    if isinstance(node,(ast.If,ast.Match,ast.Try,ast.For,ast.AsyncFor,ast.While)):
                        records.append(record("branch",f"{relative}:{node.lineno}:{type(node).__name__}",requirements,relative.as_posix()))
                    names=[]
                    if isinstance(node,ast.Import):names=[value.name.split('.')[0] for value in node.names]
                    elif isinstance(node,ast.ImportFrom) and node.module:names=[node.module.split('.')[0]]
                    for dependency in names:
                        identity=f"{relative}:{node.lineno}:python-import:{dependency}"
                        records.append(record("dependency",identity,requirements,relative.as_posix(),
                            f"AST import edge {dependency} at line {node.lineno}; removal makes this source import unresolved"))
                        if dependency not in PYTHON_ALLOWED:unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
            if relative.as_posix().startswith(("crates/habitat-models/","crates/habitat-harnesses/")):
                found=FORBIDDEN.search(content)
                if found: unresolved.append(f"forbidden-adapter-path:{relative}:{found.group(0)}")
        elif relative.as_posix().startswith(("crates/habitat-models/","crates/habitat-harnesses/")):
            found=FORBIDDEN.search(content)
            if found: unresolved.append(f"forbidden-adapter-path:{relative}:{found.group(0)}")
        if suffix in {".nix",".sh",".yml",".yaml"}:
            for number,line in enumerate(content.splitlines(),1):
                if SCRIPT_BRANCH.search(line) and not line.lstrip().startswith(("#","//")):
                    records.append(record("branch",f"{relative}:{number}:script-branch",requirements,relative.as_posix()))
        executable=suffix in {".rs",".py",".sh",".nix",".yml",".yaml"}
        test_or_policy=(relative.as_posix().startswith(("tests/","evidence/","contracts/","docs/"))
            or relative.as_posix()=="tools/audit_v2_core.py" or "/tests/" in relative.as_posix())
        production_source=executable and not test_or_policy
        found=next((match for match in AMBIENT.finditer(content)
            if not (relative.as_posix() in AMBIENT_EXEMPT and AMBIENT_EXEMPT[relative.as_posix()].fullmatch(match.group(0)))),None)
        if production_source and found:
            unresolved.append(f"ambient-core-path:{relative}:{found.group(0)}")
        if production_source and relative.as_posix() not in COMBINED_EXEMPT and SECRET_REFERENCE.search(content) and EXTERNAL_EFFECT.search(content):
            unresolved.append(f"secret-external-effect-path:{relative}")
        if relative.as_posix().startswith("crates/habitat-provider-transport/"):
            forbidden=PROVIDER_FORBIDDEN.search(content)
            if forbidden:unresolved.append(f"provider-direct-effect-path:{relative}:{forbidden.group(0)}")
        if production_source and re.search(rb"transcript",path.read_bytes(),re.I):
            unresolved.append(f"provider-transcript-authority-surface:{relative}")
        if path.name=="Cargo.toml":
            data=tomllib.loads(path.read_text())
            for section in ("dependencies","dev-dependencies","build-dependencies"):
                for dependency in sorted(data.get(section,{})):
                    records.append(record("dependency",f"{relative}:{section}:{dependency}",requirements,relative.as_posix(),
                        DEPENDENCY_PURPOSES.get(dependency)))
                    allowed=next((values for prefix,values in CARGO_ALLOWED.items() if relative.as_posix().startswith(prefix)),set())
                    if dependency not in allowed or dependency not in DEPENDENCY_PURPOSES:
                        unresolved.append(f"untrusted-dependency:{relative}:{dependency}")
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
    repository_digest=hashlib.sha256()
    for relative in sorted(repository_files):
        repository_digest.update(relative.encode()+b"\0"+(root/relative).read_bytes()+b"\0")
    counts={kind:sum(item["kind"]==kind for item in records) for kind in ("public_interface","branch","dependency","test","fixture")}
    return {"schema_version":1,"runner":{"name":"audit-v2-core","version":1},"scope_digest":digest.hexdigest(),
      "authority_catalog":{value:{key:REQUIREMENT_DETAILS[value][key] for key in
          ("source_authority","source_reference","trigger","shall","boundary","failure","enforcement")}
          for value in sorted({requirement for item in records for requirement in item["requirement_ids"]})},
      "counts":counts,"candidate_file_count":len(files),"unresolved_candidates":sorted(set(unresolved)),
      "repository_coverage":{"file_count":len(repository_files),"digest":repository_digest.hexdigest(),
          "self_excluded_artifact":self_artifact},
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
