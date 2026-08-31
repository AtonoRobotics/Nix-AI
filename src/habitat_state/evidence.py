"""Content-addressed Garage evidence adapter."""
import hashlib
import json
from pathlib import Path

import boto3
from botocore.config import Config

from .errors import EvidenceNotFound, LedgerCorrupt, LedgerUnavailable


class GarageEvidenceAdapter:
    """Byte-oriented Garage adapter for authoritative evidence references."""
    def __init__(self, client, bucket): self.client, self.bucket = client, bucket
    @classmethod
    def from_urls(cls, endpoint, access_key, secret_key, bucket, region="us-east-1"):
        client=boto3.client("s3",endpoint_url=endpoint,aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,region_name=region,
            config=Config(signature_version="s3v4",s3={"addressing_style":"path"}))
        return cls(client,bucket)
    def ensure_bucket(self):
        try:self.client.list_objects_v2(Bucket=self.bucket,MaxKeys=1)
        except Exception as error: raise LedgerUnavailable("evidence bucket unavailable") from error
    def put_content(self,key,content,metadata=None):
        expected=metadata or {}
        try:self.client.put_object(Bucket=self.bucket,Key=key,Body=content,Metadata=expected,IfNoneMatch="*")
        except Exception as error:
            code=getattr(error,"response",{}).get("Error",{}).get("Code")
            if code not in ("PreconditionFailed","412"): raise LedgerUnavailable("evidence write unavailable") from error
        head=self.client.head_object(Bucket=self.bucket,Key=key)
        stored=self.client.get_object(Bucket=self.bucket,Key=key)["Body"].read()
        if head.get("Metadata",{})!=expected or head.get("ContentLength")!=len(content) or stored!=content:
            raise LedgerCorrupt("immutable evidence object conflicts with canonical bytes")
        return stored
    def get_content(self,key):
        try:
            head=self.client.head_object(Bucket=self.bucket,Key=key)
            return head["ContentLength"],self.client.get_object(Bucket=self.bucket,Key=key)["Body"].read()
        except self.client.exceptions.NoSuchKey as error: raise EvidenceNotFound(key) from error
        except Exception as error:
            code=getattr(error,"response",{}).get("Error",{}).get("Code")
            if code in ("404","NoSuchKey","NotFound"): raise EvidenceNotFound(key) from error
            raise LedgerUnavailable("evidence object store unavailable") from error
    def clear(self):
        listed=self.client.list_objects_v2(Bucket=self.bucket).get("Contents",[])
        if listed:self.client.delete_objects(Bucket=self.bucket,Delete={"Objects":[{"Key":item["Key"]} for item in listed]})


class EvidenceStore:
    def __init__(self, credential_path, admission=None):
        try:
            config = json.loads(Path(credential_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LedgerUnavailable("object-store credential is unavailable") from error
        required = ("endpoint", "access_key", "secret_key", "bucket", "region")
        if any(not isinstance(config.get(key), str) or not config[key] for key in required):
            raise LedgerUnavailable("object-store credential is incomplete")
        self.admission=admission
        self.adapter=GarageEvidenceAdapter.from_urls(config["endpoint"],config["access_key"],
            config["secret_key"],config["bucket"],config["region"]); self.bucket=config["bucket"]
        try: self.adapter.client.list_objects_v2(Bucket=self.bucket,MaxKeys=1)
        except Exception as error: raise LedgerUnavailable("evidence object store unavailable") from error

    def put(self, record):
        content = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(content).hexdigest(); key = f"sha256/{digest}"
        try:
            stored=self.adapter.put_content(key,content,{"sha256":digest})
        except Exception as error: raise LedgerUnavailable("evidence write or verification failed") from error
        if hashlib.sha256(stored).hexdigest() != digest or stored != content:
            raise LedgerCorrupt("evidence bytes do not match committed digest")
        return f"s3://{self.bucket}/{key}"

    def put_envelope(self,envelope,principal,command_id=None):
        required={"schema_version","producer","subject","operation","source","payload"}
        if not isinstance(envelope,dict) or set(envelope)!=required:
            raise LedgerCorrupt("evidence envelope fields are not canonical")
        if envelope["schema_version"]!="1" or envelope["producer"]!=principal:
            raise LedgerCorrupt("evidence producer is not the authenticated service")
        if not all(isinstance(envelope[key],str) and envelope[key] for key in ("subject","operation","source")):
            raise LedgerCorrupt("evidence identity fields are required")
        if ":" not in envelope["subject"] or len(envelope["subject"])>256:
            raise LedgerCorrupt("evidence subject identity is malformed")
        if envelope["source"].startswith("sha256:") and (len(envelope["source"])!=71
                or any(character not in "0123456789abcdef" for character in envelope["source"][7:])):
            raise LedgerCorrupt("evidence source digest is malformed")
        if not isinstance(envelope["payload"],dict): raise LedgerCorrupt("evidence payload must be an object")
        families={
          "service:authority":("authority.",("sha256:",)),
          "service:effects":("effect.",("provider://","sha256:")),
          "service:runtime":(("change.","package."),("sha256:","generation:")),
          "service:abi":("command.",("sha256:",)),
          "service:controller":(("change.","package."),("sha256:","generation:")),
          "service:packages":("package.",( "sha256:",)),
          "service:evaluator":("change.",("sha256:",)),
          "service:signer":("change.",("sha256:",)),
          "service:health":("change.",("sha256:","generation:")),
        }
        family,sources=families.get(principal,(None,()))
        families_allowed=family if isinstance(family,tuple) else (family,)
        if family is None or not envelope["operation"].startswith(families_allowed) or not envelope["source"].startswith(sources):
            raise LedgerCorrupt("evidence operation or source is outside service authority")
        content=json.dumps(envelope,sort_keys=True,separators=(",", ":")).encode()
        digest=hashlib.sha256(content).hexdigest()
        admission=getattr(self,"admission",None)
        if admission is not None:
            if not isinstance(command_id,str) or not command_id:raise LedgerCorrupt("evidence command identity is required")
            replay=admission.reserve_evidence(principal,command_id,digest)
            if replay:return {"evidence_ref":replay,"sha256":replay.rsplit("/",1)[-1]}
        reference=self.put(envelope)
        if admission is not None:admission.finalize_evidence(principal,command_id,digest,reference)
        if self.verify(reference)!=json.dumps(envelope,sort_keys=True,separators=(",", ":")).encode():
            raise LedgerCorrupt("evidence read-back differs from canonical envelope")
        return {"evidence_ref":reference,"sha256":reference.rsplit("/",1)[-1]}

    def verify(self, evidence_ref):
        prefix = f"s3://{self.bucket}/sha256/"
        if not isinstance(evidence_ref, str) or not evidence_ref.startswith(prefix):
            raise LedgerCorrupt("evidence reference is not digest addressed")
        digest = evidence_ref.removeprefix(prefix)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise LedgerCorrupt("evidence reference digest is malformed")
        _,stored=self.adapter.get_content(f"sha256/{digest}")
        if hashlib.sha256(stored).hexdigest() != digest:
            raise LedgerCorrupt("evidence bytes do not match address digest")
        return stored

    def verify_record(self,evidence_ref,*,subject,producer,source,operation=None,disposition=None):
        raw=self.verify(evidence_ref)
        try: record=json.loads(raw)
        except (UnicodeDecodeError,json.JSONDecodeError) as error: raise LedgerCorrupt("evidence is not JSON") from error
        if not isinstance(record,dict): raise LedgerCorrupt("evidence must be a JSON object")
        expected={"subject":subject,"producer":producer,"source":source}
        if operation is not None:expected["operation"]=operation
        if any(record.get(key)!=value for key,value in expected.items()):
            raise LedgerCorrupt("evidence binding mismatch")
        if disposition is not None and record.get("payload",{}).get("disposition")!=disposition:
            raise LedgerCorrupt("evidence disposition mismatch")
        return record
