# Gates: Governance integration

Scope: Audit, issues, evidence, and source identity agree.

- [x] G1: Both immutable contract validators pass.
  CHECK: python3 contracts/v2/validate_contract.py && python3 contracts/v2.0.1/validate_contract.py
  EXPECT: /"valid": true/
  EVIDENCE: "work_packet_count": 14 | }

