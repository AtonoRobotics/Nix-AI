{ graph ? null }:
let
  canonical = {
    services = {
      state = { identity = "service:state"; unit = "habitat-state.service"; dependencies = [ "postgresql.target" "habitat-garage-initialize.service" ]; readiness = [ ]; credentials = [ "database" "objectStore" "effect" ]; clients = [ "service:abi" "service:scheduler" "service:authority" "service:effects" "service:packages" "service:runtime" ]; };
      scheduler = { identity = "service:scheduler"; unit = "habitat-scheduler.service"; dependencies = [ "habitat-state.service" ]; readiness = [ "state" ]; credentials = [ ]; clients = [ "service:runtime" ]; };
      authority = { identity = "service:authority"; unit = "habitat-authority.service"; dependencies = [ "habitat-state.service" "habitat-scheduler.service" ]; readiness = [ "state" "scheduler" ]; credentials = [ "authorityGrants" "authorityForwarding" ]; clients = [ "service:runtime" "service:effects" "service:operator" "service:reviewer" ]; };
      provider = { identity = "service:provider"; unit = "habitat-provider.service"; dependencies = [ ]; readiness = [ ]; credentials = [ ]; clients = [ "service:effects" ]; };
      effects = { identity = "service:effects"; unit = "habitat-effects.service"; dependencies = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-provider.service" ]; readiness = [ "state" "scheduler" "authority" "provider" ]; credentials = [ "effect" "database" ]; clients = [ "service:runtime" "service:operator" ]; };
      packages = { identity = "service:packages"; unit = "habitat-packages.service"; dependencies = [ "habitat-state.service" ]; readiness = [ "state" ]; credentials = [ "packageTrust" "packagePolicy" ]; clients = [ "service:runtime" ]; };
      abi = { identity = "service:abi"; unit = "habitat-abi.service"; dependencies = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" ]; readiness = [ "state" "scheduler" "authority" "effects" ]; credentials = [ "activation" ]; clients = [ "service:runtime" ]; };
      runtime = { identity = "service:runtime"; unit = "habitat-runtime.service"; dependencies = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" "habitat-packages.service" "habitat-abi.service" ]; readiness = [ "state" "scheduler" "authority" "effects" "packages" "abi" ]; credentials = [ "authorityForwarding" ]; clients = [ "service:operator" "service:runtime-conformance" ]; };
    };
    credentials = {
      authorityGrants = { option = "authorityGrants"; loadName = "grants"; };
      authorityForwarding = { option = "authorityForwardingCredential"; loadName = "authority-forwarding-key"; };
      database = { option = "databaseCredential"; loadName = "database-url"; };
      objectStore = { option = "objectStoreCredential"; loadName = "object-store-url"; };
      activation = { option = "activationCredential"; loadName = "activation-credential"; };
      effect = { option = "effectCredential"; loadName = "effect-token"; };
      packageTrust = { option = "packageTrust"; loadName = "package-trust"; };
      packagePolicy = { option = "packagePolicy"; loadName = "package-policy"; };
    };
    principals = [ "service:state" "service:scheduler" "service:authority" "service:provider" "service:effects" "service:packages" "service:abi" "service:runtime" "service:operator" "service:reviewer" "service:runtime-conformance" ];
  };
  value = if graph == null then canonical else graph;
  names = builtins.attrNames value.services;
  all = pred: xs: builtins.foldl' (ok: x: ok && pred x) true xs;
  unitOwner = unit: builtins.filter (n: value.services.${n}.unit == unit) names;
  internalUnits = builtins.filter (u: builtins.length (unitOwner u) > 0);
  typed = id: builtins.match "service:[a-z][a-z0-9-]*" id != null;
  knownIdentity = id: builtins.elem id value.principals;
  readinessMatches = n: builtins.sort builtins.lessThan value.services.${n}.readiness ==
    builtins.sort builtins.lessThan (map (u: builtins.head (unitOwner u)) (internalUnits value.services.${n}.dependencies));
  visit = path: n: if builtins.elem n path then false else all (visit (path ++ [ n ])) value.services.${n}.readiness;
  valid =
    all (n: typed value.services.${n}.identity && knownIdentity value.services.${n}.identity) names &&
    all (n: all knownIdentity value.services.${n}.clients) names &&
    all (n: all (c: builtins.hasAttr c value.credentials) value.services.${n}.credentials) names &&
    all (n: all (u: builtins.length (unitOwner u) == 1) (internalUnits value.services.${n}.dependencies)) names &&
    all readinessMatches names && all (visit [ ]) names;
in
assert valid;
value // {
  inherit names;
  dependencies = builtins.mapAttrs (_: service: service.dependencies) value.services;
  readiness = builtins.mapAttrs (_: service: service.readiness) value.services;
  clients = builtins.mapAttrs (_: service: service.clients) value.services;
  rustProjection = builtins.toJSON {
    readiness = builtins.mapAttrs (_: service: service.readiness) value.services;
  };
}
