{ config, lib, pkgs, ... }:
let
  cfg = config.habitat.runtime;
  deploymentGraph = import ../lib/habitat-deployment-graph.nix { };
  components = deploymentGraph.names;
  dependencies = deploymentGraph.dependencies;
  principalUser = identity: let name = lib.removePrefix "service:" identity; in
    if name == "runtime-conformance" then "root" else "habitat-${name}";
  writePeers = component: ''
    peers=/run/habitat/${component}/peers.json
    printf '[]\n' > "$peers"
    ${lib.concatMapStringsSep "\n" (identity: let user = principalUser identity; in ''
      uid="$(${pkgs.coreutils}/bin/id -u ${user})"
      gid="$(${pkgs.coreutils}/bin/id -g ${user})"
      ${pkgs.jq}/bin/jq --arg service_id '${identity}' --argjson uid "$uid" --argjson gid "$gid" \
        '. + [{service_id:$service_id,uid:$uid,gid:$gid}]' "$peers" > "$peers.new"
      ${pkgs.coreutils}/bin/mv "$peers.new" "$peers"
    '') deploymentGraph.services.${component}.clients}
  '';
  loadCredentials = component: map (credential: let binding = deploymentGraph.credentials.${credential}; in
    "${binding.loadName}:${cfg.${binding.option}}") deploymentGraph.services.${component}.credentials;
  common = component: {
    description = "Habitat ${component} runtime service"; wantedBy = [ "multi-user.target" ];
    after = dependencies.${component}; wants = dependencies.${component}; restartTriggers = [ cfg.package ];
    serviceConfig = {
      Type = "simple"; User = "habitat-${component}"; Group = "habitat-${component}-clients";
      Restart = "on-failure"; RestartSec = "1s"; StartLimitBurst = 5;
      StateDirectory = "habitat/${component}"; StateDirectoryMode = "0700"; UMask = "0007";
      NoNewPrivileges = true; PrivateDevices = true; PrivateTmp = true; ProtectClock = true;
      ProtectProc = "default"; ProcSubset = "all";
      ProtectControlGroups = true; ProtectHome = true; ProtectHostname = true; ProtectKernelLogs = true;
      ProtectKernelModules = true; ProtectKernelTunables = true; ProtectSystem = "strict";
      RestrictAddressFamilies = [ "AF_UNIX" ]; RestrictNamespaces = true; LockPersonality = true;
      MemoryDenyWriteExecute = true; CapabilityBoundingSet = ""; SystemCallArchitectures = "native";
      TasksMax = 64; MemoryMax = "256M"; CPUQuota = "100%";
      StandardOutput = "journal+console"; StandardError = "journal+console";
    };
  };
  runtimeStart = component: pkgs.writeShellScript "habitat-${component}-start" ''
    set -eu
    ${writePeers component}
    exec ${lib.getExe' cfg.package "habitat-runtime"} ${component} /run/habitat \
      /var/lib/habitat/${component} /run/habitat/${component}/peers.json
  '';
  runtimeUnit = component: lib.recursiveUpdate (common component) {
    serviceConfig.ExecStart = runtimeStart component;
  };
  abiStart = pkgs.writeShellScript "habitat-abi-start" ''
    set -eu
    export HABITAT_ABI_ACTIVATION_CREDENTIAL="$(cat "$CREDENTIALS_DIRECTORY/activation-credential")"
    export HABITAT_ABI_PEER_UID="$(${pkgs.coreutils}/bin/id -u habitat-runtime)"
    exec ${cfg.abiPackage}/bin/habitat-abi-server /run/habitat/abi/abi.sock /run/habitat/state/state.sock
  '';
  stateStart = pkgs.writeShellScript "habitat-state-start" ''
    set -eu
    export HABITAT_DATABASE_URL="$(cat "$CREDENTIALS_DIRECTORY/database-url")"
    export HABITAT_OBJECT_STORE_CREDENTIAL="$CREDENTIALS_DIRECTORY/object-store-url"
    exec ${cfg.statePackage}/bin/habitat-state /run/habitat/state/state.sock \
      ${lib.concatMapStringsSep " \\\n      " (identity: let service = lib.removePrefix "service:" identity; in ''--allow-service "${identity}=$(${pkgs.coreutils}/bin/id -u ${principalUser identity}):$(${pkgs.coreutils}/bin/id -g ${principalUser identity}):habitat-${service}.service"'') deploymentGraph.services.state.clients} \
      --effect-uid "$(${pkgs.coreutils}/bin/id -u habitat-effects)" \
      --effect-token-credential "$CREDENTIALS_DIRECTORY/effect-token"
  '';
  authorityStart = pkgs.writeShellScript "habitat-authority-start" ''
    set -eu
    state_socket=/run/habitat/state/state.sock
    for attempt in $(${pkgs.coreutils}/bin/seq 1 300); do
      if [ -S "$state_socket" ]; then
        break
      fi
      ${pkgs.coreutils}/bin/sleep 0.1
    done
    if [ ! -S "$state_socket" ]; then
      echo "state socket did not become available" >&2
      exit 1
    fi
    ${writePeers "authority"}
    exec ${cfg.authorityPackage}/bin/habitat-authority \
      /run/habitat/authority/authority.sock \
      "$CREDENTIALS_DIRECTORY/grants" \
      /run/habitat/authority/peers.json \
      "$state_socket" \
      "$CREDENTIALS_DIRECTORY/authority-forwarding-key"
  '';
  effectsStart = pkgs.writeShellScript "habitat-effects-start" ''
    set -eu
    database_url="$(cat "$CREDENTIALS_DIRECTORY/database-url")"
    schema_ready=
    for attempt in $(${pkgs.coreutils}/bin/seq 1 300); do
      if ${config.services.postgresql.package}/bin/psql -XqAt \
        "$database_url" -c "SELECT 1 FROM effect_records LIMIT 0" >/dev/null 2>&1; then
        schema_ready=1
        break
      fi
      ${pkgs.coreutils}/bin/sleep 0.1
    done
    if [ -z "$schema_ready" ]; then
      echo "PostgreSQL effect schema did not become readable" >&2
      exit 1
    fi
    ${writePeers "effects"}
    exec ${cfg.effectsPackage}/bin/habitat-effects \
      /run/habitat/effects/effects.sock \
      /run/habitat/state/state.sock \
      /run/habitat/authority/authority.sock \
      /run/habitat/provider/provider.sock \
      /var/lib/habitat/effects/ledger.json \
      "$CREDENTIALS_DIRECTORY/effect-token" \
      "$CREDENTIALS_DIRECTORY/database-url" \
      "${config.services.postgresql.package}/bin/psql" \
      /run/habitat/effects/peers.json
  '';
  providerStart = pkgs.writeShellScript "habitat-provider-start" ''
    set -eu
    ${writePeers "provider"}
    exec ${cfg.executionPackage}/bin/habitat-execution \
      /run/habitat/provider/provider.sock /var/lib/habitat/provider \
      /run/habitat/provider/peers.json
  '';
  abiUnit = lib.recursiveUpdate (common "abi") {
    restartTriggers = [ cfg.abiPackage ];
    serviceConfig.ExecStart = abiStart;
    serviceConfig.LoadCredential = loadCredentials "abi";
  };
  clientGroups = lib.genAttrs components (component:
    [ "habitat-${component}-clients" ] ++ map (name: "habitat-${name}-clients")
      (builtins.filter (name: builtins.elem deploymentGraph.services.${component}.identity
        deploymentGraph.services.${name}.clients) components));
in {
  options.habitat.runtime = {
    enable = lib.mkEnableOption "the autonomous Habitat service graph";
    package = lib.mkOption { type = lib.types.package; description = "Package containing habitat-runtime."; };
    abiPackage = lib.mkOption { type = lib.types.package; description = "Package containing habitat-abi-server."; };
    statePackage = lib.mkOption { type = lib.types.package; description = "Package containing the PostgreSQL-backed habitat-state service."; };
    authorityPackage = lib.mkOption { type = lib.types.package; description = "Package containing the fail-closed habitat-authority service."; };
    effectsPackage = lib.mkOption { type = lib.types.package; description = "Package containing the durable habitat-effects service."; };
    executionPackage = lib.mkOption { type = lib.types.package; description = "Package containing the offline durable provider."; };
    authorityGrants = lib.mkOption { type = lib.types.path; description = "Explicitly provisioned runtime grants."; };
    authorityForwardingCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; description = "Runtime-to-authority forwarding MAC key."; };
    databaseCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
    objectStoreCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
    activationCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
    effectCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
  };
  config = lib.mkIf cfg.enable {
    users.groups = (lib.genAttrs (map (name: "habitat-${name}-clients") components) (_: { })) // {
      habitat-operator = { };
      habitat-reviewer = { };
    };
    users.users = (lib.genAttrs (map (name: "habitat-${name}") components) (userName: let
      component = lib.removePrefix "habitat-" userName;
    in { isSystemUser = true; group = "habitat-${component}-clients"; extraGroups = clientGroups.${component}; })) // {
      habitat-operator = {
        isSystemUser = true;
        group = "habitat-operator";
        extraGroups = [
          "habitat-authority-clients"
          "habitat-effects-clients"
          "habitat-runtime-clients"
        ];
      };
      habitat-reviewer = { isSystemUser = true; group = "habitat-reviewer"; extraGroups = [ "habitat-authority-clients" ]; };
    };
    systemd.services = (lib.listToAttrs (map (component: lib.nameValuePair "habitat-${component}" (runtimeUnit component)) [ "scheduler" "runtime" ])) // {
      habitat-authority = lib.recursiveUpdate (common "authority") {
        restartTriggers = [ cfg.authorityPackage cfg.authorityGrants ];
        serviceConfig.ExecStart = authorityStart;
        serviceConfig.LoadCredential = loadCredentials "authority";
      };
      habitat-effects = lib.recursiveUpdate (common "effects") {
        restartTriggers = [ cfg.effectsPackage ];
        unitConfig = {
          BindsTo = [ "habitat-state.service" ];
          PartOf = [ "habitat-state.service" ];
        };
        serviceConfig.ExecStart = effectsStart;
        serviceConfig.LoadCredential = loadCredentials "effects";
        serviceConfig.RestrictAddressFamilies = [ "AF_UNIX" ];
      };
      habitat-provider = lib.recursiveUpdate (common "provider") {
        restartTriggers = [ cfg.executionPackage ];
        serviceConfig.ExecStart = providerStart;
      };
      habitat-abi = abiUnit;
      habitat-state = lib.recursiveUpdate (common "state") {
        requires = dependencies.state;
        # A fresh state listener must also bring back effects after BindsTo
        # detached it from the old socket. Upholds is declarative and bounded;
        # it does not add a process-local restart loop.
        unitConfig.Upholds = [ "habitat-effects.service" ];
        restartTriggers = [ cfg.statePackage ];
        serviceConfig.ExecStart = stateStart;
        serviceConfig.RestartMode = "direct";
        serviceConfig.LoadCredential = loadCredentials "state";
        serviceConfig.RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
      habitat-runtime = lib.recursiveUpdate (runtimeUnit "runtime") {
        serviceConfig.LoadCredential = loadCredentials "runtime";
      };
    };
    systemd.tmpfiles.rules = [ "d /run/habitat 0755 root root -" ] ++ map
      (component: "d /run/habitat/${component} 0750 habitat-${component} habitat-${component}-clients -") components;
  };
}
