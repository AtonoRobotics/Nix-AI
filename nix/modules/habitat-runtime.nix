{ config, lib, pkgs, ... }:
let
  cfg = config.habitat.runtime;
  components = [ "state" "scheduler" "authority" "effects" "abi" "runtime" ];
  dependencies = {
    state = [ "postgresql.service" "habitat-garage-initialize.service" ]; scheduler = [ "habitat-state.service" ];
    authority = [ "habitat-state.service" "habitat-scheduler.service" ];
    effects = [ "habitat-state.service" "habitat-scheduler.service" ];
    abi = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" ];
    runtime = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" "habitat-abi.service" ];
  };
  common = component: {
    description = "Habitat ${component} runtime service"; wantedBy = [ "multi-user.target" ];
    after = dependencies.${component}; wants = dependencies.${component}; restartTriggers = [ cfg.package ];
    serviceConfig = {
      Type = "simple"; User = "habitat-${component}"; Group = "habitat-${component}-clients";
      Restart = "on-failure"; RestartSec = "1s"; StartLimitBurst = 5;
      StateDirectory = "habitat/${component}"; StateDirectoryMode = "0700"; UMask = "0007";
      NoNewPrivileges = true; PrivateDevices = true; PrivateTmp = true; ProtectClock = true;
      ProtectControlGroups = true; ProtectHome = true; ProtectHostname = true; ProtectKernelLogs = true;
      ProtectKernelModules = true; ProtectKernelTunables = true; ProtectSystem = "strict";
      RestrictAddressFamilies = [ "AF_UNIX" ]; RestrictNamespaces = true; LockPersonality = true;
      MemoryDenyWriteExecute = true; CapabilityBoundingSet = ""; SystemCallArchitectures = "native";
      TasksMax = 64; MemoryMax = "256M"; CPUQuota = "100%";
      StandardOutput = "journal+console"; StandardError = "journal+console";
    };
  };
  runtimeUnit = component: lib.recursiveUpdate (common component) {
    serviceConfig.ExecStart = "${lib.getExe' cfg.package "habitat-runtime"} ${component} /run/habitat /var/lib/habitat/${component}";
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
      --allow-uid "$(${pkgs.coreutils}/bin/id -u habitat-abi)" \
      --allow-uid "$(${pkgs.coreutils}/bin/id -u habitat-scheduler)" \
      --allow-uid "$(${pkgs.coreutils}/bin/id -u habitat-authority)" \
      --allow-uid "$(${pkgs.coreutils}/bin/id -u habitat-effects)" \
      --allow-uid "$(${pkgs.coreutils}/bin/id -u habitat-runtime)"
  '';
  abiUnit = lib.recursiveUpdate (common "abi") {
    restartTriggers = [ cfg.abiPackage ];
    serviceConfig.ExecStart = abiStart;
    serviceConfig.LoadCredential = "activation-credential:${cfg.activationCredential}";
  };
  clientGroups = {
    state = [ "habitat-state-clients" ];
    scheduler = [ "habitat-state-clients" "habitat-scheduler-clients" ];
    authority = [ "habitat-state-clients" "habitat-scheduler-clients" "habitat-authority-clients" ];
    effects = [ "habitat-state-clients" "habitat-scheduler-clients" "habitat-effects-clients" ];
    abi = [ "habitat-state-clients" "habitat-scheduler-clients" "habitat-authority-clients" "habitat-effects-clients" "habitat-abi-clients" ];
    runtime = map (name: "habitat-${name}-clients") components;
  };
in {
  options.habitat.runtime = {
    enable = lib.mkEnableOption "the autonomous Habitat service graph";
    package = lib.mkOption { type = lib.types.package; description = "Package containing habitat-runtime."; };
    abiPackage = lib.mkOption { type = lib.types.package; description = "Package containing habitat-abi-server."; };
    statePackage = lib.mkOption { type = lib.types.package; description = "Package containing the PostgreSQL-backed habitat-state service."; };
    databaseCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
    objectStoreCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
    activationCredential = lib.mkOption { type = lib.types.strMatching "^/.*"; };
  };
  config = lib.mkIf cfg.enable {
    users.groups = lib.genAttrs (map (name: "habitat-${name}-clients") components) (_: { });
    users.users = lib.genAttrs (map (name: "habitat-${name}") components) (userName: let
      component = lib.removePrefix "habitat-" userName;
    in { isSystemUser = true; group = "habitat-${component}-clients"; extraGroups = clientGroups.${component}; });
    systemd.services = (lib.listToAttrs (map (component: lib.nameValuePair "habitat-${component}" (runtimeUnit component)) [ "scheduler" "authority" "effects" "runtime" ])) // {
      habitat-abi = abiUnit;
      habitat-state = lib.recursiveUpdate (common "state") {
        requires = dependencies.state;
        restartTriggers = [ cfg.statePackage ];
        serviceConfig.ExecStart = stateStart;
        serviceConfig.RestartMode = "direct";
        serviceConfig.LoadCredential = [ "database-url:${cfg.databaseCredential}" "object-store-url:${cfg.objectStoreCredential}" ];
        serviceConfig.RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
    };
    systemd.tmpfiles.rules = [ "d /run/habitat 0755 root root -" ] ++ map
      (component: "d /run/habitat/${component} 0750 habitat-${component} habitat-${component}-clients -") components;
  };
}
