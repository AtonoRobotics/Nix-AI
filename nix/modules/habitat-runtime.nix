{ config, lib, pkgs, ... }:
let
  cfg = config.habitat.runtime;
  components = [ "state" "scheduler" "authority" "effects" "abi" "runtime" ];
  unit = component: {
    description = "Habitat ${component} runtime service";
    wantedBy = [ "multi-user.target" ];
    after = cfg.dependencies.${component};
    requires = cfg.dependencies.${component};
    restartTriggers = [ cfg.package ];
    environment = lib.optionalAttrs (component == "state") {
      HABITAT_DATABASE_CREDENTIAL = "%d/database-url";
      HABITAT_OBJECT_STORE_CREDENTIAL = "%d/object-store-url";
    };
    serviceConfig = {
      Type = "simple";
      User = "habitat-${component}";
      Group = "habitat-runtime";
      ExecStart = "${lib.getExe cfg.package} ${component} /run/habitat /var/lib/habitat/${component}";
      Restart = "on-failure";
      RestartSec = "1s";
      StartLimitBurst = 5;
      RuntimeDirectory = "habitat";
      RuntimeDirectoryMode = "0770";
      RuntimeDirectoryPreserve = "yes";
      StateDirectory = "habitat/${component}";
      StateDirectoryMode = "0700";
      UMask = "0007";
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHome = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      ProtectSystem = "strict";
      RestrictAddressFamilies = [ "AF_UNIX" ];
      RestrictNamespaces = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      CapabilityBoundingSet = "";
      SystemCallArchitectures = "native";
      TasksMax = 64;
      MemoryMax = "256M";
      CPUQuota = "100%";
    } // lib.optionalAttrs (component == "state") {
      LoadCredential = [
        "database-url:${cfg.databaseCredential}"
        "object-store-url:${cfg.objectStoreCredential}"
      ];
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
    };
  };
in {
  options.habitat.runtime = {
    enable = lib.mkEnableOption "the autonomous Habitat service graph";
    package = lib.mkOption {
      type = lib.types.package;
      description = "Package containing the habitat-runtime executable.";
    };
    databaseCredential = lib.mkOption {
      type = lib.types.strMatching "^/.*";
      description = "Absolute path to a root-readable systemd credential containing the PostgreSQL URL; kept out of the Nix store.";
    };
    objectStoreCredential = lib.mkOption {
      type = lib.types.strMatching "^/.*";
      description = "Absolute path to a root-readable systemd credential containing the MinIO endpoint and credentials; kept out of the Nix store.";
    };
    dependencies = lib.mkOption {
      readOnly = true;
      default = {
        state = [ "postgresql.service" "minio.service" ];
        scheduler = [ "habitat-state.service" ];
        authority = [ "habitat-state.service" "habitat-scheduler.service" ];
        effects = [ "habitat-state.service" "habitat-scheduler.service" ];
        abi = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" ];
        runtime = [ "habitat-state.service" "habitat-scheduler.service" "habitat-authority.service" "habitat-effects.service" "habitat-abi.service" ];
      };
      description = "Fail-closed boot dependency graph.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.habitat-runtime = { };
    users.users = lib.genAttrs (map (name: "habitat-${name}") components) (_: {
      isSystemUser = true;
      group = "habitat-runtime";
    });
    systemd.services = lib.listToAttrs (map (component: lib.nameValuePair "habitat-${component}" (unit component)) components);
    systemd.tmpfiles.rules = [ "d /run/habitat 0770 root habitat-runtime -" ];
  };
}
