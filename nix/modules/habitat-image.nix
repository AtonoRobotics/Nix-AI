{ config, lib, pkgs, ... }:
let
  profile = builtins.fromJSON (builtins.readFile ../profiles/qemu-x86_64-conformance.json);
  role = config.habitat.generationRole;
  generationId = builtins.substring 0 32 (builtins.hashString "sha256" "${config.system.nixos.version}:${role}");
  emitBootstrap = pkgs.writeShellApplication {
    name = "habitat-bootstrap";
    runtimeInputs = [ pkgs.coreutils pkgs.findutils pkgs.jq pkgs.systemd ];
    text = ''
      set -euo pipefail
      install -d -m 0700 /var/lib/habitat/boot-history /srv/habitat /var/lib/habitat/activations
      machine_id="$(cat /etc/machine-id)"
      attempt_id="$(cat /proc/sys/kernel/random/uuid)"
      previous="$(cat /var/lib/habitat/previous-generation 2>/dev/null || printf 'none')"
      generation_role='${role}'
      history_count="$(find /var/lib/habitat/boot-history -maxdepth 1 -name '*.json' | wc -l)"
      operational_state="$(cat /var/lib/habitat/operational-state 2>/dev/null || printf 'none')"
      store_protected=true
      recovery_protected=true
      if touch /nix/store/.habitat-write-test 2>/dev/null; then rm -f /nix/store/.habitat-write-test; store_protected=false; fi
      if touch /run/habitat-recovery/.habitat-write-test 2>/dev/null; then rm -f /run/habitat-recovery/.habitat-write-test; recovery_protected=false; fi
      decision=UNCONFIRMED
      if [ "$generation_role" = candidate ]; then
        decision=ACTIVE_UNCONFIRMED
        printf '%s\n' "$attempt_id" > /var/lib/habitat/candidate-attempt
      elif [ -e /var/lib/habitat/candidate-attempt ]; then
        decision=ROLLED_BACK
      fi
      record="$(jq -cn \
        --arg machine_id "$machine_id" \
        --arg generation_id '${generationId}' \
        --arg closure_digest 'sha256:${builtins.hashString "sha256" "${config.system.nixos.version}:${role}"}' \
        --arg profile_id '${profile.profile_id}' \
        --arg boot_attempt_id "$attempt_id" \
        --arg previous_confirmed_generation_id "$previous" \
        --arg decision "$decision" \
        --arg generation_role '${role}' \
        --argjson history_count "$history_count" \
        --arg operational_state "$operational_state" \
        --argjson store_protected "$store_protected" \
        --argjson recovery_protected "$recovery_protected" \
        '{schema_version:"1.0",event:"habitat.bootstrap",machine_id:$machine_id,system_generation_id:$generation_id,closure_digest:$closure_digest,hardware_profile_id:$profile_id,boot_attempt_id:$boot_attempt_id,previous_confirmed_generation_id:$previous_confirmed_generation_id,bootstrap_phase:"reconciliation",health_result:"PRE_OPERATIONAL",decision:$decision,generation_role:$generation_role,history_count:$history_count,operational_state:$operational_state,protections:{nix_store_read_only:$store_protected,recovery_read_only:$recovery_protected}}')"
      printf '%s\n' "$record" > "/var/lib/habitat/boot-history/$attempt_id.json"
      printf '%s\n' '${generationId}' > /var/lib/habitat/active-generation
      printf '%s\n' 'PRE_OPERATIONAL' > /var/lib/habitat/readiness
      sync
      printf '%s\n' "$record"
    '';
  };
in {
  options.habitat.generationRole = lib.mkOption {
    type = lib.types.enum [ "baseline" "candidate" "recovery" ];
    default = "baseline";
    description = "Generation role recorded in boot evidence.";
  };

  config = {
  boot.kernelPackages = pkgs.linuxPackages_6_12;
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = 8;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.uki.tries = lib.mkDefault null;
  boot.kernelParams = [ "console=ttyS0,115200n8" "panic=-1" ];

  networking.hostName = lib.mkDefault "habitat";
  networking.useDHCP = false;
  services.getty.autologinUser = lib.mkForce null;
  systemd.services."getty@tty1".enable = false;
  systemd.services."serial-getty@ttyS0".enable = false;
  services.openssh.enable = false;
  users.mutableUsers = false;
  # Deliberate appliance lockout: no getty, SSH, password, or authorized key exists.
  users.allowNoPasswordLogin = true;
  users.users.root.hashedPassword = "!";
  documentation.enable = false;
  services.logrotate.enable = false;
  environment.defaultPackages = lib.mkForce [ ];
  programs.command-not-found.enable = false;
  nix.enable = false;

  systemd.services.habitat-bootstrap = {
    description = "Habitat pre-operational bootstrap reconciliation";
    wantedBy = [ "multi-user.target" ];
    after = [ "local-fs.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe emitBootstrap;
      User = "root";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/var/lib/habitat" "/srv/habitat" ];
      UMask = "0077";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  systemd.services.habitat-stage-candidate = lib.mkIf (role == "baseline") {
    description = "Install the boot-counted W01 qualification candidate";
    wantedBy = [ "multi-user.target" ];
    after = [ "habitat-bootstrap.service" "boot.mount" ];
    requires = [ "habitat-bootstrap.service" ];
    unitConfig.ConditionPathExists = "!/var/lib/habitat/candidate-staged";
    script = ''
      set -euo pipefail
      install -m 0600 /boot/EFI/Linux/habitat-candidate.efi.staged /boot/EFI/Linux/habitat-candidate+1.efi
      ${pkgs.systemd}/bin/bootctl set-oneshot habitat-candidate+1.efi
      printf 'baseline-durable-state\n' > /var/lib/habitat/operational-state
      printf '%s\n' '${generationId}' > /var/lib/habitat/previous-generation
      touch /var/lib/habitat/candidate-staged
      record='{"schema_version":"1.0","event":"habitat.generation.candidate_installed","candidate":"habitat-candidate+1.efi","tries":1}'
      printf '%s\n' "$record" > /var/lib/habitat/candidate-installed.json
      sync
      printf '%s\n' "$record" > /dev/ttyS0
    '';
    serviceConfig = {
      Type = "oneshot";
      NoNewPrivileges = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/boot" "/var/lib/habitat" ];
    };
  };

  systemd.services.habitat-reject-unconfirmed-candidate = lib.mkIf (role == "candidate") {
    description = "Reject the deliberately non-confirming W01 candidate";
    wantedBy = [ "multi-user.target" ];
    after = [ "habitat-bootstrap.service" "boot.mount" ];
    requires = [ "habitat-bootstrap.service" ];
    script = ''
      set -euo pipefail
      failed=false
      for entry in /boot/EFI/Linux/habitat-candidate+*.efi; do
        if [ -e "$entry" ]; then
          mv "$entry" "$entry.failed"
          failed=true
        fi
      done
      [ "$failed" = true ]
      printf 'default habitat_1.0.0.efi\ntimeout 0\nconsole-mode keep\n' > /boot/loader/loader.conf
      record='{"schema_version":"1.0","event":"habitat.generation.candidate_rejected","reason":"confirmation_withheld","fallback":"habitat_1.0.0.efi"}'
      printf '%s\n' "$record" > /var/lib/habitat/candidate-rejected.json
      sync
      printf '%s\n' "$record" > /dev/ttyS0
    '';
    serviceConfig = {
      Type = "oneshot";
      NoNewPrivileges = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/boot" "/var/lib/habitat" ];
    };
  };

  systemd.tmpfiles.rules = [
    # Dedicated service state leaves remain 0700.  The shared root must be
    # traverse-only so those service users can reach their systemd-owned leaf.
    "d /var/lib/habitat 0711 root root -"
    "d /srv/habitat 0750 root root -"
  ];

  environment.etc."habitat/hardware-profile.json".source = ../profiles/qemu-x86_64-conformance.json;
  environment.etc."habitat/generation-id".text = generationId + "\n";
  environment.etc."habitat/generation-manifest.json".text = builtins.toJSON {
    schema_version = "1.0";
    generation_id = generationId;
    generation_role = role;
    closure_digest = "sha256:${builtins.hashString "sha256" "${config.system.nixos.version}:${role}"}";
    hardware_profile_id = profile.profile_id;
    confirmation_policy = if role == "candidate" then "explicit-habitat-health-gate" else "retained-fallback";
  } + "\n";
  system.stateVersion = "26.05";
  };
}
