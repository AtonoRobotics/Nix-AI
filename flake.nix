{
  description = "Habitat OS contract toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      rustSource = pkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: _type:
          let relative = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
          in relative == "Cargo.toml" || relative == "Cargo.lock"
            || relative == "crates" || pkgs.lib.hasPrefix "crates/" relative
            || relative == "contracts" || relative == "contracts/proto"
            || pkgs.lib.hasPrefix "contracts/proto/" relative;
      };
      pythonStateSource = pkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: _type:
          let relative = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
          in relative == "pyproject.toml"
            || relative == "src" || pkgs.lib.hasPrefix "src/" relative;
      };
      runtimeCredentials = pkgs.writeShellApplication {
        name = "habitat-runtime-credentials";
        runtimeInputs = [ pkgs.coreutils ];
        text = ''
          set -euo pipefail
          umask 0077
          credential_dir=/run/habitat-credentials
          token_dir=/var/lib/habitat/credentials
          token_file="$token_dir/runtime-token"
          install -d -m 0700 "$credential_dir"
          install -d -m 0700 "$token_dir"
          if [ ! -s "$token_file" ]; then
            token="$(tr -d '-' </proc/sys/kernel/random/uuid)$(tr -d '\n' </etc/machine-id)"
            printf '%s\n' "$token" > "$token_file.new"
            chmod 0600 "$token_file.new"
            mv "$token_file.new" "$token_file"
            sync "$token_file"
          fi
          token="$(cat "$token_file")"
          password="$(printf '%s' "$token" | sha256sum | cut -d ' ' -f 1)"
          access_key="GK$(printf '%s' "$token" | sha256sum | cut -c1-24)"
          verifier_secret="$(printf 'verifier:%s' "$token" | sha256sum | cut -d ' ' -f 1)"
          verifier_access="GK$(printf 'verifier:%s' "$token" | sha256sum | cut -c1-24)"
          printf 'GARAGE_RPC_SECRET=%s\n' "$password" > "$credential_dir/garage.env"
          printf 'postgresql:///habitat-state?host=/run/postgresql\n' > "$credential_dir/database-url"
          printf '{"endpoint":"http://127.0.0.1:9000","access_key":"%s","secret_key":"%s","bucket":"habitat-evidence","region":"garage"}\n' \
            "$access_key" "$password" > "$credential_dir/object-store-url"
          printf '{"endpoint":"http://127.0.0.1:9000","access_key":"%s","secret_key":"%s","bucket":"habitat-evidence","region":"garage"}\n' \
            "$verifier_access" "$verifier_secret" > "$credential_dir/verifier-object-store-url"
          printf '%s\n' "$token" > "$credential_dir/abi-activation"
          printf '%s\n' "$(printf 'effect-admission:%s' "$token" | sha256sum | cut -d ' ' -f 1)" \
            > "$credential_dir/effect-token"
          printf '%s\n' "$(printf 'authority-forwarding:%s' "$token" | sha256sum | cut -d ' ' -f 1)" \
            > "$credential_dir/authority-forwarding-key"
          chmod 0400 "$credential_dir"/*
        '';
      };
      garageInitialize = pkgs.writeShellApplication {
        name = "habitat-garage-initialize";
        runtimeInputs = [ pkgs.coreutils pkgs.garage pkgs.gnugrep pkgs.jq ];
        text = ''
          set -euo pipefail
          GARAGE_RPC_SECRET="$(sed -n 's/^GARAGE_RPC_SECRET=//p' /run/habitat-credentials/garage.env)"
          export GARAGE_RPC_SECRET

          status_file="$(mktemp)"
          trap 'rm -f "$status_file"' EXIT
          for attempt in $(seq 1 300); do
            if garage status >"$status_file" 2>&1; then
              break
            fi
            test "$attempt" -lt 300 || {
              echo 'Garage RPC did not become ready' >&2
              cat "$status_file" >&2
              exit 1
            }
            sleep 0.1
          done

          node_id="$(garage node id | grep -Eo '[0-9a-f]{64}@' | head -n1 | tr -d '@')"
          test -n "$node_id"
          if grep -q 'NO ROLE ASSIGNED' "$status_file"; then
            garage layout assign --zone local --capacity 1G "$node_id"
            garage layout apply --version 1
          fi

          access_key="$(jq -r .access_key /run/habitat-credentials/object-store-url)"
          secret_key="$(jq -r .secret_key /run/habitat-credentials/object-store-url)"
          if ! garage key info habitat >/dev/null 2>&1; then
            garage key import --yes -n habitat "$access_key" "$secret_key"
          fi
          if ! garage bucket info habitat-evidence >/dev/null 2>&1; then
            garage bucket create habitat-evidence
          fi
          garage bucket allow --read --write --owner --key habitat habitat-evidence
          verifier_access="$(jq -r .access_key /run/habitat-credentials/verifier-object-store-url)"
          verifier_secret="$(jq -r .secret_key /run/habitat-credentials/verifier-object-store-url)"
          if ! garage key info habitat-verifier >/dev/null 2>&1; then
            garage key import --yes -n habitat-verifier "$verifier_access" "$verifier_secret"
          fi
          garage bucket allow --read --key habitat-verifier habitat-evidence
        '';
      };
      runtimeConformance = pkgs.replaceVars ./nix/tests/habitat_runtime_conformance.py.in {
        systemctl = "${pkgs.systemd}/bin/systemctl";
      };
      runtimeLiveProbe = pkgs.replaceVars ./nix/tests/habitat_runtime_live.py.in {
        systemctl = "${pkgs.systemd}/bin/systemctl";
        systemd_run = "${pkgs.systemd}/bin/systemd-run";
        operator = "${habitatAuthority}/bin/habitat-authority";
        psql = "${pkgs.postgresql_17}/bin/psql";
        runuser = "${pkgs.util-linux}/bin/runuser";
      };
      changeLiveProbe = pkgs.replaceVars ./nix/tests/habitat_change_live.py.in {
        systemctl = "${pkgs.systemd}/bin/systemctl";
        initial_generation = "generation:${habitatRuntime}";
      };
      runtimeAuthorityGrants = pkgs.writeText "habitat-runtime-grants.json" (builtins.toJSON [{
        grant_id = "grant:runtime-conformance";
        issuer = "service:operator";
        independent_approver = "operator:release";
        machine_id = "machine:local";
        service_id = "service:runtime";
        activation_id = "activation:runtime";
        capability = "runtime.effect";
        operation = "commit";
        target_prefix = "objective:qemu-";
        generation = "generation:current";
        state_version = "state:current";
        quota = 1000;
        remaining_delegation_depth = 1;
        parent_grant_id = null;
        not_before = 1;
        expires_at = 4102444800;
      } {
        grant_id = "grant:runtime-compensation";
        issuer = "service:operator";
        independent_approver = "operator:release";
        machine_id = "machine:local";
        service_id = "service:runtime";
        activation_id = "activation:runtime";
        capability = "runtime.effect";
        operation = "compensate";
        target_prefix = "effect:sha256:";
        generation = "generation:current";
        state_version = "state:current";
        quota = 1000;
        remaining_delegation_depth = 0;
        parent_grant_id = null;
        not_before = 1;
        expires_at = 4102444800;
      }]);
      runtimePackageTrust = pkgs.writeText "habitat-package-trust.json" (builtins.toJSON {
        "publisher:conformance" = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
      });
      runtimePackagePolicy = pkgs.writeText "habitat-package-policy.json" (builtins.toJSON {
        allowed_authority = [ "runtime.effect" ];
        max_memory_bytes = 268435456;
        max_cpu_millis = 1000;
        execution_profiles = [ "isolated" ];
        abi_version = "V2.0.1";
      });
      runtimeConfiguration = {
        services.postgresql = {
          enable = true;
          package = pkgs.postgresql_17;
          ensureDatabases = [ "habitat-state" ];
          ensureUsers = [
            { name = "habitat-state"; ensureDBOwnership = true; }
            { name = "habitat-effects"; }
            { name = "habitat-verifier"; }
          ];
        };
        users.groups.habitat-verifier = { };
        users.users.habitat-verifier = {
          isSystemUser = true;
          group = "habitat-verifier";
        };
        services.garage = {
          enable = true;
          package = pkgs.garage;
          environmentFile = "/run/habitat-credentials/garage.env";
          settings = {
            db_engine = "sqlite";
            replication_factor = 1;
            rpc_bind_addr = "127.0.0.1:3901";
            rpc_public_addr = "127.0.0.1:3901";
            s3_api = {
              s3_region = "garage";
              api_bind_addr = "127.0.0.1:9000";
              root_domain = ".s3.garage";
            };
          };
        };
        systemd.services.habitat-runtime-credentials = {
          description = "Create ephemeral Habitat runtime credentials";
          wantedBy = [ "multi-user.target" ];
          before = [ "garage.service" "habitat-state.service" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${runtimeCredentials}/bin/habitat-runtime-credentials";
            RemainAfterExit = true;
          };
        };
        systemd.services.garage = {
          after = [ "habitat-runtime-credentials.service" ];
          requires = [ "habitat-runtime-credentials.service" ];
        };
        systemd.services.habitat-garage-initialize = {
          description = "Initialize the Habitat Garage layout, key, and evidence bucket";
          wantedBy = [ "multi-user.target" ];
          after = [ "garage.service" ];
          requires = [ "garage.service" ];
          before = [ "habitat-state.service" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${garageInitialize}/bin/habitat-garage-initialize";
            RemainAfterExit = true;
          };
        };
        systemd.services.habitat-runtime-conformance = {
          description = "Exercise a live objective and verify durable evidence";
          wantedBy = [ "multi-user.target" ];
          after = [ "habitat-runtime.service" ];
          wants = [ "habitat-runtime.service" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${python}/bin/python ${runtimeConformance}";
            LoadCredential = "object-store:/run/habitat-credentials/object-store-url";
            NoNewPrivileges = true;
            PrivateTmp = true;
            ProtectHome = true;
            ProtectSystem = "strict";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
        };
        systemd.services.habitat-state.environment.HABITAT_TEST_FAULTS = "1";
        systemd.services.habitat-effects.environment.HABITAT_TEST_FAULTS = "1";
        habitat.runtime = {
          enable = true;
          package = habitatRuntime;
          abiPackage = habitatAbi;
          statePackage = habitatState;
          authorityPackage = habitatAuthority;
          effectsPackage = habitatEffects;
          executionPackage = habitatExecution;
          packagesPackage = habitatPackages;
          authorityGrants = runtimeAuthorityGrants;
          authorityForwardingCredential = "/run/habitat-credentials/authority-forwarding-key";
          databaseCredential = "/run/habitat-credentials/database-url";
          objectStoreCredential = "/run/habitat-credentials/object-store-url";
          activationCredential = "/run/habitat-credentials/abi-activation";
          effectCredential = "/run/habitat-credentials/effect-token";
          packageTrust = runtimePackageTrust;
          packagePolicy = runtimePackagePolicy;
        };
      };
      habitatSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nix/profiles/qemu-x86_64-conformance.nix
          ./nix/images/habitat-raw.nix
          runtimeConfiguration
        ];
      };
      candidateSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nix/profiles/qemu-x86_64-conformance.nix
          ./nix/images/habitat-raw.nix
          runtimeConfiguration
          {
            habitat.generationRole = "candidate";
            boot.uki.tries = 1;
            boot.kernelParams = [ "habitat.candidate=non-confirming" ];
            systemd.services.systemd-bless-boot.enable = false;
          }
        ];
      };
      recoverySystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nix/profiles/qemu-x86_64-conformance.nix
          ./nix/images/habitat-raw.nix
          runtimeConfiguration
          {
            habitat.generationRole = "recovery";
            networking.hostName = "habitat-recovery";
          }
        ];
      };
      python = pkgs.python3.withPackages (ps: [ ps.boto3 ps.jsonschema ps.psycopg ps.pyyaml ]);
      contractTools = with pkgs; [
        buf
        cargo
        clippy
        coreutils
        gitMinimal
        jq
        nixfmt
        protobuf
        protoc-gen-prost
        python
        rustc
        rustfmt
        shellcheck
      ];
      validateContracts = pkgs.writeShellApplication {
        name = "validate-contracts";
        runtimeInputs = contractTools;
        text = ''
          exec ${python}/bin/python ${./tools/validate_contracts.py} ${self}
        '';
      };
      generateProto = pkgs.writeShellApplication {
        name = "generate-proto";
        runtimeInputs = contractTools;
        text = ''
          exec ${python}/bin/python ${./tools/proto_contracts.py} ${self} --write
        '';
      };
      qualifyW00 = pkgs.writeShellApplication {
        name = "qualify-w00";
        runtimeInputs = contractTools;
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w00.py} ${self} "$@"
        '';
      };
      qualifyW02 = pkgs.writeShellApplication {
        name = "qualify-w02";
        runtimeInputs = [ pkgs.docker-client pkgs.garage python ];
        text = ''
          export PYTHONPATH=${./src}
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w02.py} "$@"
        '';
      };
      testAllPython = pkgs.writeShellApplication {
        name = "test-all-python";
        runtimeInputs = contractTools ++ [ pkgs.docker-client pkgs.garage python ];
        text = ''
          export PYTHONPATH=${./src}
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/test_all_python.py} "$@"
        '';
      };
      habitatState = pkgs.python3Packages.buildPythonPackage {
        pname = "habitat-state";
        version = "0.1.0";
        pyproject = true;
        src = pythonStateSource;
        build-system = [ pkgs.python3Packages.setuptools ];
        dependencies = with pkgs.python3Packages; [ boto3 psycopg ];
        doCheck = false;
      };
      habitatAbi = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-abi";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [ pkgs.protobuf ];
        cargoBuildFlags = [ "-p" "habitat-abi" ];
        cargoTestFlags = [ "-p" "habitat-abi" ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };
      habitatAuthority = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-authority";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-authority" ];
        cargoTestFlags = [ "-p" "habitat-authority" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'authorization-*' -o -name 'attenuation_revocation-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatExecution = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-execution";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-execution" ];
        cargoTestFlags = [ "-p" "habitat-execution" ];
      };
      habitatContext = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-context";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-context" ];
        cargoTestFlags = [ "-p" "habitat-context" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'compiler-*' -o -name 'faults-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatEffects = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-effects";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-effects" ];
        cargoTestFlags = [ "-p" "habitat-effects" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'admission-*' -o -name 'fault_matrix-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatModels = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-models";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-models" ];
        cargoTestFlags = [ "-p" "habitat-models" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'driver_boundary-*' -o -name 'provider_replacement-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatPackages = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-packages";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-packages" ];
        cargoTestFlags = [ "-p" "habitat-packages" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'admission-*' -o -name 'lifecycle-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatHarnesses = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-harnesses";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-harnesses" ];
        cargoTestFlags = [ "-p" "habitat-harnesses" ];
        postInstall = ''
          mkdir -p "$out/libexec/nix-ai-tests"
          find target -type f -executable \( -name 'backend_conformance-*' -o -name 'runtime_boundary-*' \) -exec cp {} "$out/libexec/nix-ai-tests/" \;
        '';
      };
      habitatRuntime = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-runtime";
        version = "0.1.0";
        src = rustSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-runtime" ];
        cargoTestFlags = [ "-p" "habitat-runtime" ];
      };
      qualifyW03 = pkgs.writeShellApplication {
        name = "qualify-w03";
        runtimeInputs = [ habitatAbi validateContracts python ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w03.py} \
            --root ${self} --server ${habitatAbi}/bin/habitat-abi-server "$@"
        '';
      };
      qualifyW04 = pkgs.writeShellApplication {
        name = "qualify-w04";
        runtimeInputs = [ habitatAuthority validateContracts python ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w04.py} \
            --root ${self} --library ${habitatAuthority}/bin/habitat-authority \
            --test-dir ${habitatAuthority}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyW05 = pkgs.writeShellApplication {
        name = "qualify-w05";
        runtimeInputs = [ pkgs.docker-client python ];
        text = ''
          export PYTHONPATH=${./src}
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w05.py} "$@"
        '';
      };
      qualifyW06 = pkgs.writeShellApplication {
        name = "qualify-w06";
        runtimeInputs = [ python ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w06.py} --bwrap /usr/bin/bwrap --bash ${pkgs.bash}/bin/bash --python ${pkgs.python3}/bin/python --prlimit ${pkgs.util-linux}/bin/prlimit --taskset ${pkgs.util-linux}/bin/taskset --dd ${pkgs.coreutils}/bin/dd --sleep ${pkgs.coreutils}/bin/sleep --execution ${habitatExecution}/bin/habitat-execution --profile ${./nix/profiles/qemu-x86_64-conformance.json} "$@"
        '';
      };
      qualifyW07 = pkgs.writeShellApplication {
        name = "qualify-w07";
        runtimeInputs = [ habitatContext python validateContracts ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w07.py} --root ${self} --artifact ${habitatContext}/bin/habitat-context \
            --test-dir ${habitatContext}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyW08 = pkgs.writeShellApplication {
        name = "qualify-w08";
        runtimeInputs = [ habitatEffects python validateContracts ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w08.py} --root ${self} \
            --artifact ${habitatEffects}/bin/habitat-effects \
            --test-dir ${habitatEffects}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyW09 = pkgs.writeShellApplication {
        name = "qualify-w09";
        runtimeInputs = [ habitatModels python validateContracts ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w09.py} --root ${self} --artifact ${habitatModels}/bin/habitat-models \
            --test-dir ${habitatModels}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyW10 = pkgs.writeShellApplication {
        name = "qualify-w10";
        runtimeInputs = [ habitatPackages python validateContracts ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w10.py} --root ${self} --artifact ${habitatPackages}/bin/habitat-packages \
            --test-dir ${habitatPackages}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyW11 = pkgs.writeShellApplication {
        name = "qualify-w11";
        runtimeInputs = [ habitatHarnesses python validateContracts ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_w11.py} --root ${self} --artifact ${habitatHarnesses}/bin/habitat-harnesses \
            --test-dir ${habitatHarnesses}/libexec/nix-ai-tests "$@"
        '';
      };
      qualifyV2Release = pkgs.writeShellApplication {
        name = "qualify-v2-release";
        runtimeInputs = contractTools ++ [ pkgs.docker-client ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_v2_release.py} --root "$PWD" --run "$@"
        '';
      };
      verifyV2Release = pkgs.writeShellApplication {
        name = "verify-v2-release";
        runtimeInputs = [ python ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec ${python}/bin/python ${./tools/qualify_v2_release.py} --root ${self} --verify-evidence "$@"
        '';
      };
      habitatClosure = pkgs.closureInfo {
        rootPaths = [
          habitatSystem.config.system.build.toplevel
          candidateSystem.config.system.build.toplevel
          recoverySystem.config.system.build.toplevel
        ];
      };
      v2BuildClosure = pkgs.closureInfo {
        rootPaths = [
          habitatState habitatAbi habitatAuthority habitatExecution habitatContext habitatEffects
          habitatModels habitatPackages habitatHarnesses habitatRuntime habitatQemu
        ];
      };
      artifactQualification = pkgs.runCommand "nix-ai-v2-artifact-qualification" {
        nativeBuildInputs = contractTools ++ [ pkgs.diffutils ];
      } ''
        ${python}/bin/python ${self}/tools/qualify_v2_artifacts.py --root ${self} \
          --verify-proto --output artifact-report.json
        cmp artifact-report.json ${./evidence/v2-rebuild/artifact-closure-report.json}
        ${python}/bin/python ${self}/tools/verify_v2_build_closure.py \
          --closure-paths ${v2BuildClosure}/store-paths --output closure-report.json
        cmp closure-report.json ${./evidence/v2-rebuild/build-closure-report.json}
        touch "$out"
      '';
      habitatRaw = pkgs.runCommand "habitat-raw" {
        nativeBuildInputs = with pkgs; [ coreutils dosfstools e2fsprogs gptfdisk gnused mtools ];
      } ''
        set -euo pipefail
        mkdir -p "$out" root/nix/store root/etc root/var/lib/habitat root/srv/habitat root/run
        touch root/etc/NIXOS
        while IFS= read -r path; do cp -a --parents "$path" root; done < ${habitatClosure}/store-paths
        truncate -s 4600M "$out/habitat.raw"
        sgdisk --clear \
          --new=1:16384:+256M --typecode=1:ef00 --change-name=1:HABITAT_ESP \
          --new=2:0:+3000M --typecode=2:8304 --change-name=2:HABITAT_ROOT \
          --new=3:0:+512M --typecode=3:8310 --change-name=3:HABITAT_STATE \
          --new=4:0:+256M --typecode=4:8306 --change-name=4:HABITAT_SRV \
          --new=5:0:+256M --typecode=5:8300 --change-name=5:HABITAT_ACT \
          --new=6:0:0 --typecode=6:8300 --change-name=6:HABITAT_RECOVERY \
          "$out/habitat.raw"

        truncate -s 256M esp.img
        mkfs.vfat -n HABITAT_ESP -i 48414231 esp.img
        mmd -i esp.img ::/EFI ::/EFI/BOOT ::/EFI/Linux ::/loader
        mcopy -i esp.img ${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi ::/EFI/BOOT/BOOTX64.EFI
        mcopy -i esp.img ${habitatSystem.config.system.build.uki}/${habitatSystem.config.system.boot.loader.ukiFile} ::/EFI/Linux/${habitatSystem.config.system.boot.loader.ukiFile}
        mcopy -i esp.img ${candidateSystem.config.system.build.uki}/${candidateSystem.config.system.boot.loader.ukiFile} ::/EFI/Linux/habitat-candidate.efi.staged
        mcopy -i esp.img ${recoverySystem.config.system.build.uki}/${recoverySystem.config.system.boot.loader.ukiFile} ::/EFI/Linux/habitat-recovery.efi
        printf 'default habitat-candidate*\ntimeout 0\nconsole-mode keep\n' > loader.conf
        mcopy -i esp.img loader.conf ::/loader/loader.conf
        dd if=esp.img of="$out/habitat.raw" bs=512 seek=16384 conv=notrunc status=none

        truncate -s 3000M root.img
        mke2fs -q -t ext4 -N 500000 -L HABITAT_ROOT -U 48414249-5441-5400-0000-000000000002 -d root root.img
        root_start="$(sgdisk -i 2 "$out/habitat.raw" | sed -n 's/^First sector: \([0-9]*\).*/\1/p')"
        dd if=root.img of="$out/habitat.raw" bs=512 seek="$root_start" conv=notrunc status=none

        make_partition() {
          number="$1" size="$2" label="$3" uuid="$4"
          truncate -s "$size" partition.img
          mke2fs -q -t ext4 -L "$label" -U "$uuid" partition.img
          start="$(sgdisk -i "$number" "$out/habitat.raw" | sed -n 's/^First sector: \([0-9]*\).*/\1/p')"
          dd if=partition.img of="$out/habitat.raw" bs=512 seek="$start" conv=notrunc status=none
        }
        make_partition 3 512M HABITAT_STATE 48414249-5441-5400-0000-000000000003
        make_partition 4 256M HABITAT_SRV 48414249-5441-5400-0000-000000000004
        make_partition 5 256M HABITAT_ACT 48414249-5441-5400-0000-000000000005
        recovery_start="$(sgdisk -i 6 "$out/habitat.raw" | sed -n 's/^First sector: \([0-9]*\).*/\1/p')"
        recovery_sectors="$(sgdisk -i 6 "$out/habitat.raw" | sed -n 's/^Partition size: \([0-9]*\).*/\1/p')"
        mkdir recovery
        printf 'Habitat recovery generation\n' > recovery/RECOVERY_READ_ONLY
        truncate -s "$((recovery_sectors * 512))" recovery.img
        mke2fs -q -t ext4 -L HABITAT_RECOVERY -U 48414249-5441-5400-0000-000000000006 -d recovery recovery.img
        dd if=recovery.img of="$out/habitat.raw" bs=512 seek="$recovery_start" conv=notrunc status=none
      '';
      habitatQemu = pkgs.runCommand "habitat-qemu" {
        nativeBuildInputs = [ pkgs.qemu ];
      } ''
        mkdir -p "$out"
        qemu-img convert -f raw -O qcow2 ${habitatRaw}/habitat.raw "$out/habitat.qcow2"
      '';
      habitatInstaller = pkgs.runCommand "habitat-installer" { } ''
        mkdir -p "$out"
        ln -s ${habitatRaw}/habitat.raw "$out/habitat-installer.raw"
        printf '%s\n' 'Write habitat-installer.raw to the target disk; installation is a byte-for-byte reproducible image deployment.' > "$out/README"
      '';
      habitatRecovery = pkgs.runCommand "habitat-recovery" {
        nativeBuildInputs = [ pkgs.coreutils pkgs.mtools ];
      } ''
        mkdir -p "$out"
        cp ${habitatRaw}/habitat.raw "$out/habitat-recovery.raw"
        chmod u+w "$out/habitat-recovery.raw"
        printf 'default habitat-recovery*\ntimeout 0\nconsole-mode keep\n' > loader.conf
        mcopy -o -i "$out/habitat-recovery.raw@@8388608" loader.conf ::/loader/loader.conf
      '';
      testW01 = mode: pkgs.writeShellApplication {
        name = "test-${mode}";
        runtimeInputs = [ pkgs.coreutils pkgs.python3 pkgs.qemu ];
        text = ''
          export PYTHONPATH=${self}/tools''${PYTHONPATH:+:$PYTHONPATH}
          exec python3 ${./tools/test_w01.py} ${mode} \
            --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
            --code ${pkgs.OVMF.fd}/FV/OVMF_CODE.fd \
            --vars ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd \
            --disk ${habitatQemu}/habitat.qcow2 "$@"
        '';
      };
      testBoot = testW01 "boot";
      testRollback = testW01 "rollback";
      runtimeLiveCheck = pkgs.testers.runNixOSTest {
        name = "habitat-runtime-live";
        nodes.machine = {
          imports = [ ./nix/modules/habitat-runtime.nix runtimeConfiguration ];
          system.stateVersion = "26.05";
          networking.hostName = "habitat-runtime-live";
          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;
          systemd.services.habitat-runtime-conformance.enable = false;
        };
        testScript = ''
          import json
          import os
          import pathlib
          machine.start()
          machine.wait_for_unit("multi-user.target", timeout=180)
          machine.wait_for_unit("habitat-runtime.service", timeout=180)
          output = machine.succeed("${python}/bin/python ${runtimeLiveProbe}", timeout=300)
          event = json.loads(output.strip().splitlines()[-1])
          assert event["event"] == "habitat.runtime_live"
          assert event["outcome"] == "passed"
          probes = event["probes"]
          assert probes["forged_identity"] == "UNAUTHORIZED"
          assert probes["direct_state"] == "UNAUTHORIZED"
          assert probes["provider_mismatch"] == "UNAUTHORIZED"
          assert probes["duplicate_attempts"] == 1
          assert probes["restart_reconciliation"] == "ResolvedSucceeded"
          assert probes["reconciliation_unavailable"] == "Reconciling"
          assert probes["caller_subject"] == "UNAUTHORIZED"
          assert probes["same_uid_wrong_unit"] == "UNAUTHORIZED"
          assert probes["quota_replay"] == "IDEMPOTENT"
          assert probes["compensation"] == "ObservedSucceeded"
          assert probes["safe_attestation"] == "SO_PEERCRED+EXACT_CGROUP+RUNTIME_HMAC"
          assert probes["revocation_restart"] == "UNAUTHORIZED"
          assert probes["objective_guard_count"] == 1
          assert probes["runtime_effect_files"] == 0
          assert probes["transactional_store"] == "postgresql"
          assert probes["evidence_store"] == "garage-s3"
          artifact = pathlib.Path(os.environ["out"]) / "runtime-live-probe.json"
          artifact.parent.mkdir(parents=True, exist_ok=True)
          artifact.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
          print(output.strip())
        '';
      };
      changeLiveCheck = pkgs.testers.runNixOSTest {
        name = "habitat-change-live";
        nodes.machine = {
          imports = [ ./nix/modules/habitat-runtime.nix runtimeConfiguration ];
          system.stateVersion = "26.05";
          networking.hostName = "habitat-change-live";
          virtualisation.memorySize = 2048;
          virtualisation.cores = 2;
          systemd.services.habitat-runtime-conformance.enable = false;
          systemd.services.habitat-change-conformance = {
            after = [ "habitat-controller.service" "habitat-evaluator.service"
              "habitat-signer.service" "habitat-health.service" ];
            requires = [ "habitat-controller.service" "habitat-evaluator.service"
              "habitat-signer.service" "habitat-health.service" ];
            serviceConfig = {
              Type = "oneshot";
              User = "root";
              ExecStart = "${python}/bin/python ${changeLiveProbe}";
              StandardOutput = "journal+console";
              StandardError = "journal+console";
            };
          };
        };
        testScript = ''
          import json
          import os
          import pathlib
          machine.start()
          machine.wait_for_unit("multi-user.target", timeout=180)
          machine.succeed("systemctl start habitat-change-conformance.service", timeout=180)
          status = machine.succeed("systemctl show habitat-change-conformance.service --property=Result --value").strip()
          assert status == "success", machine.succeed("journalctl -u habitat-change-conformance.service --no-pager")
          output = machine.succeed("journalctl -u habitat-change-conformance.service -o cat --no-pager")
          event = json.loads([line for line in output.splitlines() if line.startswith("{")][-1])
          assert event["gate"] == "V-CHANGE" and event["result"] == "pass"
          assert all(value == 0 for value in event["metrics"].values())
          artifact = pathlib.Path(os.environ["out"]) / "change-live-probe.json"
          artifact.parent.mkdir(parents=True, exist_ok=True)
          artifact.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        '';
      };
      testRuntimeLive = pkgs.writeShellApplication {
        name = "test-runtime-live";
        runtimeInputs = [ pkgs.coreutils pkgs.jq ];
        text = ''
          artifact=${runtimeLiveCheck}/runtime-live-probe.json
          test -s "$artifact"
          jq -e '.schema_version == "2.0" and .event == "habitat.runtime_live" and
            .outcome == "passed" and .probes.safe_attestation == "SO_PEERCRED+EXACT_CGROUP+RUNTIME_HMAC" and
            .probes.compensation == "ObservedSucceeded" and
            .probes.reconciliation_unavailable == "Reconciling"' "$artifact" >/dev/null
          jq -c --arg artifact "$artifact" \
            '. + {event:"habitat.runtime_live.gate",probe_artifact:$artifact}' "$artifact"
        '';
      };
      testChangeLive = pkgs.writeShellApplication {
        name = "test-change-live";
        runtimeInputs = [ pkgs.jq ];
        text = ''
          artifact=${changeLiveCheck}/change-live-probe.json
          jq -e '.gate == "V-CHANGE" and .result == "pass" and
            .metrics.self_confirmed_candidate_count == 0 and
            .metrics.evaluator_capture_count == 0 and
            .metrics.in_place_contract_mutation_count == 0' "$artifact" >/dev/null
          jq -c --arg artifact "$artifact" '. + {probe_artifact:$artifact}' "$artifact"
        '';
      };
      runHabitatQemu = pkgs.writeShellApplication {
        name = "run-habitat-qemu";
        runtimeInputs = [ pkgs.coreutils pkgs.qemu ];
        text = ''
          work="$(mktemp -d -t habitat-qemu.XXXXXXXX)"
          trap 'rm -rf "$work"' EXIT
          cp ${habitatQemu}/habitat.qcow2 "$work/habitat.qcow2"
          cp ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd "$work/OVMF_VARS.fd"
          chmod u+w "$work/habitat.qcow2" "$work/OVMF_VARS.fd"
          exec qemu-system-x86_64 -machine q35,accel=tcg -m 2048 -smp 2 \
            -display none -serial stdio -no-reboot \
            -drive if=pflash,format=raw,readonly=on,file=${pkgs.OVMF.fd}/FV/OVMF_CODE.fd \
            -drive if=pflash,format=raw,file="$work/OVMF_VARS.fd" \
            -drive if=virtio,format=qcow2,file="$work/habitat.qcow2"
        '';
      };
    in {
      apps.${system} = {
        validate-contracts = {
          type = "app";
          program = "${validateContracts}/bin/validate-contracts";
          meta.description = "Verify the governing bundle, contracts, and projections";
        };
        generate-proto = {
          type = "app";
          program = "${generateProto}/bin/generate-proto";
          meta.description = "Regenerate descriptor and Rust Protobuf bindings";
        };
        qualify = {
          type = "app";
          program = "${qualifyW00}/bin/qualify-w00";
          meta.description = "Run every qualification gate applicable to W00";
        };
        run-habitat-qemu = {
          type = "app";
          program = "${runHabitatQemu}/bin/run-habitat-qemu";
          meta.description = "Run a disposable persistent-copy Habitat UEFI VM";
        };
        test-boot = {
          type = "app";
          program = "${testBoot}/bin/test-boot";
          meta.description = "Run the live persistent-disk V-BOOT qualification";
        };
        test-runtime-live = {
          type = "app";
          program = "${testRuntimeLive}/bin/test-runtime-live";
          meta.description = "Prove the live PostgreSQL/Garage runtime trust and persistence boundary";
        };
        test-change-live = {
          type = "app";
          program = "${testChangeLive}/bin/test-change-live";
          meta.description = "Prove peer-authenticated governed change and rollback in a live VM";
        };
        test-rollback = {
          type = "app";
          program = "${testRollback}/bin/test-rollback";
          meta.description = "Run the live boot-counted V-ROLLBACK qualification";
        };
        test-w02 = {
          type = "app";
          program = "${qualifyW02}/bin/qualify-w02";
          meta.description = "Run live PostgreSQL/Garage W02 disaster qualification";
        };
        test-python = {
          type = "app";
          program = "${testAllPython}/bin/test-all-python";
          meta.description = "Run the complete Python suite with live PostgreSQL and Garage";
        };
        test-w03 = {
          type = "app";
          program = "${qualifyW03}/bin/qualify-w03";
          meta.description = "Verify W03 Agent ABI bindings and Unix transport";
        };
        test-w04 = {
          type = "app";
          program = "${qualifyW04}/bin/qualify-w04";
          meta.description = "Verify W04 capability authority invariants";
        };
        test-w05 = {
          type = "app";
          program = "${qualifyW05}/bin/qualify-w05";
          meta.description = "Run W05 wake and lease crash qualification";
        };
        test-w06 = {
          type = "app";
          program = "${qualifyW06}/bin/qualify-w06";
          meta.description = "Run W06 native isolation adversarial qualification";
        };
        test-w07 = {
          type = "app";
          program = "${qualifyW07}/bin/qualify-w07";
          meta.description = "Run W07 context compiler and fault qualification";
        };
        test-w08 = {
          type = "app";
          program = "${qualifyW08}/bin/qualify-w08";
          meta.description = "Run W08 durable effect and reconciliation qualification";
        };
        test-w09 = {
          type = "app";
          program = "${qualifyW09}/bin/qualify-w09";
          meta.description = "Run W09 provider-neutral model-driver qualification";
        };
        test-w10 = {
          type = "app";
          program = "${qualifyW10}/bin/qualify-w10";
          meta.description = "Run W10 signed package lifecycle qualification";
        };
        test-w11 = {
          type = "app";
          program = "${qualifyW11}/bin/qualify-w11";
          meta.description = "Run W11 Codex and Claude harness conformance";
        };
        qualify-v2-release = {
          type = "app";
          program = "${qualifyV2Release}/bin/qualify-v2-release";
          meta.description = "Run every live v2 release gate and regenerate protected evidence";
        };
        test-w13 = {
          type = "app";
          program = "${verifyV2Release}/bin/verify-v2-release";
          meta.description = "Verify all v2 gates and the binding completion predicate";
        };
      };

      packages.${system} = {
        habitat-qemu = habitatQemu;
        habitat-raw = habitatRaw;
        habitat-installer = habitatInstaller;
        habitat-recovery = habitatRecovery;
        habitat-state = habitatState;
        habitat-abi = habitatAbi;
        habitat-authority = habitatAuthority;
        habitat-execution = habitatExecution;
        habitat-context = habitatContext;
        habitat-effects = habitatEffects;
        habitat-models = habitatModels;
        habitat-packages = habitatPackages;
        habitat-harnesses = habitatHarnesses;
        habitat-runtime = habitatRuntime;
        v2-build-closure = v2BuildClosure;
      };

      checks.${system} = {
        release-qualification = pkgs.runCommand "nix-ai-v2-release-qualification" {
          nativeBuildInputs = [ verifyV2Release ];
        } ''
          verify-v2-release
          touch "$out"
        '';
        artifact-qualification = artifactQualification;
        w11-qualification = pkgs.runCommand "habitat-w11-qualification" {
          nativeBuildInputs = [ qualifyW11 ];
        } ''
          qualify-w11 --evidence-dir "$out"
        '';
        w10-qualification = pkgs.runCommand "habitat-w10-qualification" {
          nativeBuildInputs = [ qualifyW10 ];
        } ''
          qualify-w10 --evidence-dir "$out"
        '';
        w09-qualification = pkgs.runCommand "habitat-w09-qualification" {
          nativeBuildInputs = [ qualifyW09 ];
        } ''
          qualify-w09 --evidence-dir "$out"
        '';
        w08-qualification = pkgs.runCommand "habitat-w08-qualification" {
          nativeBuildInputs = [ qualifyW08 ];
        } ''
          qualify-w08 --evidence-dir "$out"
        '';
        w07-qualification = pkgs.runCommand "habitat-w07-qualification" {
          nativeBuildInputs = [ qualifyW07 ];
        } ''
          qualify-w07 --evidence-dir "$out"
        '';
        w04-qualification = pkgs.runCommand "habitat-w04-qualification" {
          nativeBuildInputs = [ qualifyW04 ];
        } ''
          qualify-w04 --evidence-dir "$out"
        '';
        w03-qualification = pkgs.runCommand "habitat-w03-qualification" {
          nativeBuildInputs = [ qualifyW03 ];
        } ''
          qualify-w03 --evidence-dir "$out"
        '';
        contracts = pkgs.runCommand "habitat-contract-validation" {
          nativeBuildInputs = [ validateContracts ];
        } ''
          validate-contracts
          touch "$out"
        '';
        w00-qualification = pkgs.runCommand "habitat-w00-qualification" {
          nativeBuildInputs = [ qualifyW00 ];
        } ''
          qualify-w00
          touch "$out"
        '';
      };

      formatter.${system} = pkgs.nixfmt;

      devShells.${system}.default = pkgs.mkShell {
        packages = contractTools ++ [ validateContracts qualifyW00 qualifyW02 testAllPython qualifyW03 qualifyW04
          qualifyW06 qualifyW07 qualifyW08 qualifyW09 qualifyW10 qualifyW11 qualifyV2Release verifyV2Release
          habitatState habitatAbi habitatAuthority habitatExecution habitatContext habitatEffects habitatModels habitatPackages habitatHarnesses habitatRuntime ];
      };
    };
}
