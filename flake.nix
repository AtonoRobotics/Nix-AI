{
  description = "Habitat OS contract toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      habitatSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nix/profiles/qemu-x86_64-conformance.nix
          ./nix/images/habitat-raw.nix
        ];
      };
      candidateSystem = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./nix/profiles/qemu-x86_64-conformance.nix
          ./nix/images/habitat-raw.nix
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
          exec ${python}/bin/python ${./tools/qualify_w00.py} ${self}
        '';
      };
      qualifyW02 = pkgs.writeShellApplication {
        name = "qualify-w02";
        runtimeInputs = [ pkgs.docker-client python ];
        text = ''
          export PYTHONPATH=${./src}
          exec ${python}/bin/python ${./tools/qualify_w02.py} "$@"
        '';
      };
      habitatState = pkgs.python3Packages.buildPythonPackage {
        pname = "habitat-state";
        version = "0.1.0";
        pyproject = true;
        src = ./.;
        build-system = [ pkgs.python3Packages.setuptools ];
        dependencies = with pkgs.python3Packages; [ boto3 psycopg ];
        doCheck = false;
      };
      habitatAbi = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-abi";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [ pkgs.protobuf ];
        cargoBuildFlags = [ "-p" "habitat-abi" ];
        cargoTestFlags = [ "-p" "habitat-abi" ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };
      habitatAuthority = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-authority";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-authority" ];
        cargoTestFlags = [ "-p" "habitat-authority" ];
      };
      habitatExecution = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-execution";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-execution" ];
        cargoTestFlags = [ "-p" "habitat-execution" ];
      };
      habitatContext = pkgs.rustPlatform.buildRustPackage {
        pname = "habitat-context";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "habitat-context" ];
        cargoTestFlags = [ "-p" "habitat-context" ];
      };
      qualifyW03 = pkgs.writeShellApplication {
        name = "qualify-w03";
        runtimeInputs = [ habitatAbi validateContracts python ];
        text = ''
          exec ${python}/bin/python ${./tools/qualify_w03.py} \
            --root ${self} --server ${habitatAbi}/bin/habitat-abi-server "$@"
        '';
      };
      qualifyW04 = pkgs.writeShellApplication {
        name = "qualify-w04";
        runtimeInputs = [ habitatAuthority validateContracts python ];
        text = ''
          exec ${python}/bin/python ${./tools/qualify_w04.py} \
            --root ${self} --library ${habitatAuthority}/bin/habitat-authority "$@"
        '';
      };
      qualifyW05 = pkgs.writeShellApplication {
        name = "qualify-w05";
        runtimeInputs = [ pkgs.docker-client python ];
        text = ''
          export PYTHONPATH=${./src}
          exec ${python}/bin/python ${./tools/qualify_w05.py} "$@"
        '';
      };
      qualifyW06 = pkgs.writeShellApplication {
        name = "qualify-w06";
        runtimeInputs = [ python ];
        text = ''
          exec ${python}/bin/python ${./tools/qualify_w06.py} --bwrap /usr/bin/bwrap --bash ${pkgs.bash}/bin/bash --python ${pkgs.python3}/bin/python --prlimit ${pkgs.util-linux}/bin/prlimit --dd ${pkgs.coreutils}/bin/dd --execution ${habitatExecution}/bin/habitat-execution "$@"
        '';
      };
      qualifyW07 = pkgs.writeShellApplication {
        name = "qualify-w07";
        runtimeInputs = [ habitatContext python validateContracts ];
        text = ''
          exec ${python}/bin/python ${./tools/qualify_w07.py} --root ${self} --artifact ${habitatContext}/bin/habitat-context "$@"
        '';
      };
      habitatClosure = pkgs.closureInfo {
        rootPaths = [
          habitatSystem.config.system.build.toplevel
          candidateSystem.config.system.build.toplevel
          recoverySystem.config.system.build.toplevel
        ];
      };
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
          exec python3 ${./tools/test_w01.py} ${mode} \
            --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
            --code ${pkgs.OVMF.fd}/FV/OVMF_CODE.fd \
            --vars ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd \
            --disk ${habitatQemu}/habitat.qcow2 "$@"
        '';
      };
      testBoot = testW01 "boot";
      testRollback = testW01 "rollback";
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
        test-rollback = {
          type = "app";
          program = "${testRollback}/bin/test-rollback";
          meta.description = "Run the live boot-counted V-ROLLBACK qualification";
        };
        test-w02 = {
          type = "app";
          program = "${qualifyW02}/bin/qualify-w02";
          meta.description = "Run live PostgreSQL/MinIO W02 disaster qualification";
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
      };

      checks.${system} = {
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
        packages = contractTools ++ [ validateContracts qualifyW00 qualifyW02 qualifyW03 qualifyW04
          qualifyW06 qualifyW07 habitatState habitatAbi habitatAuthority habitatExecution habitatContext ];
      };
    };
}
