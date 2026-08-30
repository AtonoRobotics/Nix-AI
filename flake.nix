{
  description = "Habitat OS contract toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      python = pkgs.python3.withPackages (ps: [ ps.pyyaml ps.jsonschema ]);
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
      };

      checks.${system} = {
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
        packages = contractTools ++ [ validateContracts qualifyW00 ];
      };
    };
}
