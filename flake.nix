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
    in {
      apps.${system}.validate-contracts = {
        type = "app";
        program = "${validateContracts}/bin/validate-contracts";
        meta.description = "Verify the governing bundle, contracts, and projections";
      };

      checks.${system}.contracts = pkgs.runCommand "habitat-contract-validation" {
        nativeBuildInputs = [ validateContracts ];
      } ''
        validate-contracts
        touch "$out"
      '';

      formatter.${system} = pkgs.nixfmt;

      devShells.${system}.default = pkgs.mkShell {
        packages = contractTools ++ [ validateContracts ];
      };
    };
}
