{
  outputs = { nixpkgs, ... }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = f: builtins.listToAttrs (map (system: { name = system; value = f system; }) systems);
    forAllSystemsWithPkgs = f: forAllSystems (system: f (nixpkgs.legacyPackages.${system}));
  in {
    devShells = forAllSystemsWithPkgs (pkgs: {
      default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [linux-pam gdb cmake];
        shellHook = ''
          export PAM_SHIM_SERVER=$(git rev-parse --show-toplevel)/build/pam_shim_server
        '';
      };
    });
    packages = forAllSystemsWithPkgs (pkgs: rec {
      default = pkgs.callPackage ./nix/default.nix { };
      test = pkgs.callPackage ./nix/test.nix { };
      test-with-shim = pkgs.replaceDependencies {
        drv = test;
        replacements = [
          {
            oldDependency = pkgs.linux-pam;
            newDependency = default;
          }
        ];
      };
    });
    homeModules.default = import ./nix/home-module.nix;
  };
}
