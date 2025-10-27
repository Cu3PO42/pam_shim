{
  outputs = { nixpkgs, ... }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      nativeBuildInputs = with pkgs; [cargo rustc linux-pam llvmPackages.bintools gdb];
      shellHook = ''
        export PAM_SHIM_SERVER_PATH=$(git rev-parse --show-toplevel)/target/debug/pam_shim_server
      '';
    };
    packages.x86_64-linux = rec {
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
    };
    homeModules.default = import ./nix/home-module.nix;
  };
}
