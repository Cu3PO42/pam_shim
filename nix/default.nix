{
  rustPlatform,
  llvmPackages,
  lib,
  linux-pam,
}:

rustPlatform.buildRustPackage rec {
  pname = "linux-pam";
  version = "0.1.0";

  buildInputs = [ linux-pam ];
  nativeBuildInputs = [ llvmPackages.bintools ];

  src = ./..;
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [ "--workspace" ];
  outputs = [ "out" "dev" ];

  preBuild = ''
    export PAM_SHIM_SERVER_PATH="$out/bin/pam_shim_server"
  '';

  dontConfigure = true;
  dontStrip = true;

  postFixup = ''
    patchelf --set-interpreter /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 $out/bin/pam_shim_server
    patchelf --set-rpath "" $out/bin/pam_shim_server
    mv $out/lib/libpam_shim_client.so $out/lib/libpam.so.0
  '';

  meta = with lib; {
    description = "libpam proxy shim that forwards PAM requests to a separate server process";
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
  };
}