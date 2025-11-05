{
  stdenv,
  linux-pam,
  cmake,
  lib,
}:

stdenv.mkDerivation {
  pname = "lpam-shim";
  version = "0.1.0";

  buildInputs = [ linux-pam ];
  nativeBuildInputs = [ cmake ];

  src = ./..;

  outputs = [ "out" "dev" ];

  preConfigure = ''
    cmakeFlagsArray+=(
      -DPAM_SHIM_DEFAULT_SERVER=$out/bin/pam_shim_server
    )
  '';

  dontStrip = true;

  postFixup = let arch = stdenv.hostPlatform.parsed.cpu.arch; in ''
    patchelf --set-interpreter /lib64/ld-linux-${arch}.so.2 $out/bin/pam_shim_server
    patchelf --set-rpath "" $out/bin/pam_shim_server
  '';

  meta = with lib; {
    description = "libpam proxy shim that forwards PAM requests to a separate server process";
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
  };
}