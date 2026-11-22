{ stdenv, linux-pam, cmake, lib }: stdenv.mkDerivation {
  name = "pam_tester";

  src = ../test;

  buildInputs = [ linux-pam ];
  nativeBuildInputs = [ cmake ];

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    ./pam_strerror_check
    runHook postCheck
  '';

  meta = with lib; {
    description = "A simple test program for PAM";
    license = licenses.gpl3Only;
    platforms = platforms.linux;
    mainProgram = "pam_tester";
  };
}