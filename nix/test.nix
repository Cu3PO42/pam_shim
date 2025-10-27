{ stdenv, linux-pam, lib }: stdenv.mkDerivation {
  name = "pam-test";

  src = ../test;

  buildInputs = [ linux-pam ];

  buildPhase = ''
    gcc -o pam_test main.c -lpam
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp pam_test $out/bin/
  '';

  meta = with lib; {
    description = "A simple test program for PAM";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "pam_test";
  };
}