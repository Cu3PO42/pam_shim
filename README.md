# pam_shim

pam_shim enables applications built with Nix to use the system's libpam on non-NixOS systems.

## Rationale

Applications using PAM are generally broken when run on non-NixOS Linux distributions.
There are many causes that can contribute here.
Among them are:

- PAM needs a suid helper which has a different hardcoded path on NixOS
- some distributions, such as Debian and its derived distros patch libpam to support additional syntax.

All of these are fixed if we could just use the already installed libpam instead of one from nixpkgs.
Patching individual derivations to hardcode paths on the local system is, however, tedious and prone to lead to crashes since two worlds are mixing.
Additionally, this would mean rebuilding many packages.

## Approach

Instead, pam_shim spawns a new process using the system's dynamic linker to load the native `libpam` and any required libraries the exact way a native application would.

## Limitations

pam_shim does not expose the full API surface of libpam, in particular it is not designed to enable the creation of PAM modules, but only to authenticate via it.
If your application needs any functions that are not handled, raise an issue, it might be easy to add.

## Usage

### Integration

To make use of pam_shim, you need to simply replace `linux-pam` with `pam_shim` in the relevant derivations.
You can either build against it directly by using `drv.override { linux-pam = pam_shim; }` or use `pkgs.replaceDependencies`.
Note that if you want to use an overlay, you need to take special care to avoid circular dependencies.

#### Home-Manager

The easiest and most common way to use this package is via the included Home-Manager module. Simply add

```nix
imports = [
    pam_shim.homeManagerModules.default
];
pamShim.enable = true;
```

to your configuration and then use `lib.replacePam` as needed.
For example, to wrap swaylock`, you might set

```nix
programs.swaylock.package = config.lib.pamShim.replacePam pkgs.swaylock;
```

## License

pam_shim is available under the same license as libpam, i.e. GPL 2.0 or later.
