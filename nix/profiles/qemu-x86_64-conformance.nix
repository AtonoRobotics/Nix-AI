{ modulesPath, ... }:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    ../modules/habitat-image.nix
    ../modules/habitat-runtime.nix
  ];
}
