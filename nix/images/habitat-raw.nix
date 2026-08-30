{ config, lib, modulesPath, pkgs, ... }:
let
  loader = pkgs.writeText "loader.conf" ''
    default habitat-*
    timeout 0
    console-mode keep
  '';
  recoveryMarker = pkgs.writeText "RECOVERY_READ_ONLY" "Habitat recovery generation\n";
in {
  imports = [ (modulesPath + "/image/repart.nix") ];

  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.emergencyAccess = false;
  boot.initrd.supportedFilesystems = [ "ext4" "vfat" ];
  fileSystems."/" = { device = "/dev/disk/by-label/HABITAT_ROOT"; fsType = "ext4"; };
  fileSystems."/var/lib/habitat" = { device = "/dev/disk/by-label/HABITAT_STATE"; fsType = "ext4"; };
  fileSystems."/srv/habitat" = { device = "/dev/disk/by-label/HABITAT_SRV"; fsType = "ext4"; };
  fileSystems."/var/lib/habitat/activations" = { device = "/dev/disk/by-label/HABITAT_ACT"; fsType = "ext4"; options = [ "nodev" "nosuid" ]; };
  fileSystems."/run/habitat-recovery" = { device = "/dev/disk/by-label/HABITAT_RECOVERY"; fsType = "ext4"; options = [ "ro" "nodev" "nosuid" "noexec" ]; };

  system.image.id = "habitat";
  system.image.version = "1.0.0";
  image.repart = {
    name = "habitat-raw";
    compression.enable = false;
    seed = "62cecad0-4a84-4a37-906d-a87371f43c65";
    partitions = {
      "10-esp" = {
        contents = {
          "/EFI/BOOT/BOOTX64.EFI".source = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi";
          "/EFI/Linux/${config.system.boot.loader.ukiFile}".source = "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
          "/loader/loader.conf".source = loader;
        };
        repartConfig = { Type = "esp"; Format = "vfat"; Label = "HABITAT_ESP"; SizeMinBytes = "256M"; };
      };
      "20-root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = { Type = "root-x86-64"; Format = "ext4"; Label = "HABITAT_ROOT"; Minimize = "guess"; ReadOnly = true; };
      };
      "30-state".repartConfig = { Type = "var"; Format = "ext4"; Label = "HABITAT_STATE"; SizeMinBytes = "512M"; };
      "40-srv".repartConfig = { Type = "srv"; Format = "ext4"; Label = "HABITAT_SRV"; SizeMinBytes = "256M"; };
      "50-activations".repartConfig = { Type = "linux-generic"; Format = "ext4"; Label = "HABITAT_ACT"; SizeMinBytes = "256M"; };
      "60-recovery" = {
        contents."/RECOVERY_READ_ONLY".source = recoveryMarker;
        repartConfig = { Type = "linux-generic"; Format = "ext4"; Label = "HABITAT_RECOVERY"; SizeMinBytes = "256M"; ReadOnly = true; };
      };
    };
  };
}
