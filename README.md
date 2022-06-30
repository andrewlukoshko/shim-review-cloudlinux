-------------------------------------------------------------------------------
### What organization or people are asking to have this signed?
-------------------------------------------------------------------------------
Cloud Linux Software, Inc.

-------------------------------------------------------------------------------
### What product or service is this for?
-------------------------------------------------------------------------------
CloudLinux OS 8

-------------------------------------------------------------------------------
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
-------------------------------------------------------------------------------
We're a well known vendor with more than 4000 clients and more than 200,000
product installations

-------------------------------------------------------------------------------
### Who is the primary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: Andrew Lukoshko
- Position: Software Architect
- Email address: alukoshko@cloudlinux.com
- PGP key fingerprint: 135E B273 0F8A 5B9C D0AC 38B0 0ED6 B51B CD0F AADF
- PGP key: https://raw.githubusercontent.com/cloudlinux/shim-review/master/alukoshko.pub

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Who is the secondary contact for security updates, etc.?
-------------------------------------------------------------------------------
- Name: Leonid Kanter
- Position: IT Director
- Email address: lkanter@cloudlinux.com
- PGP key fingerprint: A07D AA47 48B2 C445 6A44 9B38 4002 9607 9AE5 954F
- PGP key: https://raw.githubusercontent.com/cloudlinux/shim-review/master/lkanter.pub

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

-------------------------------------------------------------------------------
### Were these binaries created from the 15.6 shim release tar?
Please create your shim binaries starting with the 15.6 shim release tar file: https://github.com/rhboot/shim/releases/download/15.6/shim-15.6.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.6 and contains the appropriate gnu-efi source.

-------------------------------------------------------------------------------
This is the unmodified shim-15.6 release.

-------------------------------------------------------------------------------
### URL for a repo that contains the exact code which was built to get this binary:
-------------------------------------------------------------------------------
https://github.com/rhboot/shim/tree/15.6  
Source rpm is: https://github.com/cloudlinux/shim-review/blob/master/shim-unsigned-x64-15.6-1.el8.cloudlinux.src.rpm  
CloudLinux 8 is based on AlmaLinux 8 so repos for build deps etc are: http://repo.almalinux.org/almalinux/8/

-------------------------------------------------------------------------------
### What patches are being applied and why:
-------------------------------------------------------------------------------
None.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
-------------------------------------------------------------------------------
This is a "RHEL-like" implementation.

-------------------------------------------------------------------------------
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, or the June 7th 2022 grub2 CVE list:
* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737

### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
-------------------------------------------------------------------------------
Old shims hashes are provided to Microsoft.
Old GRUB2 builds are disallowed to boot because they have generation 1 in SBAT.

-------------------------------------------------------------------------------
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?

-------------------------------------------------------------------------------
The following commits are present:  
1957a85b0032a81e6482ca4aab883643b8dae06e  
75b0cea7bf307f362057cc778efe89af4c615354  

The following is not present in RHEL8 kernel yet which is upstream for CloudLinux:  
eadb2f47a3ced5c64b23b90fd2a3463f63726066  
But it built with CONFIG_KDB_DEFAULT_ENABLE=0x0 so it isn't vulnerable.

And the configuration setting CONFIG_EFI_CUSTOM_SSDT_OVERLAYS is disabled.

-------------------------------------------------------------------------------
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
-------------------------------------------------------------------------------
We don't use vendor_db in this build.

-------------------------------------------------------------------------------
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
-------------------------------------------------------------------------------
We don't use vendor_dbx in this build.
Old GRUB2 builds are disallowed to boot because they have generation 1 in SBAT.

-------------------------------------------------------------------------------
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
-------------------------------------------------------------------------------
This is built on a AlmaLinux OS 8.6. The Dockerfile in this repository can be used to launch an identical buildroot.

-------------------------------------------------------------------------------
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.

-------------------------------------------------------------------------------
root.log and build.log in this repo.

-------------------------------------------------------------------------------
### What changes were made since your SHIM was last signed?
-------------------------------------------------------------------------------
Updated version from 15.4 to 15.6.

-------------------------------------------------------------------------------
### What is the SHA256 hash of your final SHIM binary?
-------------------------------------------------------------------------------
96dd31a8e0c9a2bb278a63be330c65b664b71b72a941e2959f8df5a596f8811a  shimia32.efi
dd2b4413b033df6a0152a2831804097a8a99e098b65de415d83807d285577ab7  shimx64.efi

-------------------------------------------------------------------------------
### How do you manage and protect the keys used in your SHIM?
-------------------------------------------------------------------------------
They're stored in an FIPS 140-2 certified HSM tokens provided by Certification Authorities.

-------------------------------------------------------------------------------
### Do you use EV certificates as embedded certificates in the SHIM?
-------------------------------------------------------------------------------
Yes

-------------------------------------------------------------------------------
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
-------------------------------------------------------------------------------
```
shim:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,2,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.cloudlinux,2,CloudLinux,shim,15.6,security@cloudlinux.com

grub2:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,2,Free Software Foundation,grub,2.02,https//www.gnu.org/software/grub/
grub.rh,2,Red Hat,grub2,2.02-123.el8_6.8,mailto:secalert@redhat.com
grub.cloudlinux,2,CloudLinux,grub2,2.02-123.el8_6.8.cloudlinux,mailto:security@cloudlinux.com

fwupd:
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.1,https://github.com/fwupd/fwupd
fwupd-efi.cloudlinux,1,CloudLinux,fwupd,1.7.4,mail:security@cloudlinux.com
```

-------------------------------------------------------------------------------
### Which modules are built into your signed grub image?
-------------------------------------------------------------------------------
`all_video boot blscfg btrfs cat configfile cryptodisk echo ext2 fat font
gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool
gfxmenu gfxterm gzio halt hfsplus http increment iso9660 jpeg loadenv loopback
linux lvm luks mdraid09 mdraid1x minicmd net normal part_apple part_msdos
part_gpt password_pbkdf2 png reboot regexp search search_fs_uuid search_fs_file
search_label serial sleep syslinuxcfg test tftp video xfs efi_netfs efifwsetup
efinet lsefi lsefimmap connectefi backtrace chain usb usbserial_common
usbserial_pl2303 usbserial_ftdi usbserial_usbdebug keylayouts at_keyboard`

-------------------------------------------------------------------------------
### What is the origin and full version number of your bootloader (GRUB or other)?
-------------------------------------------------------------------------------
`RHEL 8 downstream, 2.02-123.el8_6.8.cloudlinux`  
https://repo.cloudlinux.com/cloudlinux/8/cloudlinux-x86_64-server-8/Source/Packages/grub2-2.02-123.el8_6.8.cloudlinux.src.rpm

-------------------------------------------------------------------------------
### If your SHIM launches any other components, please provide further details on what is launched.
-------------------------------------------------------------------------------
It also launches fwupd

-------------------------------------------------------------------------------
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
-------------------------------------------------------------------------------
grub2 verifies signatures on booted kernels via shim. fwupd does not include
code to launch other binaries, it can only load UEFI updates.

-------------------------------------------------------------------------------
### How do the launched components prevent execution of unauthenticated code?
-------------------------------------------------------------------------------
grub2 verifies signatures on booted kernels via shim. fwupd does not include
code to launch other binaries, it can only load UEFI updates.

-------------------------------------------------------------------------------
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
-------------------------------------------------------------------------------
No.

-------------------------------------------------------------------------------
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
-------------------------------------------------------------------------------
It's RHEL8 kernel based on 4.18.0, plus a full compliment of patches for Secure
Boot and relevant bug fixes.

-------------------------------------------------------------------------------
### Add any additional information you think we may need to validate this shim.
-------------------------------------------------------------------------------
Previous review: https://github.com/rhboot/shim-review/issues/152
