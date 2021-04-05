Make sure you have provided the following information:

 - [v] link to your code branch cloned from rhboot/shim-review in the form user/repo@tag
 - [v] completed README.md file with the necessary information
 - [v] shim.efi to be signed
 - [v] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
 - [v] binaries, for which hashes are added do vendor_db ( if you use vendor_db and have hashes allow-listed )
 - [v] any extra patches to shim via your own git tree or as files
 - [v] any extra patches to grub via your own git tree or as files
 - [v] build logs

Link to review:

###### What organization or people are asking to have this signed:
Cloud Linux Software, Inc.

###### What product or service is this for:
CloudLinux OS 8

###### Please create your shim binaries starting with the 15.4 shim release tar file:
###### https://github.com/rhboot/shim/releases/download/15.4/shim-15.4.tar.bz2
###### This matches https://github.com/rhboot/shim/releases/tag/15.4 and contains
###### the appropriate gnu-efi source.
###### Please confirm this as the origin your shim.
This starts with the shim 15.4 release tarball.

###### What's the justification that this really does need to be signed for the whole world to be able to boot it:
We're a well known vendor with more than 4000 clients and more than 200,000
product installations

###### How do you manage and protect the keys used in your SHIM?
They're stored in an HSM token provided by Certification Authority.

###### Do you use EV certificates as embedded certificates in the SHIM?
Yes

###### If you use new vendor_db functionality, are any hashes allow-listed, and if yes: for what binaries ?
We don't use vendor_db in this build.

###### Is kernel upstream commit 75b0cea7bf307f362057cc778efe89af4c615354 present in your kernel, if you boot chain includes a Linux kernel ?
All of the following commits are present:
```
475fb4e8b2f4444d1d7b406ff3a7d21bc89a1e6f  
1957a85b0032a81e6482ca4aab883643b8dae06e  
612bd01fc6e04c3ce9eb59587b4a7e4ebd6aff35  
75b0cea7bf307f362057cc778efe89af4c615354  
435d1a471598752446a72ad1201b3c980526d869  
```
And the configuration setting CONFIG_EFI_CUSTOM_SSDT_OVERLAYS is disabled.

###### if SHIM is loading GRUB2 bootloader, are CVEs CVE-2020-14372,
###### CVE-2020-25632, CVE-2020-25647, CVE-2020-27749, CVE-2020-27779,
###### CVE-2021-20225, CVE-2021-20233, CVE-2020-10713, CVE-2020-14308,
###### CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705,
###### ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
###### and if you are shipping the shim_lock module CVE-2021-3418
###### fixed ?
Yes, these are all fixed

###### "Please specifically confirm that you add a vendor specific SBAT entry for SBAT header in each binary that supports SBAT metadata
###### ( grub2, fwupd, fwupdate, shim + all child shim binaries )" to shim review doc ?
###### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim
On shim, we have:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,1,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.cloudlinux,1,CloudLinux,shim,15.4-4,security@cloudlinux.com
```
On grub2, we have:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,1,Free Software Foundation,grub,2.02,https//www.gnu.org/software/grub/
grub.cl8,1,CloudLinux OS 8,grub2,1:2.02-90.el8_3.1,mail:security@cloudlinux.com
```
##### Were your old SHIM hashes provided to Microsoft ?
We don't have old SHIM binaries

##### Did you change your certificate strategy, so that affected by CVE-2020-14372, CVE-2020-25632, CVE-2020-25647, CVE-2020-27749,
##### CVE-2020-27779, CVE-2021-20225, CVE-2021-20233, CVE-2020-10713,
##### CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, CVE-2020-14311, CVE-2020-15705 ( July 2020 grub2 CVE list + March 2021 grub2 CVE list )
##### grub2 bootloaders can not be verified ?
This is our first submission so no old grub2 binaries allowed.

##### What exact implementation of Secureboot in grub2 ( if this is your bootloader ) you have ?
##### * Upstream grub2 shim_lock verifier or * Downstream RHEL/Fedora/Debian/Canonical like implementation ?
It is a "RHEL-like" implementation.

###### What is the origin and full version number of your bootloader (GRUB or other)?
GRUB2 version 2.02-90.el8_3.1 from RHEL with CloudLinux OS 8 cert and SBAT.  
Source RPM: https://github.com/cloudlinux/shim-review/raw/master/grub2-2.02-90.el8_3.1.cloudlinux.src.rpm

###### If your SHIM launches any other components, please provide further details on what is launched
No

###### If your GRUB2 launches any other binaries that are not Linux kernel in SecureBoot mode,
###### please provide further details on what is launched and how it enforces Secureboot lockdown
No, only linux.

###### If you are re-using a previously used (CA) certificate, you
###### will need to add the hashes of the previous GRUB2 binaries
###### exposed to the CVEs to vendor_dbx in shim in order to prevent
###### GRUB2 from being able to chainload those older GRUB2 binaries. If
###### you are changing to a new (CA) certificate, this does not
###### apply. Please describe your strategy.
This is our first submission so we're not re-using a previously used (CA)
certificate.

###### How do the launched components prevent execution of unauthenticated code?
Everything validates signatures using shim's protocol.

###### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
No.

###### What kernel are you using? Which patches does it includes to enforce Secure Boot?
We're using RHEL kernel.
All signed kernels are all patched for the kernel boothole CVEs and have the CONFIG_EFI_CUSTOM_SSDT_OVERLAYS config option disabled.

###### What changes were made since your SHIM was last signed?
This is our first submission

###### What is the SHA256 hash of your final SHIM binary?
```
004434383d3268e82568abcc73a9bc0a18b221f0af22efb452fd167b15b9fe72  shimia32.efi  
694c9769821d697202b58706500504a47cfde9142c576d82db25b57949881ecb  shimx64.efi
```
