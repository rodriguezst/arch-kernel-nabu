# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.0
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=3
arch=('aarch64')
url="http://www.kernel.org/"
license=('GPL2')
makedepends=('xmlto' 'docbook-xsl' 'kmod' 'inetutils' 'bc' 'git' 'uboot-tools' 'dtc' 'python3' 'systemd-ukify' 'sbsigntools')
options=('!strip')
source=("http://www.kernel.org/pub/linux/kernel/v6.x/${_srcname}.tar.xz"
        'config'
        '0001-input-nt36xxx-Enable-pen-support.patch'
        '0002-nt36xxx-add-pen-input-resolution.patch'
        '0003-SM8150-Add-apr-nodes.patch'
        '0004-SM8150-Add-slimbus-nodes.patch'
        '0005-arm64-dts-add-wcd9340-device-tree-binding-for-sm8150.patch'
        '0006-ASoC-qcom-SM8150-Add-slimbus-audio-support.patch'
        '0007-SM8150-Add-uart13-node.patch'
        '0008-arm64-dts-qcom-Initial-Xiaomi-Mi-9-support-cepheus.patch'
        '0009-arm64-boot-dts-qcom-add-OnePlus-7-Pro-T.patch'
        '0010-arm64-dts-sm8150-oneplus-guacamole-add-s6sy761-touch.patch'
        '0011-arm64-dts-sm8150-oneplus-enable-modem-and-wlan.patch'
        '0012-fixup-dts-add-ts-pinctrl-and-rmtfs_mem-guard.patch'
        '0013-SM8150-Add-device-tree-for-Xiaomi-Pad-5.patch'
        '0014-NABU-Added-novatek-touchscreen-node.patch'
        '0015-drm-panel-nt36523-Add-Xiaomi-Pad-5-CSOT-panel.patch'
        '0016-NABU-Enable-gpu-dsi0-and-dsi1.-Added-panel-and-backl.patch'
        '0017-NABU-Add-sound-nodes.patch'
        '0018-NABU-Add-pmic-fg-and-battery-nodes.patch'
        '0019-NABU-Add-wcd9340-and-microphone-dais.patch'
        '0020-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
        '0021-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
        '0022-NABU-Add-fsa4480-node.patch'
        '0023-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
        '0024-NABU-Add-flash-led-node.patch'
        '0025-NABU-Add-hall-sensor-for-magnetic-cover-detection.patch'
        '0026-NABU-Set-panel-rotation.patch'
        '0027-NABU-Remove-framebuffer-initialized-by-XBL.patch'
        '0028-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0029-arm64-dts-qcom-pm8150b-Add-fuel-gauge.patch'
        '0030-fix-whitelines.patch'
        '0031-drm-panel-nt36523-enable-prepare_prev_first.patch'
        '0032-drm-panel-novatek-nt36523-transition-to-mipi_dsi-wra.patch'
        '0033-drm-Add-drm-notifier-support.patch'
        '0034-drm-dsi-emit-panel-turn-on-off-signal-to-touchscreen.patch'
        '0035-Input-Add-nt36523-touchscreen-driver.patch'
        '0036-input-nt36523-Remove-fw-boot-delay.patch'
        '0037-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0038-arch-arm64-boot-dts-qcom-xiaomi-nabu-add-rtc-nodes.patch'
        '0039-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0040-ASoC-qcom-SM8150-Add-machine-driver.patch'
        '0041-of-property-fix-remote-endpoint-parse.patch'
        '0042-Revert-NABU-Set-panel-rotation.patch'
        '0043-nt36xxx-Change-pen-resolution.patch'
        '0044-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch'
        '0045-power-supply-qcom_fg-dont-put-battery-info-on-remove.patch'
        '0046-power-supply-qcom_fg-invert-charging-current.patch'
        '0047-power-qcom_fg-Add-initial-pm8150b-support.patch'
        '0048-power-supply-qcom_pmi8998_charger-fix-wakeirq.patch'
        '0049-power-supply-pmi8998_charger-rename-to-qcom_smbx.patch'
        '0050-power-supply-qcom_smbx-allow-disabling-charging.patch'
        '0051-power-supply-qcom_smbx-respect-battery-charge-term-c.patch'
        '0052-power-supply-qcom_smbx-bump-up-the-max-current.patch'
        '0053-power-supply-qcom_smbx-remove-unused-registers.patch'
        '0054-power-supply-qcom_smbx-add-smb5-support.patch'
        '0055-MAINTAINERS-add-myself-as-smbx-charger-driver-mainta.patch'
        '0056-power-supply-qcom_smbx-program-aicl-rerun-time.patch'
        '0057-NABU-Add-ln8000-fast-charge-IC-for-testing.patch'
        '0058-NABU-dts-enable-ln8000-charger-reduce-charge-voltage.patch'
        '0059-power-supply-qcom_smbx-default-case-handling-for-smb.patch'
        '0060-power-supply-qcom_smbx-remove-unsupported-__counted_.patch'
        '0061-dt-bindings-power-supply-qcom-pmi89980-charger-add-p.patch'
        '0062-dts-qcom-sm8150-enable-pm8150b_charger.patch'
        '0063-drm-msm-dsi-change-sync-mode-to-sync-on-DSI0-rather-.patch'
        '0064-dt-bindings-crypto-ice-Document-sm8150-inline-crypto.patch'
        '0065-arm64-dts-qcom-sm8150-Use-standalone-ICE-node-for-UF.patch'
        '0066-arm64-dts-qcom-pm8150-add-vph_pwr-and-vcoin-ADC-chan.patch'
        '0067-regulator-max77826-Add-GPIO-enable-support.patch'
        '0068-dwc3-core-Add-ssp-u3-u0-link-state-related-quirk.patch'
        '0069-dwc3-core-Add-support-to-disable-clock-gating-with-U.patch'
        '0070-drm-panel-Add-support-for-LH568WF3-ED01-AMOLED-panel.patch'
        '0071-Input-touchscreen-stm-fts-driver.patch'
        '0072-arm64-dts-qcom-Initial-Google-Pixel-4-support-google.patch'
        '0073-arm64-dts-qcom-sm8150-add-refgen-regulator.patch'
        '0074-arm64-dts-qcom-google-flame-Add-charger-node.patch'
        '0075-Input-touchscreen-fts_touch-fix-all-compilation-warn.patch'
        '0076-Input-touchscreen-fts_touch-fix-firmware-loading.patch'
        '0077-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
        '0078-clk-qcom-gcc-change-halt_check-for-gcc_ufs_phy_tx-rx.patch'
        '0079-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        'linux.preset')
sha256sums=('1a4be2fe6b5246aa4ac8987a8a4af34c42a8dd7d08b46ab48516bcc1befbcd83'
            '8ffad47f67493aebf51173e8d68caff8e4b79d4b3f3cb77f3415c86f1bc8f2fb'
            'f2fccc93ef35689ea86e7392eb9fef8ae5fa5e5d8521a36230c4b724984c6e08'
            'ee991793c6551e8c5766466349c652a63916cc4eb00fac9308925aa94fc03f63'
            '3377e6f7db2baf8d534ae6613b3faae810369d965fc69603faa0e95f1207ab46'
            'd3005bfd6ed93b053498c34bcf4db679397ba4e5ed5ceaaff6d9d63a8f6b614b'
            'fc3fde5b12889294e882cfa5827513995d23a5150022b6ab6f2d0aaf84d6a8a6'
            '48098c1bfa40fb30a66c8abcb3e0999778d752dce4441ea0e85cbcc213c41585'
            'bb1dd0a940d2343be94cd000efe47a4a8ed1a8d0654018733402eb1a25c98171'
            'bf2069b9b104f7087c3babe576d3767a73c87c45529799b01026e930dd734a7e'
            'd5ac0079e78c065a7daf7053bc9b3eb820b8ab7204e7120285250bc7e1e56ba4'
            '6d7413daa4d89bd65fd412847082a65acbccdeeddf962f017d0db78de4a90b20'
            '8f8bf0bc96dbfc9ad9ef41b5898d8ce38850cc25ebd15d28547e7961781e474e'
            '3f7eba48209b2e3e21bee975fa3818c361cd658b8699792ed90a91fa6910f2c9'
            '5e51ec442c3eb31561adbece01abc9f52966468318d4fee91e68a8ec67f1b58a'
            '7be8bd28a5f936a0cd5741072d1a7205cc68badd8e29baeb2a6a0ba6cf7bad37'
            '199b73dd27e062942053ba0a81ce2da3d0375692cac469f20fab9d4512a285c0'
            '3e0639048a18323fa856dbc38e599348f0be835fc668a8943cc8aac5096b44eb'
            'c9fbe295d1df51c0dc9fe0b0639cc6ce22fcd8dcbf2ecf2709561edc730ec6ce'
            '955ee7344c3a66265f0bbfbbaf193d2a8cd08c5677d4423ed1e623342edadbc4'
            '1041b1cc8b3ab404257c6495e2522b8bb9840536fac6df07bb175037f7f1951d'
            '6096aedc4ea913c619a7e6bfba3282005f5682173bec31481a0e4d478baf29fb'
            'ff6a7929b6d47d43d0776edc29f7c71d4158af60899ce4f5a1dab0cf6cd6c3ef'
            '017fbb6bf73e4063c064a85b5f3779801469d235cfc3b72d7591e5f852ba3e85'
            '6b655e4c9ee183afbe1c2b97c0de49c3368c61cb1d3b79547c2a8e5bd9ab0d92'
            'bdda4ff03f7ea5bdb3277cf0ecc976b697c267561ddec76f20c08e548169c980'
            '434c7b0384123728e4264353bdf213a33d08acaa55031e57717636cc9a8d2b2b'
            '6b4fb6165e0e23d5e464a9b796c09a66c21a6deae31d41b049fd9ff06407dd5a'
            '0ebf357a27e717263d04a023973f4e233ddd959001a5effed66d93f7a5dfe424'
            'ca07ac6defcafbf8ab4fc058378df8dc07a1a216c3376214d7070c3bf253d509'
            '9872a4d4f393719d225fdacaf19e457969f0fb3eaf6e5aadb9b382b4ea8de845'
            '16046ca20b40ca84ac98733732ed73a19ce5389554813c806381acebeb1eb985'
            '2e073033bcfbda64ffe091aeb35501864278c420849c07c345ef86b5bee8e27e'
            'c43e8d11283c611139bd3175a77d6c3f7a1f886251b45504140647b147d98918'
            '2ca35b09c8a59b73795171204823cf13d72b088395cbaee111b8966fcd056cc8'
            '9ac138c23d9cb7d94846370a6e29034641c8ae5f4c4ccc2f115ec543289ed732'
            '40698da9d0734ba032f8236c80a2d213f95f525f6d7d742ecd798713fd9fa5c5'
            '043a8d32632c36fea703be083988fc4e658e9a68510d837e272d56749ac45fae'
            '384bc667264b3939548ec46d533798c77448e1d49eb2b04fc674b23d7a6d5845'
            '42636a45a75efec2be8365ac9966453e0c800d744bb821cd102fce421070bf89'
            'e12e52bbdbd36d63f2a022cbf4a388fcb61f4c82877b2e76af4de63516322877'
            '178e775a4efa3b78f5d5e49113ab7cfe16fc3648f741440f3cc6e828bba0de1e'
            'ccf45024be4a1200d4c020f9e908824de71c22abacf0c727d3d36f58fe48941f'
            '9f07db0a558e31abcefbe20275d55af63a044e8724cd527c3374843716f1da16'
            'f9f1ed367cf6dbe2f7647d1e75fc6763d169fccd28636564711986ab451105f0'
            'e62b9bc755d6dec06fde279c5e36a361574f17b0aa99429c6f989b8c4d6f09a6'
            'fd52ef0b1def15ebb0100a7cd0530ab5d662cd98c4bbdf863924046e437f9aac'
            '1a3c265c4841422d8d04a382a69ad734c34f54e53db9ffd218dff66f8aa76c74'
            'b79236aafa10982d140d68a465aba712821fecf183fc467b7458fb868b684de5'
            '1c8f9b01d9babdf1883a9036f88cf7d1f4eb76f11f04e78a723a6abbcebf0a46'
            '1aacdcb93b488b509b15718e829a0d65b79ea1d59f9716809db1815b28a98e1e'
            '8f80e1fb695871cf7a3a915a7a5f2824635c3e56cf9961ef54172d95e61e060a'
            '3649810a816af9d0c3a9bbf3b180ae8296916e5e188a84cfcb97e4f730e46f64'
            '9799acb04508a69ce8ae36ef9dd1c74263b7410a8501a666924de41ad70f191a'
            '0fc7289dc58edbd7620e43cdff64ca3a8533b4828a40a2c6a0e6c3580f6df0ec'
            '4c84bc4103d51d89a10d283fca693f8bc32db0feffa2c0797cf8ff0cb8e06f72'
            '47e52a41efa223924b342fe56d14d5f32c711166be47a3ce0facbac429913ced'
            '165d8319b8333030eebdb3af172ed2ef0d8edc3bc6e5e719e18f8da5b0933af8'
            '67221d21c044f2a39167877819f157e76bb9ffa25b5de257b435a7b834cbc345'
            'f87b42226e3505ac4a2c5e271d2f1a0a2759195995b6e68f84a4cbcc8811deca'
            '7ee2092f45c3841d4a9d5891c737848ce3c29b0f6b5241a42bccd2f23334e1ea'
            '27a6137acdc66ebbb04f73a0f3d18fcb3ad0608ffc9bfccdc79bbb5e0a17fda6'
            '2030bdc69a1dfe37d4b222e3fcbedc05ce1d322e4f533ce553a6bfc68e7e1573'
            '254b83f0a43234883989cfda6d25ab2b6f49a05281a83986024123d84d53aa45'
            'fbcb736d2600ec7d9c1948d59086964724d3e5efe6326b55582abb30b1ad100c'
            'ba5f83602d2d8f9a5757174cdc5902914be2f83e1d21c8d7ad913332afcef12a'
            '9cca4de5813107dc8379cb29104079c56c97698fd39b4d8c332a2b5824af0d26'
            '018099871e2ca6d216cc990e5ce1b286832afa0308ea87e37483bcb1a5b159c6'
            '0d3ae26e07c544b4a34b144399303fbb6ad1fd88734b07425b39b3d45081293b'
            '9e373e20b5b30b907113379291fdaceebfbab2f97f531f1d638035637a59c709'
            'c5d844c140921f58f8a1df6887b2b8b1b3c2e9ec76900062db3386c191e56701'
            'c7a16642a22d11f6f725248332ab7378870a5610ce10b0771211b0878f523fd5'
            '74c5eecea3bb464fd703dcf59454d56059575ac4fb99f9459b0aeead0cb9f6e1'
            '2c1b0955b173c8341ece23151ae83a57a6c8d7599394a80b2cd85e15849e053a'
            '5074dc1786ca43bb1ba6f8f9ffc7046fde9a18b9d2b3428edcbe9b38e22b1776'
            '0a75d0a57730fdf76ecf4ca55a1ef07f543a64ff83ca5befe12793993420f883'
            '11692bd7bacacacef480b0d12bcd1f5a2e26b844c7eda81a2561afb22c98ecca'
            '5ff5e07a73812b5df2a58448acf8b70c3892c32c6e1977d5bc63e291d72b163e'
            'b2d9694a10b9d3dfb9124f4f143243cbb9f267028b6f3b1d486b189daaf637fa'
            'c2df0ccc6bc956ec4335bdf64c8bec5735bb4d1b75739a49f490b90990ed0e66'
            '1cc0cf81d0d4baa4a5ff8b762b13478f165f033bca9756838820c328b67899b9'
            '4521b5fc8964affe10f14c5bfa3ca9d12011c986f1f07d9d150d0726308fb9a1')

prepare() {
  cd $_srcname

  echo "Setting version..."
  echo "-$pkgrel" > localversion.10-pkgrel
  echo "${pkgbase#linux}" > localversion.20-pkgname

  # add upstream patch
  if [[ -f ../patch-${pkgver} ]]; then
    git apply --whitespace=nowarn ../patch-${pkgver}
  fi

  local src
  for src in "${source[@]}"; do
    src="${src%%::*}"
    src="${src##*/}"
    [[ $src = *.patch ]] || continue
    msg2 "Applying patch: $src..."
    patch -Np1 < "../$src" # || true
  done

  cat "${srcdir}/config" > ./.config
  make olddefconfig
}

build() {
  cd ${_srcname}

  # get kernel version
  make prepare
  make -s kernelrelease > version

  # build!
  unset LDFLAGS
  make ${MAKEFLAGS} Image Image.gz modules
  # Generate device tree blobs with symbols to support applying device tree overlays in U-Boot
  make ${MAKEFLAGS} DTC_FLAGS="-@" dtbs
}

_package_common() {
  echo "Installing boot image and dtbs..."
  install -Dm644 arch/arm64/boot/Image "${pkgdir}/boot/vmlinux-${kernver}"
  install -Dm644 arch/arm64/boot/Image.gz "${pkgdir}/boot/vmlinuz-${kernver}"
  install -Dm644 arch/arm64/boot/dts/${_dtbfile} "${pkgdir}/boot/dtb-${kernver}"

  echo "Installing modules..."
  make INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 DEPMOD=/doesnt/exist modules_install

  # remove build link
  rm "$pkgdir/usr/lib/modules/$kernver/build"
}

_package() {
  pkgdesc="The Linux Kernel and modules - ${_desc}"
  depends=('coreutils' 'linux-firmware' 'kmod' 'mkinitcpio>=0.7')
  optdepends=('wireless-regdb: to set the correct wireless channels of your country')
  provides=("linux=${pkgver}" "KSMBD-MODULE" "WIREGUARD-MODULE")
  conflicts=('linux')
  install=${pkgname}.install

  cd $_srcname
  local kernver="$(<version)"

  _package_common

  # sed expression for following substitutions
  local _subst="
    s|%PKGBASE%|${pkgbase}|g
    s|%KERNVER%|${kernver}|g
  "

  # install mkinitcpio preset file
  sed "${_subst}" ../linux.preset |
    install -Dm644 /dev/stdin "${pkgdir}/etc/mkinitcpio.d/${pkgbase}.preset"

  # rather than use another hook (90-linux.hook) rely on mkinitcpio's 90-mkinitcpio-install.hook
  # which avoids a double run of mkinitcpio that can occur
  install -d "${pkgdir}/usr/lib/initcpio/"
  echo "dummy file to trigger mkinitcpio to run" > "${pkgdir}/usr/lib/initcpio/$(<version)"
}

_package-uki() {
  pkgdesc="The Linux Kernel and modules - ${_desc} (UKI)"
  depends=('coreutils' 'linux-firmware' 'kmod')
  optdepends=('wireless-regdb: to set the correct wireless channels of your country')
  provides=("linux=${pkgver}" "KSMBD-MODULE" "WIREGUARD-MODULE")
  conflicts=('linux')
  #install=${pkgname}.install

  cd $_srcname
  local kernver="$(<version)"

  _package_common

  if [[ ! -f "$SB_SIGN_KEY" || ! -f "$SB_SIGN_CERT" ]]; then
    error "**********************************************"
    error "To build UKI version, you MUST provide:"
    error "1. SB_SIGN_KEY:    Path to private key"
    error "2. SB_SIGN_CERT:   Path to certificate"
    error "Set these via environment variables:"
    error "   export SB_SIGN_KEY=/path/to/key"
    error "   export SB_SIGN_CERT=/path/to/cert"
    error "**********************************************"
    exit 1
  fi

  # Set cmdline parameters
  local cmdline_quiet="quiet splash loglevel=3 systemd.show_status=auto rd.udev.log_level=3 vt.global_cursor_default=0"
  local cmdline_root="root=PARTLABEL=linux rw"
  local cmdline_console="console=tty0"
  local cmdline_other="systemd.gpt_auto=no cryptomgr.notests"

  # Generate and sign UKI
  mkdir -p "${pkgdir}/boot/efi/EFI/arch"
  ukify build \
    --linux="${pkgdir}/boot/vmlinux-${kernver}" \
    --cmdline="${cmdline_console} ${cmdline_root} ${cmdline_quiet} ${cmdline_other}" \
    --uname="${kernver}" \
    --devicetree="${pkgdir}/boot/dtb-${kernver}" \
    --os-release="Arch Linux ARM" \
    --secureboot-private-key="$SB_SIGN_KEY" \
    --secureboot-certificate="$SB_SIGN_CERT" \
    --output="${pkgdir}/boot/efi/EFI/arch/uki-${kernver}.efi"
}

_package-headers() {
  pkgdesc="Header files and scripts for building modules for linux kernel - ${_desc}"
  provides=("linux-headers=${pkgver}")
  conflicts=('linux-headers')

  cd $_srcname
  local builddir="$pkgdir/usr/lib/modules/$(<version)/build"

  echo "Installing build files..."
  install -Dt "$builddir" -m644 .config Makefile Module.symvers System.map \
    localversion.* version vmlinux
  install -Dt "$builddir/kernel" -m644 kernel/Makefile
  install -Dt "$builddir/arch/arm64" -m644 arch/arm64/Makefile
  cp -t "$builddir" -a scripts

  # add xfs and shmem for aufs building
  mkdir -p "$builddir"/{fs/xfs,mm}

  echo "Installing headers..."
  cp -t "$builddir" -a include
  cp -t "$builddir/arch/arm64" -a arch/arm64/include
  install -Dt "$builddir/arch/arm64/kernel" -m644 arch/arm64/kernel/asm-offsets.s
  mkdir -p "$builddir/arch/arm"
  cp -t "$builddir/arch/arm" -a arch/arm/include

  install -Dt "$builddir/drivers/md" -m644 drivers/md/*.h
  install -Dt "$builddir/net/mac80211" -m644 net/mac80211/*.h

  # https://bugs.archlinux.org/task/13146
  install -Dt "$builddir/drivers/media/i2c" -m644 drivers/media/i2c/msp3400-driver.h

  # https://bugs.archlinux.org/task/20402
  install -Dt "$builddir/drivers/media/usb/dvb-usb" -m644 drivers/media/usb/dvb-usb/*.h
  install -Dt "$builddir/drivers/media/dvb-frontends" -m644 drivers/media/dvb-frontends/*.h
  install -Dt "$builddir/drivers/media/tuners" -m644 drivers/media/tuners/*.h

  # https://bugs.archlinux.org/task/71392
  install -Dt "$builddir/drivers/iio/common/hid-sensors" -m644 drivers/iio/common/hid-sensors/*.h

  echo "Installing KConfig files..."
  find . -name 'Kconfig*' -exec install -Dm644 {} "$builddir/{}" \;

  echo "Removing unneeded architectures..."
  local arch
  for arch in "$builddir"/arch/*/; do
    [[ $arch = */arm64/ || $arch == */arm/ ]] && continue
    echo "Removing $(basename "$arch")"
    rm -r "$arch"
  done

  echo "Removing documentation..."
  rm -r "$builddir/Documentation"

  echo "Removing broken symlinks..."
  find -L "$builddir" -type l -printf 'Removing %P\n' -delete

  echo "Removing loose objects..."
  find "$builddir" -type f -name '*.o' -printf 'Removing %P\n' -delete

  echo "Stripping build tools..."
  local file
  while read -rd '' file; do
    case "$(file -bi "$file")" in
      application/x-sharedlib\;*)      # Libraries (.so)
        strip -v $STRIP_SHARED "$file" ;;
      application/x-archive\;*)        # Libraries (.a)
        strip -v $STRIP_STATIC "$file" ;;
      application/x-executable\;*)     # Binaries
        strip -v $STRIP_BINARIES "$file" ;;
      application/x-pie-executable\;*) # Relocatable binaries
        strip -v $STRIP_SHARED "$file" ;;
    esac
  done < <(find "$builddir" -type f -perm -u+x ! -name vmlinux -print0)

  echo "Adding symlink..."
  mkdir -p "$pkgdir/usr/src"
  ln -sr "$builddir" "$pkgdir/usr/src/$pkgbase"
}

pkgname=("${pkgbase}" "${pkgbase}-headers" "${pkgbase}-uki")
for _p in ${pkgname[@]}; do
  eval "package_${_p}() {
    _package${_p#${pkgbase}}
  }"
done
