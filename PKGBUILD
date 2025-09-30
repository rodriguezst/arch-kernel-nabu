# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.17.0
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=1
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
        '0006-ASoC-qcom-SM8150-Add-slimbus-audio-support-Also-adde.patch'
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
        '0025-NABU-Add-hall-sensor-for-magnetic-cover-detection.-H.patch'
        '0026-NABU-Set-panel-rotation.-https-gitlab.com-sm8250-mai.patch'
        '0027-NABU-Remove-framebuffer-initialized-by-XBL-https-git.patch'
        '0028-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0029-arm64-dts-qcom-pm8150b-Add-fuel-gauge.patch'
        '0030-drm-panel-novatek-nt36523-transition-to-mipi_dsi-wra.patch'
        '0031-drm-Add-drm-notifier-support.patch'
        '0032-drm-dsi-emit-panel-turn-on-off-signal-to-touchscreen.patch'
        '0033-Input-Add-nt36523-touchscreen-driver.patch'
        '0034-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
        '0035-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0036-arch-arm64-boot-dts-qcom-xiaomi-nabu-add-rtc-nodes.patch'
        '0037-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0038-ASoC-qcom-SM8150-Add-machine-driver.patch'
        '0039-of-property-fix-remote-endpoint-parse.patch'
        '0040-Revert-NABU-Set-panel-rotation.patch'
        '0041-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        '0042-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch'
        '0043-power-supply-qcom_fg-dont-put-battery-info-on-remove.patch'
        '0044-power-supply-qcom_fg-invert-charging-current.patch'
        '0045-power-qcom_fg-Add-initial-pm8150b-support.patch'
        '0046-power-supply-qcom_smbx-allow-disabling-charging.patch'
        '0047-power-supply-qcom_smbx-respect-battery-charge-term-c.patch'
        '0048-power-supply-qcom_smbx-bump-up-the-max-current.patch'
        '0049-power-supply-qcom_smbx-remove-unused-registers.patch'
        '0050-power-supply-qcom_smbx-add-smb5-support.patch'
        '0051-power-supply-qcom_smbx-program-aicl-rerun-time.patch'
        '0052-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
        '0053-NABU-dts-enable-ln8000-charger-reduce-charge-voltage.patch'
        '0054-power-supply-qcom_smbx-default-case-handling-for-smb.patch'
        '0055-power-supply-qcom_smbx-remove-unsupported-__counted_.patch'
        '0056-dt-bindings-power-supply-qcom-pmi89980-charger-add-p.patch'
        '0057-dts-qcom-sm8150-enable-pm8150b_charger.patch'
        '0058-drm-msm-dsi-change-sync-mode-to-sync-on-DSI0-rather-.patch'
        '0059-dt-bindings-crypto-ice-Document-sm8150-inline-crypto.patch'
        '0060-arm64-dts-qcom-sm8150-Use-standalone-ICE-node-for-UF.patch'
        '0061-arm64-dts-qcom-pm8150-add-vph_pwr-and-vcoin-ADC-chan.patch'
        '0062-regulator-max77826-Add-GPIO-enable-support.patch'
        '0063-dwc3-core-Add-ssp-u3-u0-link-state-related-quirk.patch'
        '0064-dwc3-core-Add-support-to-disable-clock-gating-with-U.patch'
        '0065-drm-panel-Add-support-for-LH568WF3-ED01-AMOLED-panel.patch'
        '0066-Input-touchscreen-stm-fts-driver.patch'
        '0067-arm64-dts-qcom-Initial-Google-Pixel-4-support-google.patch'
        '0068-arm64-dts-qcom-sm8150-add-refgen-regulator.patch'
        '0069-arm64-dts-qcom-google-flame-Add-charger-node.patch'
        '0070-Input-touchscreen-fts_touch-fix-all-compilation-warn.patch'
        '0071-Input-touchscreen-fts_touch-fix-firmware-loading.patch'
        'linux.preset')
sha256sums=('9b607166a1c999d8326098121222feb080a20a3253975fcdfa2de96ba7f757a7'
            'cc798c48aba1e6df97d2a3de1791cf3712e03da26715fd47b2906bc05020e2ee'
            '1f4b35301ebc76862a5bed5bc9dff325280b7b5a62edd4ce401e2087056b9618'
            'e3a6068d29f29a91426590a50edcd9c065553bee414937f1019c8d0b3b91e53c'
            '833538e61f6de3ccbbfafb3e91d3a05ef665e1f4537f5ea2878e07ee0065b470'
            'e37cfc3674755edaaadc90335f44c26a043cb486a245cab24d973df089aa6cb1'
            'c1aac803a385cf8b1d14f5e48b1edf69198a4a0ff788585e52428fee494a227a'
            'ae5b60dd6f06dd09cc3e9a8132f593b342f069f64a42be865b2263e9ee8b7f25'
            '189e1513f9376a4cf5b24acc357825ed915b6df3be6793561342ad0741c59d77'
            '159f5900da9dc97ae3ac6e923eaa3d7e9f4021eb9b2e0fc2f3696819d56ac1c7'
            'c6e242bfb9ca4a19741f4e0ab47207336e3c986b03ee87ebd26189bf845ad4f2'
            '3b153dbed5032c3eb1e5b9523f3a51911c75173c2f7ac2677400454b122fb6b0'
            '3462b8059ccf08b5d15faf4929a3a33ce0a80ce1cbc101f8ffb600f23fed2196'
            '6853f8a50505007cfd5c5091ebd39ba99010a70d7162c3eb2a9b16dd4d6d0bed'
            '98b1e960937556713c912519023e47be961b503f5ec30a35631a172b708d300d'
            'ac76bd4581dfe88617d336c4102b5ee0b2d4d9a7faf1f675eeff7b95c4dd0db8'
            'e5c452b472628ad4689af3b6a0acdee17d63588f2ce16982e61db76438196b36'
            'f40af0429da4e43e5640fc3b7af80324d06d899b282e33a914ff3a15dbd91310'
            '3af625b9a495756e25607c46c67bfdcc4e0d27f360cebe0f18af08a5a96f1eab'
            'cc9277ed7a3e84542ab953b788355861e2baf7d01e19006b5793a45ca054b8c1'
            'bf32b67077499106fcbb35f928222209ea14975c36e0563583603ebf400ffd87'
            '8939357b7a8ade40ce3f28383e6273052363dc08d58f9fef4d35e1688a481a57'
            '2fb09c2d3c8a223dbc2521088e4cc6867dbf7ddddd6952850a5f4f76eb1f9fec'
            'befbd1bc722b4e469cc543fae8de7720cb144634338076038ac9a55059ebdd05'
            '05c2256ade41fe0d7b808c12f194889fa488ec790d25dd72a556cba2415c848d'
            '3a5c84501076bc3850b00821255d8ee2d42131e184719709479c6d558c85338b'
            '09cce605c691b8dc64605fec98bcb39bb60d56c9b252b6825c4e5290be3669d7'
            'aed282b7ce07652b8be4b66c5f7bb0d886dadadbd8cebe0cb232dd70749b4981'
            'b7d34dd149f3580be329158df2c4399e8127e2dfd0d6f5a849c054e458a35d9f'
            '7cdbb13560f69514db13920c8678059e1f7f7c998e429c223c0ed490bb18bab2'
            'bddcde31d685e6228bc9e55b8d521b542ef36e21c27356edd65ce673a1c0aead'
            'baf0d9daa129fabdcc00a2b1d848378388e46c33fa7b8bc1f3e716dbc68ccdd9'
            'bda01339cbb1d67feb8f75716ebcc31490d6d3f5c6def196ad0226fe1e1a902d'
            '62b9d4b00f430c45c88281da977de95edea52650e988fecd4a3b6835db8f53b1'
            '6d8846e27478532abc2f045e76fa536bd5701c8cf32856600f570630281ac184'
            'efca29ebad8666cff3c73c45b0390241f7e197870b85630e42308b6d3e7b36d4'
            '74129e5c496baf37eb4cdfbb1cc68a7e620ae071372b574033f81e2806af26f3'
            '09701fc630a64baed41fc5469287e1452f3db02854b17726501bd2c6fd7ad2fb'
            '6ad5cfcae7c8cd8001c4c71a9e0ec2ca039eb4647ccd7faf74c0af004a8f0b7c'
            '699cfb5cded283fb4f0a0d0084904c6a39ba997128b52ced2259b5f0d23a1b87'
            '55dbc742fde3e26c76f1dcede1a1e44bc74e4b57adf3b29b86794531d1b1c603'
            'ce2fe8e17dfc50446dbb2846dfa12bb920fa2d20408972c5ca0a5450be48ba3e'
            '2cbb5333a24b47d9e9eb88605fc8708527b512c3a82d1163c94d48ec3294460e'
            '99330eb65c8f1b97fd212dfce0e9629fbbcd21e477bcfcf86437056b20074c23'
            '7861a0e046b31dcd5bdab7e29f974d88150d9ad6f1e96b956e2c5b8702250229'
            'df2d22d2ba98e2b900792ebfee39ec9f21ab94e04a20409e87e968ba32116a1e'
            'c3f01d2af3fb6d3e033de1ac0975de5ef08b9ca1c2dc6a468253b7e440bab4cb'
            'ced18b08cd6f9916030c124bc0b83902c56c723cbf27fc4e3d74527d8ec36d88'
            '3baa0f4e0aff424451451dc2b373d8fa13e317590b4387d9dcec024ec76abeb2'
            '3d7a4fcb6319578d3495e530bb5e9eae2cd7b37070616da1aab1f034e1538be8'
            'ce59409bb4f578deac84b4a915c0e4e0915031942faae414569c1e8c5491caef'
            'f6200032c7ce98bfc094d0b151559a488c6b39b058ca3348ac575e5df5df62ce'
            '90f1b937ae71bd60c7a751b76f5887d8d5640868b6bd1c1187e01eb2fb914720'
            'ba78c13226690591176afe9e10b9a2ceb8e74f0b2bdf5a714089ab40d6d8ee18'
            '375175bf7e58fcd5127934ba942b2957056c772917731fb819bf738373dd1a13'
            'f58bca021ceb587dbab1f1a5ad22a50055555bd85fde976a76b9179c426b162a'
            'c90e6c25f48d75b3a1f6312da32406e30da0033fd35a5711859fe400915fb9d8'
            '6d9663d3b25f947c698cf71f2ec12da1ab045fcd468e2b4b16e2002fbc64c6f8'
            '1af1974810332d7c22241eef9ee6c380a9503eb3d5f6d6e00f702615284a2b53'
            '91fa5261b4f5c3aafabd9ed7abf8561910e2e3290d27f6911c94e33f2ea45efb'
            'a590f0b6fbd719599b28ef771523a68d32fff5fc4c43817965aa015eefdf7ce0'
            '90ef3b7bd401691665402fcd106fd56345de093f6581270c93ae978253867085'
            '9606936406480cc412a1b9407e59cbca0aeef8577099c3388dc01894103c9625'
            '111ce28468756b3e84cd28ccb8475d02dffb1ef9595697a8eac90ac257b2bde1'
            '445fc1210801d1a5aedf57c8967c122f19a5289be5c018a536eff61e6690c795'
            '316e864d05f6c75f4b6346cacebeb049fbb2117b7b0a940c9b21c1c29339bfa1'
            '4cc0540282e7f2634c2f21d4ec06432ff3d51effb3722d2133208941c2f3a5f2'
            'efc8b21a1043391ea65dff022a72c4b1402ca72479771b4002e6de96343c24f3'
            '7deb3f0642422ee1d93f3baa1d805a104dbb6412a2502f6709fbcf51506d8e07'
            '9ca52a4a11c2f5c3ed361f23f17dfa9c43eccf82bf394f4c1ed0def902ff603f'
            '4558218b0184d7a536eb808e418a342b93464ce09829c0110255c01c56324dac'
            'f6ffdffc16be6f7ed82f6e4f75c1a609a2978901ff7fe1218cedb7042765f560'
            'cf7c284b57b0182c1f344a65141eba2e03d91a00e6905b9f374186d7ab273137'
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
