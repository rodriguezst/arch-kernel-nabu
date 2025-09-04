# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.4
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
        '0030-drm-panel-nt36523-enable-prepare_prev_first.patch'
        '0031-drm-panel-novatek-nt36523-transition-to-mipi_dsi-wra.patch'
        '0032-drm-Add-drm-notifier-support.patch'
        '0033-drm-dsi-emit-panel-turn-on-off-signal-to-touchscreen.patch'
        '0034-Input-Add-nt36523-touchscreen-driver.patch'
        '0035-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
        '0036-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0037-arch-arm64-boot-dts-qcom-xiaomi-nabu-add-rtc-nodes.patch'
        '0038-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0039-ASoC-qcom-SM8150-Add-machine-driver.patch'
        '0040-of-property-fix-remote-endpoint-parse.patch'
        '0041-Revert-NABU-Set-panel-rotation.patch'
        '0042-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        '0043-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch'
        '0044-power-supply-qcom_fg-dont-put-battery-info-on-remove.patch'
        '0045-power-supply-qcom_fg-invert-charging-current.patch'
        '0046-power-qcom_fg-Add-initial-pm8150b-support.patch'
        '0047-power-supply-pmi8998_charger-rename-to-qcom_smbx.patch'
        '0048-power-supply-qcom_smbx-allow-disabling-charging.patch'
        '0049-power-supply-qcom_smbx-respect-battery-charge-term-c.patch'
        '0050-power-supply-qcom_smbx-bump-up-the-max-current.patch'
        '0051-power-supply-qcom_smbx-remove-unused-registers.patch'
        '0052-power-supply-qcom_smbx-add-smb5-support.patch'
        '0053-MAINTAINERS-add-myself-as-smbx-charger-driver-mainta.patch'
        '0054-power-supply-qcom_smbx-program-aicl-rerun-time.patch'
        '0055-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
        '0056-NABU-dts-enable-ln8000-charger-reduce-charge-voltage.patch'
        '0057-power-supply-qcom_smbx-default-case-handling-for-smb.patch'
        '0058-power-supply-qcom_smbx-remove-unsupported-__counted_.patch'
        '0059-dt-bindings-power-supply-qcom-pmi89980-charger-add-p.patch'
        '0060-dts-qcom-sm8150-enable-pm8150b_charger.patch'
        '0061-drm-msm-dsi-change-sync-mode-to-sync-on-DSI0-rather-.patch'
        '0062-dt-bindings-crypto-ice-Document-sm8150-inline-crypto.patch'
        '0063-arm64-dts-qcom-sm8150-Use-standalone-ICE-node-for-UF.patch'
        '0064-arm64-dts-qcom-pm8150-add-vph_pwr-and-vcoin-ADC-chan.patch'
        '0065-regulator-max77826-Add-GPIO-enable-support.patch'
        '0066-dwc3-core-Add-ssp-u3-u0-link-state-related-quirk.patch'
        '0067-dwc3-core-Add-support-to-disable-clock-gating-with-U.patch'
        '0068-drm-panel-Add-support-for-LH568WF3-ED01-AMOLED-panel.patch'
        '0069-Input-touchscreen-stm-fts-driver.patch'
        '0070-arm64-dts-qcom-Initial-Google-Pixel-4-support-google.patch'
        '0071-arm64-dts-qcom-sm8150-add-refgen-regulator.patch'
        '0072-arm64-dts-qcom-google-flame-Add-charger-node.patch'
        '0073-Input-touchscreen-fts_touch-fix-all-compilation-warn.patch'
        '0074-Input-touchscreen-fts_touch-fix-firmware-loading.patch'
        '0075-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
        '0076-clk-qcom-gcc-change-halt_check-for-gcc_ufs_phy_tx-rx.patch'
        '0077-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        'linux.preset')
sha256sums=('d6a5e3c71a10b533a756251387cc8bf48bbd5c76d842ba5e957d8b1c316ab622'
            '79efb8256e89cf802a09815542e0ccd520f206f0956efe15ac99cf5c812881f0'
            '34b62e0d09eac7c9b0bd4176b2b8d3946acb83b9e16fb4ae7fea77cebce8dcd3'
            '42f1fd25b97f6a9a8cbe1a868294e1fdd7caeb2cbe97467d6e4616fb4f384521'
            'dfcaf4cd86d3f9fbad26af9fff6cec96bd785036725a3f3a6cd2055c097f29c0'
            '330544a119c2d6d38a245625804c22686b7ff34a0ac5761d2e23cc67d97b9edb'
            '6b6104f3e80e06290da3ca87f1e6c86f06f786c28c38ac377981ec2fc1a59475'
            '7c2e419149550b2d9372500ff58d1bb5e85fe9c195c32d67e835a1b1a4324dd3'
            '53cbbed0cea8aff53bc341e98128cd0af24f64bc59ca93676fea39535136899c'
            '399394adb1ccaf503e461f42027a56d535ac3dc869fc0f98949ec740afe8c99a'
            'c8fec4540b022d5844e38283c764cc073f353b2f9ade527850313190fa289cf8'
            '688ffcb209382fb3167f684a946cc686c2fa5c0dec2d3ee94fd260878d1400f2'
            '3734020e5b8fb7a518181eb35e0ce29d91300a23038849bc61618455412edb20'
            '2b345fb85582f31244db55a6758205f789c5a87bf15c7a9dd6336a9023173531'
            'bc7a4715223e53eaefd3d4368fa5ba6650451c140d808d7b27203a6b91311a1e'
            'f1b1bc8c1365c1a1de0dc354becf6fb1462a7bc6ca686c1055880d553a6e1c1b'
            '61720d4f62f1367109ec56cb562c873f14a7d90dcea7b75ad3ac862e806fe379'
            'eb3f6431c58d89ba882ffb7be251915f11dddf04ac7ad7ad60b60684899fdb43'
            '30bf78cb17aa77131742a0a6b98f1a4f2bd152df42ae4a6fdb926a1e67e4edb4'
            '71c45b7e4dcd489ee5bee7628ad14c754afcb15a371856ec57944a0275177568'
            '12f1fc8480ef5d543f2757abd3278921eec7e2e89aa3709fcd2724467ee8fae0'
            'e695ae0b1f57fd34aeb1f85f39de8f5e8170388b08526f9ffa6474f7b62a9dc4'
            'd0c16d3249613f4353dd19bbecb7d054a7287c590f52378343fa0aa04dd03eab'
            'c658f16635351e66408e607b40abe6d3473682ff30c3ee32a6ffed793138ed4b'
            'bedecf389cfda6ad50bc3d2e345d67fef003bb50a7baa1569ce8999ca2ced701'
            '9b4ef31d58c267602b47a4ec7639bc631886baf9a6d823a46e6f94c20e2527d5'
            'c0a9c8f5556f4e76459e7139d470c1df2a93593748efafcc78ccb1f3625f14c1'
            '3e70e5fe6145e55e95d5b2c81df0a8f3533d393d34974bb6e47de4b5f3c5fca6'
            '80e8c1b466592b969932bd6114bb5f434f914f71cd419195ca526845481fe542'
            'ee16c7429e2a540f2bcad65ebfeb4a1c513017a7765a3c476d5faed31e7496ae'
            '958ac1c1c6b6b5057cdf929f02aae6eeeca7e7fae6b92395245bbec3774f53fb'
            'b695853daae5d4d087e612681fd80b07439ecbb79d0ffc2432ba5bcb5c6050f6'
            '2af668a8c60b9faa1fef984eb0709310bf633d8b13888fdaa10828000ac6231c'
            'f869cc55983b7fadd960e35e7a0fa75c758fd0237622719c120231777676677d'
            '9ecb9acd6c99fb4c4698404e63f60e5ac909f1b55323221006dadc6a9a4d47f9'
            '9cbffe28ed37572e49aaa1a2feccb50d18f79081857778696394a51641172e31'
            'ecc0555e40d1a017e10263f5c7d3216fb7dd7ce8b3b7e2624646a4392bc1a32c'
            '5de21627efc155ba9654b59c03983168a8f464fb71996d6b3da0b2d2c7245f05'
            '838b97ba11f796829df88b51166008aa03202b3166c7637a8b85509c223d752e'
            '8c7b574257932e3c0481acf11b9035c5fd77cda620f91a897c7ba5527dc9963b'
            '3aca033ef14e13865b9d9bf09e0b4a30888e83af327cc025fb539b24dd86c44e'
            'ea6a9122eef87913979a5f24d7c88ffb1257d14b8830f39a392d4f2d12d3c1ff'
            'e70fd962711a0705346c93c5e9b49403d8fc030777a5c5d7679b082ee2afabd2'
            '560766c20df76ed8f53a5a0a17da826202e1bae75368314c44dd456021b418ed'
            '760fddfcfcb8c3c80d5b2f5e84c16996ca5ceecbf087d875f63ca1c073fafdde'
            'b9cae5495440113fa90888d4480279b0bd5607d97413e8be5f900a804a5496e6'
            'ee6781bb69fd03916830da95f1e59e25ac62da1057b51d7504a748a27a9d3b43'
            'ca887c0980c915f13a637f209d54f787ce55f0c11670aac2db658590ad1fb105'
            'c473cd51aed61891750c29be8f3ff2d1b5cfffb8c7d974dde060037c4d0dfb69'
            '7d1a213f1ba0bd5d861fc44a2711a7458ae52c443b3de36b7b313bedf0dd0bf2'
            '962861c7ab79be065a568d8ed940d810216f7581d47e84f1a4c72d469415efc7'
            '8040f6ade205141e4388a4d5dde0f35dce8abb2b59387edf567e9ea1b8175beb'
            '04ed0e3d2643e03b812fa69fe69c051a38cc6c81f323bd15f4c1545260203f7d'
            '9122d1edd1828a5f9a6f4c5d095ab6b50d27d43158e8c5387d09d111ab496bfe'
            '2e1ad4dd4a119c1a0bec93f7ddcbc8ea88d43ca48fb2924fb6c8a1859e71d001'
            'a33220c68416116d077a01d4bb44993bcb6efe054c75ab33334c1d48e1bc0d0d'
            'ba5bddc5d60983922d76122afc1799f5edf5b05608479e2651dba6ee72fa19a4'
            '62959e808cf78a64e086677b57010e625da4725fa0329791ed7c545693833e12'
            '476eee3fdc10cb659d02f129d0d6fd62d80f4c1f7c42f7989b220bfc85993ab1'
            'd0466bc45a4f4944bdcb92e412d979e23079c95e7b54404390490b6fc9e26648'
            'd6418496181550ba5d9b444db06b3cb1d7386868caa5a1f620d61760d5b54148'
            'bffd3c87789db08bb943fd9e86840c45ecd18274eec57c4fd4438676cf66e570'
            '6c8bab7611e561069cf0b6a918af631c3f5991b9bffec1f3f9a574c54ffcba4c'
            '525856e81f92b1d8f3e10a84f876c7926f8e74f45bde313679778d298594f5a6'
            'c62662ce967d43cdf848c808d1e93b5019aa6d00fa337a3f682d097d65f11f6b'
            '29a4868f89df3e739ad3d425068848f9260cc382512d18d8dacf74e546e29b83'
            '7767a91443fb7147e5fc1f59d0e73c5759af7e8e61d5f2bcd1ab91a15d02c996'
            '32ff4fd78941ebd99d86a68fe4cd6516eb7fc22037d8184604a2a61a70f4aed4'
            'ce56bd1abef563e6cd9c4cad4558ae96a6e384edeeafdcdebd1655df8c3d465e'
            '02b3552b61aef3528144d604731cbb23259a044922b0e20af645e741787c45a0'
            'b7b37f0356635c3f5e5a3c31b353f6630d6362a1fc1c36522920501a8e72ba9d'
            'e821d7652493d25e48d58d5da31e72a6e0767e05665bc9728ab349f8d53fdda8'
            '3af7a7804a5948c681afac0d16617618c05731d3b23599ad9c4699d9fe4a1715'
            'b49f6c666937dae2e779b05453d2b378fd4164d3c314702157e737a84549fc48'
            'e6367acf0d38643f7bb7b0f9df2e78d4984622c9015a393c5fb442d0078a1ed4'
            'cc2fa901dcf6d3d1e785505584bf885f6997e2ec2cf7437370aebbd7f4251e3f'
            'ad2c33759dccbadf15ae6a9bcf88e92958856e850e46c1e5bffece2cc08051eb'
            'd0dae86cf54aaa90ea17ab0bbe223a1c8262f0c8fbcc6175445cc84d403ddbab'
            '72fad0edaf784fd01b686e98e258d1c82bd25ddff8ca13db99f30540353150c4'
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
