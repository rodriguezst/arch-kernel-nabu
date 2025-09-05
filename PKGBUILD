# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.5
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
sha256sums=('76bffbae7eab2a1de1ed05692bef709f43b02a52fe95ae655cacf0fa252213f3'
            'abafd5aba095efe5c4e04fe6dec6d3def5e08377e896beaebe9ae1495cd6e32a'
            '3ced6cdb28e75667d6250b3f3c9f2e733371d2dd1f9c43924f8d7a583044bb53'
            '362a8763fa5a0def99a37efd55a74bc7954fe54c5a6a3352f1b3b574266d916e'
            'efe89f16d31357f8a97b5de231bd24d06825faf6f449af8ab653f6bb5d8b9af1'
            'fc59d679b350297b32e415270f9c1b7b673006b1c312de0a23bc4ed8e6a5d448'
            '9177ae6d83a8cca85e72f9d3ea607cdc130ce58ca8fce0ba9c6290dfb0cefa40'
            '7e4ee773316af41f3c37bb6659e1c718348bfe59771c44dbe613bb4351a8a87c'
            'a856f572dd270b197e28be1f2ffb2652890095bbd69540fee2bf8ad495ba714f'
            'bb05c58c6bbefc581e2f36c04a9a3bc0cb0e41f2a25fb59c92e35e255d4940e8'
            'd752836736bfcfedabe06f5c32f1ecf66efe021772a9be8b910e623114e360cf'
            'fc9ad10ea8f47c7e30207e97d0db89ef8e7b62a42354c426b01cb17ec1893897'
            'af5bfbba1456d987ce7f997c8cb54c5a98af3b709f5838cf13e05eb3932c1bb0'
            'b31301d15beaa334f771d6cedbb4eaf8ab4554518ad01b1799bced111f7b1089'
            '4b8415f71fbe7401a7d8974b2c4280d61ef149e12e2a7ed5a4e067947477dbab'
            'c704e6d5dabedca8ba1a091db1075c5aab6a139d9897ca9d645ef2b409a55c9c'
            '60ca9454781c8db45edc10ac1fbe8f256430c2ebe9ba711775d7b0d0c6489594'
            '98b527ca95ceb7ab1ffa8687b1747612c15d4a450ea6eb8b2cf5092b017d075a'
            '34c5b519e57c930e4b1caf55e4382cf5eec290f5bf45429cbae49650eb1ff1bb'
            '374514faa7d1630a27f655fbef598bb659999de8b2a623fb5d960268ddbe481f'
            '01c74d1d85ed660167f7612224228c1b634d6602a333339646e26d31fb9918ac'
            '9bf4824a0450998319b3098c904a722c14e152d165a3720924c9fc26f931f191'
            'dd706931dde34f8a2f939574719481640d7fe542c41fd156fd079b1394f2a639'
            '26e213241724892dc3da32a8fe14e4bd287725b7042707df0a8227eca7afaa1d'
            '1a8e31da20a7609a4f844d45c5d773908eda79e06613119c6949d1b544c45265'
            'b349950cfddd921e9d09173962b905fd4c0713739eec28aaf47208290f41746b'
            'bccd336971f94fed1d8b284a08b1f6ce2c8d5480483f17f57e0322a299debace'
            '0c1bb7e7b5d271943001f56a4682f17788c6d77c6f61cbf0588b9956031c58d1'
            '5ae1b7159720245813ac6ff69dff2f742b9ec503fb19921201bb48e614497b60'
            'c8af9b236de2d08f616a9ca11310cc8c1bf9ab7b358fd30234b9b45e4b2fb2a7'
            '98394635681f17ba8faebfb000e51ceccc21cb26a3003ac9504316c352ed8e8b'
            '367e1451ffd04eb436abeb289079d615a1cac5be5163be87f5e2f23df75ec860'
            '453ae78d2e3c6be6b014eddf00b2bc6feb3be2f771866eb271756bbeaf2f769b'
            '587f6a98af552ba3a1c6b469da3c222ca85de441ba7d11a844e408c42e24a5c9'
            'fe363413e464c4ec6050549d210633909c35aaed9efd7d1534b9d85a0e43b727'
            'e2a40b69751ef2982899374a28eb312ee08e12b81df5a3da0a42d737def730f1'
            '0c0d58f7ec7d43d7e80b8520b114176d9f36447d229692d89740f19422c35a8a'
            '23cf62e9f044ecb317f86ba6a2d7abf1d0c7f7c9b834e838006b5600382df7ce'
            '860e47b2cdb94a67d1970826d2e47da6734acc8e3a6c5b373d82457727587e3c'
            '5bfc441d79f0e6af705744bda8f34d700a320b979eff493a44f7acf21481f1e9'
            '8e50bb9aaa9f4df109f076d7dd223671dd8ae78233fc57b09073f86d7e321223'
            '9f55df330f837614573aba89558d480da7fcacf9eaab80c362042e91e2a09506'
            'f17e6a84453892b8fde7411224c5c249e5cf3d92e404e934d94645e5511dd160'
            '67d132cbe021762bb99016d792f366a4a9a235bb1f7c75280b050c7bfe3187f9'
            '05fa049baf6179cbe15c16c76dddba7c003368d1f3080c1cf178865d96850254'
            '7f5d76cc5db1ba4506dbe284f87fff13bdbaef58285f52b9576e984422146e49'
            '77ce2f359206a3d44c5b8948f7408631279091a367e1cb5b196963a94042398f'
            '51e8556c7f6382f24b720d6590469f50760bde22de7c74552a898be4b3dd8b88'
            '5dadaf322a90a7426b7154039e2d1361360864141b552d8c120dc2a5db9d8acd'
            'b1f1e976313502502adab2aaa4eba81ff7f87f42b434621c21252af8b2e71b10'
            'bb68d6b74e653418044dac232bd17736f9fd436dce86c18da904c4ac08952cbc'
            '9c1e1841e68ee0067934e3c4349e073cee65859569fa1c26108e7301c002abca'
            '7c264aefc71674a75746512f8ff52b62e3f0fb19a29cb9a111e7fd580823cc2e'
            '5a9d9a37266e01cf2bf76ffef8c0271123085d4ce8b6e212feb1fe4f89c8b7d8'
            'a8d8c204871a71bbb7cc3a50814890e44acaa88e00b9a7a7a10a6e51b3620a1a'
            '9fab3a160c8c30babd4e1b184600e5f6fd226cdecbbfc993159eb09ecfbc48c0'
            '0759eefef0afbda80fe4df7c617f15ec933162459e89358e40507cc18242f5f0'
            '28667d42075a615a8bf12cdd570c4394891ddb6be96098183d9fdb0e926b4d6d'
            '12affa357cc13fe845e6df97c5d6a3623a321d6f2986f8b25728fa1d183ea018'
            '7e06bc85539de09e95cb243bbcad745e25334c920590a30988d43d3ecd754878'
            'eda6bad1c5f08b055a1c906bf1e1290f989d261d89b3e700a8a71323d0ef9fd9'
            'ecf2438f79b359de1f76447d5325bf43e91b3c6ecd86dada9889c8b28c591ab8'
            '46e483eeb7daf50742079d55289509c3933a0d51ce759ae34f5f084124378bfa'
            '74841c7368d528aa41c95b2f9784c23055579bea4197625da264ac07457b7b58'
            '734462fd8a6fce509fa309c6de0e6c7213402b0ada92a22d197b2acf6cecf89a'
            '7e7056e96bd2d5be769b281f38da7386d851af0f1f9af8807a38c3b261eefd1d'
            '3bc2f4a9440df5b1d3dc5aa9b84aad4ea02be9fea0c789505b1be9b8269fdf80'
            'eefe8432ad3cbc4e024afa9644f7a4fb5f300fd2759f48e35367eb9123b7a762'
            '493d774234f25d1117e4895b7de56a5660630814e3cc442980c68ef6b3406f25'
            '47f228b9fc6f8ca87f5b7b6febc50a4a02ee4c613dc41aa4146e89854cd08fe1'
            '795e9403be1b1f079c37d789c8a23ea9ad964520dbcd4a5909ac01f3f58cfa1c'
            'e952469240e7a9965cb51ebe74da3e52f74c5532ab6e0d22b03287811d823ece'
            '8ea3f110a9591c1564f12111c7275c3217b71062589abf50ff0b35dfb5c3e916'
            '6fdc95343993f7ece34d25ae5893bdf127058d56b42b7b5c508a96ba797d1e51'
            'c80125ce411a21c2dd4f143c25f28efe46620a740ed37e6991ca113f43e06fd9'
            'fc85313e956728c7d6597a02259ca9e619fc03a98b5a8b3e555179bd43334a47'
            '6d3b5e5183e3456cebb81014711531ad36973a70b350ea478deeb3dda03ad9b5'
            'e5d09364d11f8b66c488213ddb418028fbd264319b4e67c760b35bfbdad65e06'
            '7a9a158966c422086eee80b4a528f790d39b334e8c56c1fca42a9b1b21e9c8e1'
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
