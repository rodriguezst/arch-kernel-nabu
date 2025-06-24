# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.15.3
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
        "http://www.kernel.org/pub/linux/kernel/v6.x/patch-${pkgver}.xz"
        'config'
        '0001-SM8150-Add-uart13-node.patch'
        '0002-SM8150-Add-device-tree-for-Xiaomi-Pad-5.patch'
        '0003-drm-Add-drm-notifier-support.patch'
        '0004-drm-dsi-emit-panel-turn-on-off-signal-to-touchscreen.patch'
        '0005-Input-Add-nt36523-touchscreen-driver.patch'
        '0006-nt36xxx-Fix-module-autoload.patch'
        '0007-NABU-Added-novatek-touchscreen-node.patch'
        '0008-drm-panel-nt36523-Add-Xiaomi-Pad-5-CSOT-panel.patch'
        '0009-NABU-Enable-gpu-dsi0-and-dsi1.-Added-panel-and-backl.patch'
        '0010-SM8150-Add-apr-nodes.patch'
        '0011-ASoC-qcom-SM8150-Add-machine-driver.patch'
        '0012-NABU-Add-sound-nodes.patch'
        '0013-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch'
        '0014-power-qcom_fg-Add-initial-pm8150b-support.patch'
        '0015-arm64-dts-qcom-pm8150b-Add-fuel-gauge.patch'
        '0016-NABU-Add-pmic-fg-and-battery-nodes.patch'
        '0017-SM8150-Add-slimbus-nodes.patch'
        '0018-arm64-dts-add-wcd9340-device-tree-binding-for-sm8150.patch'
        '0019-ASoC-qcom-SM8150-Add-slimbus-audio-support-Also-adde.patch'
        '0020-ASoC-qcom-sm8150-Fix-compilation-in-v6.7.0.patch'
        '0021-NABU-Add-wcd9340-and-microphone-dais.patch'
        '0022-drm-msm-dsi-change-sync-mode-to-sync-on-DSI0-rather-.patch'
        '0023-drm-msm-dpu1-improve-support-for-active-CTLs.patch'
        '0024-drm-msm-dpu1-use-one-active-CTL-if-it-is-available.patch'
        '0025-drm-msm-dpu-populate-has_active_ctls-in-the-catalog.patch'
        '0026-drm-msm-dpu1-dpu_encoder_phys_-proper-support-for-ac.patch'
        '0027-drm-panel-nt36523-enable-prepare_prev_first.patch'
        '0028-input-nt36xxx-Enable-pen-support.patch'
        '0029-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
        '0030-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
        '0031-NABU-Add-fsa4480-node.patch'
        '0032-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
        '0033-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
        '0034-NABU-Add-flash-led-node.patch'
        '0035-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
        '0036-NABU-Add-hall-sensor-for-magnetic-cover-detection.-H.patch'
        '0037-NABU-DISABLED-Set-panel-rotation.-https-gitlab.com-s.patch'
        '0038-NABU-Remove-framebuffer-initialized-by-XBL-https-git.patch'
        '0039-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0040-drm-msm-dpu-Drop-BIT-DPU_CTL_SPLIT_DISPLAY-from-acti.patch'
        '0041-of-property-fix-remote-endpoint-parse.patch'
        '0042-drivers-gpu-drm-drm_notifier.c-add-include-drm-drm_n.patch'
        '0043-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0044-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0045-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
        '0046-NABU-enable-rtc.patch'
        '0047-NABU-disable-Sensor-Low-Power-Island.patch'
        '0048-NABU-enable-ln8000-charger-driver.patch'
        '0049-clk-qcom-gcc-change-halt_check-for-gcc_ufs_phy_tx-rx.patch'
        '0050-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        '0051-nt36xxx-add-pen-input-resolution.patch'
        '0052-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0053-arch-arm64-boot-dts-qcom-sm8150-disable-broken-crypt.patch'
        '0054-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        'linux.preset')
sha256sums=('12b50c89925438d9cd7385a0cafc9c433e6562ac5df00a21889fce9f548d65b0'
            '4dc11b9c6c84cae146f1da95579c6294ec58727170edf227f700b777d433ba22'
            '7f95accad00f05e5b4ecc7c07a9d79638622d8ed90505793efe2ca0baa367f3c'
            'c2e1112e5c022313b2eaedf86679e7fb0fae556c8b80ca5420289b498df75875'
            '3ae71ff6b850e10b3f048081b93885227725a95fe6579b4b44c7ada2a711b171'
            'b1faa45f94b5b61a83005c0376f38bbdceb1c7b812a52f5589121448cf9c599a'
            '061953b421d65e0258129512776b658a84b8f00b851ec4182ed3627df30e5707'
            'ef27c3fad97d5afe164b799922fe9d54b002bbd7760325361050b490d0def900'
            '8bd9218b7f78912886913f2eb79176a10d4f3cb3656ae77b0107ea00bebe1c40'
            'b72795d23323ace449c73d8bebc4c06db2224888c277b4fdd164079f57820aa9'
            '8a11408a7b51d65f0c2a598a49600d6236d75c553ce113048a053df6e76a1e25'
            '498269ed6254ab7830a1b0e724b8da19fc4f37e18bb6176659d697556f16faf6'
            'fa6878ac7b0f57190688e3f218c0182ae51648fb149bb09d331ed172edc8ad7f'
            '1061cb40f9cf9be5162fe95f37f4f3516d0fac6264991196b99520ba363857dd'
            '6ab58366c78087cce0680fa844140835b4e58ed41d87531f499e1a2ac008cb34'
            '51f362e003ac0bfe1a30dbbc2d2dde054d9f0283a5e5dbb4bd6878d1d253142b'
            'd366c2d414d77f26f2108653866f436fc2f3efcb7e99b0958785266cd1ce2029'
            '1f035001f0f0281364ce8a4fc3f47c8f916b20222123a67c39386d93f0054704'
            '60822199f57798e56637829cad645d2b4fd46a7c7be09ffcacf4d3636f11b1cb'
            '8f2f1b7059dd9265c99560e5c4fc2495591fde8f025ca204d441882280b27a7b'
            '4e6f17860e5be0673cc253d27c77348476d90e3c49f09862507e638f6068b834'
            'e8fea826a849116aa6877cf6b77ded5cce84ba256a275db0ed725ac1cc0c6d3d'
            'c28cd2eb6a758397687bf4730e767c4b58b389f8097cf7a5cd6ff07e83496a2c'
            '168751aabd3b9ad5bbd153be4d321034d215cca2d57fb245360d4b220c5e87ab'
            '0253ae624ce195527dab5a99ba66226afbfc7d3bbd4d73b4cb8c37d9dbc37050'
            'e517a306f54bf21cb6f963ea4e11decbe9901c8e633a371c93769b4344fefd9d'
            '1ea279347ca576118a67c8ec887dbb4f8d02c0e02425fb0de97943f08c2d9ec7'
            '1051bf6e817b45e237ed33043bf5c509dfe2c412db823d50659533ca6ce1f2b2'
            '0acfbd9fcd77045f4145468608c155eb613447911bcfd813705bb091af1022fc'
            '7f0879bac6efa4b1b45296e37a82324318d637567d7596d4272efe95d771c155'
            '8be97f942a1f5cf1477f523d8c2336f54ccec43f465068873e77dab74e630752'
            '89fdfc35cd026374701e0a24479407e2b07ebc60ff21384576dfb7ea1d5953e1'
            '64ceaa368cc79b5476ddabc2acfae14a07b8dbf2ece6768282c8527ea5adf742'
            'e58020343fe3c28f2e5de8cde967ea9c2dbe55f257af24b8bdd7b31dba4b4a32'
            'd627f5a55ec1414a5744d05825195985a93d91075c7d7837b56a4e50a398da08'
            'd175a5db77538bb3d190d89d36fcb498e458789cd9178f63513e31010344d703'
            '121795969409b51d8bd30e9df321c9db89ffb26e43d64bf69a2e18060bd805ff'
            '52b096d9a243006cdd10f7116f66fb0def5a2f3aac04e17345963073ce358447'
            '5a4691a6b889eb9d83fa899d7cfcadb1847b20d869819f2c56937fccb3833470'
            '7ce98301ef1d7d475ac02d80ea37a66e587b84fb5a3be5040359fe937808fec9'
            'd9830f2595bc18176be3112417a4d1caef03be5ed3a42173835e9732f70acedd'
            '7353b207c64fb24adb61cb3a4ba2e666427739c028d26839b6b070f03fdec973'
            '0175ca7342eb3306505b347ee75c567a27a6b9ecc384b2de0547c1ac784f6ca7'
            '766ee237407d1592b72868b75d26cc562249b7a129dcd9ff9e66301dbc225d0e'
            '9ee5a7821bd84cdcd12bbedfbbf172e0f7e0696150149c64dd30f0218dcd481b'
            '7520ebf4364abcf8b405e9074293d65f80dbb0c4da7f536506269047974c47ba'
            'b1c50280a40b36139bf6521b767e6f2c1b823de0463db13cfc4f7d40c86004ab'
            '0c2ab86f38bfef605e5cd529d20b9a06de24e16b1670324070b47d0b197cbcb3'
            '0f545c00db62f0069743362bd06b027a575ac5b2321cf46b8bff2d78e5682bb9'
            'adc17f8ca4d97036e74f2fe686a9a6c01b0228ca3f9f1d7ceb6fec311a41da42'
            '1d4961ddae41dfa77bf8cce61ee22a5bcf030104ad208e7f5ee505f1172a3795'
            '532826f397ae09d11d6a486d72bf05cf4ef479cda85045c43e7bd5bcd817fdc6'
            '6bc5b91105b2f78ac4b3462c1d72cadaf51587a8a2193fcc7c36f627b1a8589b'
            '0ebc5c36cdebbddf686fa88552ed638527a85bb2e6f89b32dafc97fa4e73c10a'
            '9aed0a023f0e7e0459ac817dc5d38cbd947508410a3a49e17f93b011dca774f2'
            'fd319a2e2d5b10deb4aeae6a01a5c601e4ca0100cc580a80eeec5dc8eb34a4a5'
            'be0e58cfa8a4b898467e7b2ade2bec835fbbe61c2533502c2a68c6885be49d1b'
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
