# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.17.0
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=300
arch=('aarch64')
url="http://www.kernel.org/"
license=('GPL2')
makedepends=('xmlto' 'docbook-xsl' 'kmod' 'inetutils' 'bc' 'git' 'uboot-tools' 'dtc' 'python3' 'systemd-ukify' 'sbsigntools')
options=('!strip')
source=("http://www.kernel.org/pub/linux/kernel/v6.x/${_srcname}.tar.xz"
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
        '0023-input-nt36xxx-Enable-pen-support.patch'
        '0024-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
        '0025-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
        '0026-NABU-Add-fsa4480-node.patch'
        '0027-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
        '0028-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
        '0029-NABU-Add-flash-led-node.patch'
        '0030-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
        '0031-NABU-Add-hall-sensor-for-magnetic-cover-detection.-H.patch'
        '0032-NABU-DISABLED-Set-panel-rotation.-https-gitlab.com-s.patch'
        '0033-NABU-Remove-framebuffer-initialized-by-XBL-https-git.patch'
        '0034-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0035-of-property-fix-remote-endpoint-parse.patch'
        '0036-drivers-gpu-drm-drm_notifier.c-add-include-drm-drm_n.patch'
        '0037-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0038-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0039-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
        '0040-NABU-enable-rtc.patch'
        '0041-NABU-disable-Sensor-Low-Power-Island.patch'
        '0042-NABU-enable-ln8000-charger-driver.patch'
        '0044-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        '0045-nt36xxx-add-pen-input-resolution.patch'
        '0046-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0047-arch-arm64-boot-dts-qcom-sm8150-disable-broken-crypt.patch'
        '0048-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        '0049-power-supply-Update-to-kernel-6.17-API.patch'
        '0050-arch-arm64-boot-dts-qcom-sm8150-add-resets-to-mdss.patch'
        'linux.preset')
sha256sums=('9b607166a1c999d8326098121222feb080a20a3253975fcdfa2de96ba7f757a7'
            'b15f2ec83d0da2e87d4f7075525e05191a180dd37b7cc98e8d30ec3b7276efa9'
            '239a0c85ca11b5294e1441aeeeb786bb2230402918a3f7313914456016967386'
            '058ebcd2fbecc145bf24fecab8878874a0ffcf3b6264ebb324c7bb431fabe7c8'
            '5b9c4eea6a516ab474b41adc77ce7ec11b4d909e4b0eb9b7b6e5b43422629613'
            '99be7e111c81158b0b9347708c228625f6126b810df286ca2c43ea7964cfbb66'
            'f69d61eee132fc0c3bb919197f4e570279d2b36051c35292193194e147872009'
            'bab642b918355e14626e169fd15d733498e789b5f43de75cc18c6cbc4c39a848'
            '52ff1cb7d74bd6f75f396d116173d3253aa9c45c3ffa206e95340bc9ccc44dba'
            '0352e4f19d184f78866c520efc98a6ad966a0ad2f3e50bcda16b23b872a7890f'
            '8dbcb0f84afe1377c7dcd52abd6d78d39d98e9a935b26079042f2982ba0d6a25'
            'b3b9eb336da58aace9f5e341465f5fd35b1ab4ab875d414924d60088d3dfccb2'
            '32e92b6c1f13035bc2c824c02379feaab7c1e30517f48e7a9f2632b0b416cc4a'
            'd41fa58cd3313690335f38ede4c066de914b7d3e9276d2f68ed4dc77b2272647'
            '8d16eab0f42813a5a83658db24591a1d744cce39283a2e967a077789e28fe2be'
            '35b7f307c8c4b8e0ad819277efc0f51587bdc3d9376bc6f9e520301554827606'
            '529ad3bdf950cff9f95d9c5c7635ebac130e852a662a0abec0d5c9c44281e19a'
            'cab66d8969441f49f7c3de88c63f47b524b76e4b6496d1b2b92c90dd131d1cfe'
            'dde2311df908f973624756943beb0fb4a71d9a7e383ba447be6e3b3872c2a85f'
            'a2f5e87dc9038997fe2fcfb1f1a1de401d0ac837981e9eb5e3fbfca8b42c52c4'
            '57f84ba828c94db977206d0fbff38994612a6a5721aaa0bf7f5aed8b02111a8e'
            '317605d7c4ea5400b2dee4399c3ab655179944cc674f169e9d9a183254b2e3da'
            'f338fc8af306016311dea0aa738f2e92d8cb9126a162c6de2269c806877e15a0'
            'ae539bcd31151b92b2728a4d8ddbd6c22465743e18dd214d8810fde8499eb5ab'
            '9bc802bbbfac7360a2e46658198bcb32cfe2635d8fcd661f0410a9a3f0f2c4da'
            'bf0b1b5cab5d5b5c782fba71e3f84fea6932bb2f19bf1cae9d8ec053212383e9'
            '10219ca9dc17e05a4322ae40194da2fef8cbf403eaedf71a2a2d36641ca3112d'
            'a000ea632faae86254e1c9dc24c03bde0274d123b045189eed770bd76d852f79'
            '8fe6bd16074d4c6b4c91c68b053147e2455a0a7a036f7de0aebca0737b75f710'
            '0e00fbf351f4b46e16c98f6b20f323633af60d190e16f7bcd8d3c14d1f7d9877'
            '863c65e3d1da94620d027d77092430c013d63d0dc82b5f75006880d0996d283a'
            '6f23f2705edecdafd46fa682379bbdf7be384d6041f42883f70a88ce907856c2'
            '3407fe8b590d2f075d98fbb571c6a13e57c642960b466dc9d2eb7ac5e53d6b58'
            '848fa75ce9747904ea51343ec0e92d3693668f82ff2b908f2ab3f40894e6757b'
            'f7409a215be4610e204be1705fba5eae52344560d306cb4e54efb4a3f28f0673'
            '83485558021ec4049572d1eb7403e27a78622bec3a37b24f0706a9cae783a671'
            '8b7f899a2085323c22f3781b28db8e05495317664c48c6d6b64865f7aef6e6bf'
            '50c6768da4b205d557b91280c73a93828a7de9c444ab217d913030705759a8f6'
            '82be4c684ee64d02e66d417604f5226903fcd1eb4c856b701a6394befdbede99'
            '6876f8fe5a83cc36287ec6e8f3a5b03790f4f39c295cf6769f638ab975201f7e'
            'dacd39ba3510e92ec15dcf2573654f94cb56543c7a6825aa525031134ee55e1a'
            '464be53afcb73769e72f5a8476defe7e71344e67e96d693b28e04d0bedec9d80'
            'd48fe1f16dbc51fae47c123d56f378297b618f0968f092bdd587dd0c105a072e'
            '570b93c252cbc82aaefe618018d3da907a17b84610a6cf827e52905b6d7421af'
            '28873983c239155dd6df26cb2edbb1985e18dd2223798eef4e5700b7a3ac8f14'
            'e5ca40661cd73d32c1932382eb75588b7eaaca54f3485642eeb74011e3b4e6ec'
            'f1c729ec5da705aae4ea0b9e5da35c8328e2bf6039447e6434acb00cafff4c3d'
            '9b03baf4affa297e9730f114e2ef757b2e8bddf8fbc7c863b7358399488554ad'
            '9b4de1f7f59bd333fefe0c584650d785a843c703ac50a2458db73702eca766df'
            'dabbf5c8b9c6369571627149b42eb30dabb9dedd87a00332a35ddd17ebe11d75'
            '71f801b2e12c086126791adc3e1a65f16bd1891c15df045467dc3d795756da66'
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
  local cmdline_other="systemd.gpt_auto=no cryptomgr.notests panic=5"

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
