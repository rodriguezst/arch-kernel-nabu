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
        '0023-drm-panel-nt36523-enable-prepare_prev_first.patch'
        '0024-input-nt36xxx-Enable-pen-support.patch'
        '0025-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
        '0026-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
        '0027-NABU-Add-fsa4480-node.patch'
        '0028-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
        '0029-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
        '0030-NABU-Add-flash-led-node.patch'
        '0031-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
        '0032-NABU-Add-hall-sensor-for-magnetic-cover-detection.-H.patch'
        '0033-NABU-DISABLED-Set-panel-rotation.-https-gitlab.com-s.patch'
        '0034-NABU-Remove-framebuffer-initialized-by-XBL-https-git.patch'
        '0035-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0036-of-property-fix-remote-endpoint-parse.patch'
        '0037-drivers-gpu-drm-drm_notifier.c-add-include-drm-drm_n.patch'
        '0038-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0039-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0040-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
        '0041-NABU-enable-rtc.patch'
        '0042-NABU-disable-Sensor-Low-Power-Island.patch'
        '0043-NABU-enable-ln8000-charger-driver.patch'
        '0044-clk-qcom-gcc-change-halt_check-for-gcc_ufs_phy_tx-rx.patch'
        '0045-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        '0046-nt36xxx-add-pen-input-resolution.patch'
        '0047-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0048-arch-arm64-boot-dts-qcom-sm8150-disable-broken-crypt.patch'
        '0049-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        '0050-power-supply-Fix-power_supply-API-compatibility-with.patch'
        'linux.preset')
sha256sums=('9b607166a1c999d8326098121222feb080a20a3253975fcdfa2de96ba7f757a7'
            'b15f2ec83d0da2e87d4f7075525e05191a180dd37b7cc98e8d30ec3b7276efa9'
            '935a83cacaa4e95e6a55e0540ef84d26d3efe2478936e6cece1ae922a7f7fbb7'
            '882ed17aa6dc6caa109febd9944ced3e5887900ab2bbeef155003c84541942ae'
            'a895460adcb7817297e8e247cb606648928a47eed757beb1cb424024997973ea'
            'b24f98ebd76598a4167e9d8162a89d5b4b8df71f7fdebdd5364935ea9b9b2031'
            '0838b351374131105509b8245c76ef8914357325bc5f9ca46aa57f91284d0635'
            'a4b5b7f2c1e7043c01d04e1fa195b7812fd32d2da719d4b4d9c65f2045f5af6d'
            '090f6c85a3c20f4d10a2f954a153a27f2ce9f802f75c653d7efb3986faba9baf'
            'd2e0788c1f14c541bdbab419abacbb155e873a41fe184e39a9956d8f0d914f73'
            '3afe2684ee7534c50500caa789c6df7e217fa881ca0881773c1f9c7c6a3d3764'
            '11e39ed1bf3fa6207a33e2121496c4011d3f0e7d71b23e5c700e9926ae7c4e07'
            '4f5ed4bd18427ddfec0da67246a75fe7538f2d9a77e6d0bfd1c38dda0748db2d'
            '6741ab5ac91535a13dc8cada5fa74a0af30b54fc1b2e5eb9637e8a472020b01a'
            '6472ef77c055b88ddbd442b774790ae185fdc30d7f0ffcf18bfc2b62d792af87'
            '81f2b58162ef7784aa4e63cc6463ad56b60f3c29a7752fe9a2df1447f372c41b'
            '8c2447d0415215dc902fe437cf413a337c864ee6f34cb3e26c54b54d96e7d720'
            'a15b19e52ea13265d6027e030d27df854b2a045f1f48355dae39980da3df1ae0'
            '879f57833947e555bda751145761f3d3a0357cb9c4ea996f5e748960c7e130c9'
            'f9af43cf78cc2e6e66496f6512af7f64400f58519e90be9d685f882982b8dc7d'
            '37a4523bffd069942c00d23664f659e1e1b0f78283abe97fa53a76ce559eafa1'
            'b1edeb4021c7957082f0cdb971bdf96b6ac5fcec9ebc7437cf46dbff2f2e7927'
            'b6ecb56c85ee6b2cea4496e0f8e35961185d67802cf5c708eb6e0c9fcdfa8b99'
            '4cc89896c12d2d8b3219c4478907ecb6b85a4f1b1fbc7b6e92662bf10e6e0b64'
            'aa33aef5bbdd939fffe0ee6411c488f56696eb3085f4c62a81d788f448d69b3c'
            'c4dfc5041b1efdcf8e15bc04f94a8473488fbc1d6a011bffc0ee97e55691787e'
            'fdbf7055e123030c82d037071af64f7dadf4252fbbae248bd607e550ca648735'
            '54754b307c4cf32e67bbb64e2d20aa71ed12970b00ed6d5209d152f3adc8aa84'
            '66f23c4fb23e7c40512714e54fe0ec50bb28f59e7f85a07a5e595d1bff61bddc'
            'eea28ce2d64d95758d6367f1da84d14b4a5f9ce17f895af519491db06806fc10'
            'fbf6e88543e7de8f8639bfb5430c94f9603822a21bce10b76e1b4fe99cb7fe52'
            '099a1228c9f46209f14f7b98e09f3a2a7bbbd5c862e3bbdfb7fe9f3fc92c7a2a'
            'b61f44cff133a266cba04734e2041dbc0ec96e558a7f7b9ded80537b2c665355'
            'fb611a6407e488542c927b920520ff70daf63a446b9e697624d758486a7264fa'
            '173557974b9ef77da0d84a586d10e66635c9f95374c4bd0ebbbbc440a1fb61e8'
            'c5b12d955ad5f48c9cedafcf7e1de6f0ed62dad8d5fb11587670e2eaaca0882a'
            '287e847d0279c3330c7c912705fb1a95188ce4691be338e98eee0b39c272a9f2'
            'b2ed39567f8d3e2bd40ca9c11fc10d00cc74e6a56c19aea363a77412b455f97c'
            'a930345a2968de84525f288dd5d0f431ee3c9d7a9a8134463acedd17925cf945'
            'cdfae4be7edf419a734263909a5214baaf2dc47df884f435f07baf0334c74ba1'
            'eac421124ddcffcf6502287c592bd6e0113ac2430fa19cd9e7ff021cf171236d'
            'b2972875649d670b5345df2dbf860896eed70a077c17efddd3e54cda6a79f5d0'
            '300906955ac71a6bff31563a2483662b40c57038e07aa71d2ade25600c203750'
            'f0f982c167f5469f4d134418286e9ad6ed6a6e75cf86b5dbf37b1f5b01f3e8fc'
            '8fda3a6410ade0f297f18e1725fdce22921bf7d7ed703c052c0200c7bc6fabc5'
            '5c4e998e278dc53add835bea0bc92e879815e5fe9ab012eccda5ecd9e1d33509'
            'f4a5a9601ebf24d07d1b743cf4c8a454cf87ba90d648a1b0ab4c69d191fa26cf'
            '2260b9375d8fae4ba561fed06e5f15fbfad68e31c8e76e28ccefc193f3ba7135'
            '276d9881a76e886400fbae5013c887a34ff36c6ff4aad985e26a2ffb2361f09b'
            'fb5d2717fe2ded4abdff65a5688fb3d18037a98256739aa99b03e45d7a71f139'
            '784e0ee500b898417ba45700f03410eb9c807d94a655fbca00cbb5396f47716c'
            'f9839ce60bb36e8323c0048ad2da184d8634be2e2f10db9ca106636a9d8d2dc3'
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
