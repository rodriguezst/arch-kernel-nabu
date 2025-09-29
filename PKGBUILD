# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.0
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=104
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
        'linux.preset')
sha256sums=('SKIP')

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
