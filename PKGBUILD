# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.19.11
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=2
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
        '0039-NABU-remove-resets-from-ufs-related-nodes-to-avoid-r.patch'
        '0040-NABU-enable-rtc.patch'
        '0041-NABU-disable-Sensor-Low-Power-Island.patch'
        '0042-NABU-enable-ln8000-charger-driver.patch'
        '0043-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        '0044-nt36xxx-add-pen-input-resolution.patch'
        '0045-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0046-arch-arm64-boot-dts-qcom-sm8150-disable-broken-crypt.patch'
        '0047-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        '0048-power-supply-Update-to-kernel-6.17-API.patch'
        '0049-arch-arm64-boot-dts-qcom-sm8150-add-reset-to-mdss.patch'
        '0050-drm-msm-dsi-Move-MI_DRM_BLANK_UNBLANK-notification-to-.patch'
        'linux.preset')
sha256sums=('20039d7b6b256c08be2f8fac43c3ff9a620308c703c643cf2f80c3910b9bd59b'
            '3bcef0458491235064d935da63d9577102af0c08369408c1f198f075b9873c1b'
            '947cfc2f7c584342b884310af54f13a6c81d7098eb0b077e9bc4860342644eb9'
            '6a5f8bbad7f2a6c6390a16339c11d301d10e08a78a12e4f112e35ed3e8902129'
            '1280f01ee03504a838935e895a6ce2043bc6af3722d7ec1371c382634e6561ab'
            'b1c176c93cfa6e7bdbac19e6247d8037d8008bf1f3b9828f6ea78b3d803dbb6d'
            '7ac7b54dfe05ac22120a8eeb9f4ff89b790398ac697833808d5af3573328e44a'
            '80eca7e9e9ff25aff24ecc319d9f629491483395b436d1fc1f11bd7edfa2b0d2'
            '3eeebd6e1b7e231118db3ad27274583e7f0ce42d40ceb67d2cfa6f62c14a5c5b'
            'e84ce98fe2f06ad5d8fd4a13a205717f87b4709c65ef3e140bad6a7077fd10b6'
            'd8057b4b21c93a7c9e566ea9f71d0d010978a3cc97c4329fa75e9b527e1cd224'
            'ebb83f47b413ee15885fd44cbba90f748524b1bb0c25b6a06d58162f19cffe6c'
            'c8739931fb7793f1b8c9c45f6cfd4d51b793fb67dd51a0b8f420bdce17d44c1a'
            '0207017f83a2dfd058c04501adebe1fead37fb7826431346c159a3a5c421b8f4'
            'b689e16d662f87b4a453546472bb420beda193679eda7d0df900d9cc73d70d5c'
            '13e06389abefabc286656e13ebfee9d5e72e32f6eb96eb026b07cf6865f26f31'
            'de5efbc823e58648cad3061b727e8ddd98e02bba24dfada7ebb5ce400735d47a'
            '7d1d2c8a678441be30a1a8edb14c421f8da3d1c42915e4ee09826f68e02a4b0f'
            '030b596528159fee22dce1e35c0c8d5651d147f74a19983e2b0bd7ab42e82c39'
            'd9d95dfa2c3efca86dbca884fa63adc8842d73e496aebb218dd4a5b42f338796'
            '5dea24acc0d2b990ebc121a4fa62722f9c983e17a8d3073620ef58a3b9203fde'
            '03e422ec0ccb633cd8e69ec6f2267488290e241f88653444742db89b6e8c63df'
            '6d8f5bbe7b31390277def5bb40948600f6d9f522989dd79229cce4bf8de96234'
            '8c6c7cb52e0d548c2340438bb9b5d11a13f8a8b2f1c8ec9c22ef1d8c8e071ea0'
            'a7a55e80c3177751554da07247ddabb14376a9bc1b531346d9e2cf61072791b4'
            '7f7709df0a0ba2fb10317b5641bb7ac0beee0697052652519b6b2fc1b5ca2197'
            '40d6cde3c9fcee7fb9ea8ca2a07f30919beaef740bd6ae701e77187197ea393b'
            '1b3d9accf66f7c427ef4401cd952424b81edf7090701a4453ac2916fdf27ec89'
            'fd84b6fd25e1f48b90d417dcfcda6de449d7b39cb68c32ca29f02def3978be65'
            '7554ac8dd23ff08dd1118f62d37e17cf6843a5095e8abb6f3173f765f42054b7'
            'e6663884d905e58ee9834b4e9c7fc3c728ccf7385d47aa55043e663937ac152b'
            'b9b6f2ce5381e619528e72fd8c85fd360348f5fac087d96bc43163124838bb66'
            '6d65f1b71d419859ea992a1f65e5ac74a0ee3bb63ebefada4035ad3a69d0c042'
            'b0f2075c3810b89e90a9c44a373de9502ce0aad56b7467fb2e8a738d263ba3ec'
            'e868fe44b02bab912a43a164eaff7b9a5823de825288c0984d90ac55b6a67393'
            '07b2f476ea51d005464797856e8c92bb2e36772809fccecb3b2ecbbb94087af8'
            '098a731d15e7baf01551e16daed3a851fbf41f5243c6ae638886b90ba2b5d0d9'
            'c1dca83a8ef674a3db137aa578bbbec0e8d5491452b1b26ff14122658cb60c1e'
            '25e4afa9c94dd7fb2831f2f5b7d34d6287ad578a8922d1f28646c24efbfb1ada'
            '9f2d6ab6ada28d091ba1eac25c249dd50d8078d9e4c6495972d74ca57b25e0c1'
            'c7ff8cbf31883deecbd2f93e2ba6b9c9edfac0d0ad50660d53c6e8234bd5ff1b'
            '5ed52a4c41f72d2c005463bfe8f65099a9a80000feb5db550a7547d0aa41cea4'
            '8e770083d16a4440e1b5bb76e9b8139270f81a2f22ef602950419fdc57d52251'
            '29589fe9b7a4c11bf81ffb3a1656a1dd7e1c556277b1472ca66017dcede14b6c'
            '18ce6a018ada887d2b757db2bcb29481168e6df9ac6941676a411795265cab1f'
            'a0b4b0a21adda306f6bb222e8e2ddbb1d75e58020fffcb96336099da03a5c42e'
            '7b231d557a74e84e26bb4565f68180d74506dd9c532595599fb61da8358ed523'
            '91c4cfe3f307b6d4e1b31c61d475ca4894c8600a1cdeef852c1b341e18336822'
            'ba5d5cdb0f518b6ba2f7081cfa4a824b99612b6cb583070ffb80f7bcac225735'
            'cf52cc138ac5323ba147a88551aac01e0f3764776e33a8f6db38e0195ccd6a7b'
            'e863d51a077b5e80809db46ad1d0fbdeb7658bfc922c74314756a30aad6e2649'
            '247a77569c986ce6a52a1168f5223131e4c828b1cb49a496a6581c9126faabbb'
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
