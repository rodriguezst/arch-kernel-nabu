# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.14.7
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
         '0029-drm-msm-dpu-Fix-dpu-sspp-features-for-sm8150-Why-was.patch'
         '0030-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
         '0031-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
         '0032-NABU-Add-fsa4480-node.patch'
         '0033-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
         '0034-input-nt36523-Remove-fw-boot-delay.-Should-be-fine-b.patch'
         '0035-NABU-Add-flash-led-node.patch'
         '0036-NABU-Add-ln8000-fast-charge-IC-for-testing.-If-it-sa.patch'
         '0037-NABU-Add-hall-sensor-for-magnetic-cover-detection.-H.patch'
         '0038-NABU-DISABLED-Set-panel-rotation.-https-gitlab.com-s.patch'
         '0039-NABU-Remove-framebuffer-initialized-by-XBL-https-git.patch'
         '0040-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
         '0041-Remove-missed-dsc_active-duplicate.patch'
         '0042-drm-msm-dpu-Drop-BIT-DPU_CTL_SPLIT_DISPLAY-from-acti.patch'
         '0043-of-property-fix-remote-endpoint-parse.patch'
         '0044-drivers-gpu-drm-drm_notifier.c-add-include-drm-drm_n.patch'
         '0045-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
         '0046-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
         '0047-arch-arm64-boot-dts-qcom-sm8150.dtsi-change-reset-na.patch'
         '0048-NABU-enable-rtc.patch'
         '0049-NABU-disable-Sensor-Low-Power-Island.patch'
         '0050-NABU-enable-ln8000-charger-driver.patch'
         '0051-clk-qcom-gcc-change-halt_check-for-gcc_ufs_phy_tx-rx.patch'
         '0052-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
         '0053-nt36xxx-add-pen-input-resolution.patch'
         '0054-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
         '0055-arch-arm64-boot-dts-qcom-sm8150-disable-broken-crypt.patch'
         '0056-nt36xxx-Change-pen-resolution-This-is-done-to-be-abl.patch'
        'linux.preset')
sha256sums=('8112202bc26d086957a94d2109a6dcd4478c5ba18d0f0a5e1c5dfeea01f54972'
            '632b8428077584316178b17ebf385336c6d769cdc3f79ac8f6f81db16ad64515'
            'SKIP'
            'beb6beaedd56c0be952f63faf1a4132e0fdc697d1a7e60845b588ea536dfb92b'
            '3fb272330c282cd7b06a9ea9fcdaf40f64c6362923ffea31d8e4644bcecb15d0'
            'f56e360b227814ed66311d221c0665856922f95c71574d8c66477487963772e7'
            '849ee4e26c2d224fe003517dbc5b4ea17be209f0fd34f922b42b890093e03383'
            '9eb0eabde02642c47b55e17d0b1d1b1214a70692b69bb331a39f9e96a80ad454'
            '978ed0dfb29288d7273bb1a7a4913943e711b34f838214ad46fd37dd92e405a5'
            '0ac622e7efd9cdedb7eb0bc989680492f43884deb42026e699ae28eecb994365'
            'a3f24185e9e28e3e941ee68461dfca322d220f4502f20cdd208846279bb5a7ff'
            '65e622ce80ddcc28c6fa32b8cc060c059513c11f1fa1087dd9bf30579191ce96'
            'ab958f6b61f80f66060dc94e9e80111208a441937b32abe2cbdab886e94cde45'
            'fd56379ed4ae20a1d1716b555bb40584f3a3463cbcc00dbd9f243a580407f2d9'
            'b8440d14bea0714e3b69e4e8c2b2a1bf0025b1d9d47721745ed56f6fa222b54a'
            '5d17fba63c8dd58357a6f70115739dede661130df21de17c914399f9244a9e48'
            'c10391e8c3e77ca37fb9dc324feb110262e203b919e89ad6fa5f5218b90abba5'
            'f3e16e1bef813a7cb4202dc591c4ff6b5044d2d323d82a6b81f975281a9d2795'
            '869e216008a80876067215d1cc27755ce62bcd433dfc5cc129eddd58273af194'
            '0bc4f5f9bca6bdcae6e9525df5f781fac6b430a7387d8c7e61e1cb492dac429b'
            '9345af44d24fb0cebdb636cc1a7abd981623ed7305ab68f58a84a77bd40544b8'
            '1a3074ec5dd48356a7318d85d813017af6dbb3d6c1ffaa543154aeb360ced5c4'
            '94e06fbd60867cc8df38b2a847317b3021b90a396061377dcb0d201cb10afa2d'
            '2249ab92662d9a97374c4f6a6fe03ca9970e0884235f59b9d9ee5a97972f098a'
            'dd5222f659427d4e07b5a243af8af8afdcba6719a603509dc26b08cd7ae744d7'
            '897c942989b17db5d7203aa19d1130a03a57970e667ce19ceb27194d27bdcb5e'
            '2b7a86abafba686ede6ab440c4964c0f40326a9f9c34029962bef8aee8d3a723'
            'daa78830f153be9ce578351db80e1508dfcad9c7570aee7a3246394062baf9c2'
            '24f644b83a19b5e83a3ae4c5db5878337986d93533474cdb1bb95cec7d95c309'
            '33713a846015e230414221aaa4c919d4a6154c7189fb0193513453fdcd34c9b0'
            '37a86ba8f6ed1e1618c0119ab2cb13a8ea75a788ce1955db00c9beb31bbcfbc3'
            '3fa37e5a8f59c3664ccfaddd5c23ad6329e2c5818218ba4190b2e65cb8bf6078'
            '0ad5fd03f5cb8b5ae3dd60c6187d83ee1d584102bc81c2fdee2029fc98d964e2'
            '178b4ddc00edb9710ed038086ad39fcc0d675ca50ba6619b66c226bedfadab57'
            'f85038f79f61e32f75ec9b934d46e85f48f6a08490944863210ccb55f01d520f'
            '6722d2eef901f41af330a189d23e771bcfa340309aaa01386b5e8f4860549229'
            '2dcfc782c9ce88641fa62d38b28720c4d7d111cca2bb61a7eea0befc8f448772'
            'b15d8a106c622240a52c19e1e0a23027d20160565dd2a764ddf6cb3ea9c25b56'
            'a1207c80a3fcfdd4f6387d1134b9804c7d720166dac800e5702ef8fd8f7898ca'
            '65312c6241e9ffe452ee97c2b9aaa1cb0a088540a3e8772ab66d8ec6dcac8a3e'
            '16c7fd652377a4bbed569f916bb3b5e4a5c2d5b99e4f098cfbba37d5a7238ce3'
            'f92a468ef5daab7274e9389a71b03781414c1f33904fce45da07a03f36fccd40'
            '53bdfc84808c053f92840945dc331dde1bf43097f61f18f0915336e79f5f760e'
            'b418aed34448a97099fcd61da3c60024c9bfbb699d8afb2f039291d6d2815568'
            '82d1e709c3979dd3e51115419d2c4f30dfc3920c0474a3bac452be6cb1757919'
            'a049c3c993be9b28f6ffa86eb8dde4d0fc20a6ea52d7212fb40b39675e79c4b7'
            'aa0854577aa922ab3e202a5f7194a50bdee20d69769190ae9c7d24a7fa2b50ed'
            '3901f9a5aa2bb854acfbcb628bc4e3d9caae445f43c85785118e2d53a1da92ca'
            '1ac80a09ccd7486ad8ac37fa904290f17c0258b06b4a3e5d2401cd1d82ba1d2e'
            'aa6c7d2fdcfc9a7558e7ca9306988ab29325adea36696ecdb72cf0d569f2b4ec'
            '38b022ffc7609be3c5664b4d29572e2c6cf833a4bdf98aaa4d054361d7d68586'
            'db2f5785cbf3322e9cb3e06d3e66b03e254be6f1de5492855905297895981c6a'
            'bc92d0ee8eb79f8ba3a3f9c1a4742f75b3c2433436715e3ef8ece676d4e15064'
            '5ddecfbacfeb16a911ae7883466a42236683a1f195c85ba1925c126c31891897'
            'd264182c2ac0cb4c9556a9d4066a58115b388dba85d7f1b69f0046d675acbe27'
            'e77d4017781b975062c1cfe7cd43961a82ab01f6493bfb98766dd8e6d452421a'
            '9cac9287f801abdb7f3b6943eb4ffb0ad7da86d6d09fb60fc872a2d5dbe3cd70'
            '13cde571d7ef9a6d4051f02651fe9e40d0e113c5da358a31d017ebd81a226bec'
            'bbc97006408fd7d5b3e806f35a2c3322ac23bb6b02c392be3d819e418f634f48'
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
