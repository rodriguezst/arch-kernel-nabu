# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.14.10
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
sha256sums=('de8b97cfeae74c22f832ee4ca2333c157cc978d98baa122f0ee9c01796a2fe43'
            '6ed2cf0d734b872ff433726dc18da14a501bacd4ec4e9d16c95daf1d9fc5bfa5'
            '19fde6cc3bf09aeeb1ddfdebb24fcd80076fca0cb403e201deb89c451b91f651'
            '2ddc902945a426f0b0c96dafc51b3e6f8d3bbd1799f7340ac576f1bdf9683012'
            'ff6fac711a02f7f6f59bae9eeb4ea0778db1973279d7996ab62423b36a13ea71'
            '5b4d21c8a64325512b3908abdf798f260c442c80028e5a21a3b35ff01a98aa00'
            '6c9aa996827b8840910cf9464a0b28f3dc86d73e4afdb70c8452c67151eda453'
            '9c87457afd78834e79ed8479877dd3be84a590b6cf55b9dbf46e7d9be9226f20'
            '204f4e382b41652c13dd3be9125e41aa9b2efd64b515ed05e8f0b06ebd59c202'
            'd44b4c4eb6a604d5e80e2f646b6204ee687cda5c23e72d7812b626f565180ad2'
            'f635699a7060008cb010b8a8a48bbe65816f2dacdade19b29fb7961d064a9440'
            'd7d9c875018ca9bc8b2bdadd8615c13c292fc5e7353ea42db7144fe26d7f2529'
            '4e35a07b6a8a92e4ddfb2133786ba4f2a8f970563992609480b7c24a45eda438'
            '3409e7967aaf642547020982cb208b67a8716c3c6bf0a26d7cbb275ff67bc623'
            'c6150f77753b8396116176f8b393380d7076f2b5a33bacb08643723154627084'
            'c29d8ba10c2424d52926ebf900326f05c1344ca977e40ea38eb4eec8ae850d38'
            'ef74afad451aebcbe9bfcce204d0cb846a0b6b8e0d71c1ba1480bcedd12b3058'
            '0e292a1fc7dc4716d42f83c024659484aba58e0702c0e796fcf856eddd9e69b4'
            '178db564a5fba7649f828a63752582cde8b345d562a45426e521b3aeb27d1f93'
            'd0fd13d119e93803df89fec847d224c2b4f14e459a4042c0627bf4ad1f0f7965'
            'ba0e9efa3e9fe7bfdda0b9fd2e2df0b0463871154c8a1b0f02cffe8215eac472'
            '0db21b435077217bec2af6a02ca4e66d836c54dac5d78e8ba524f5187387ffa2'
            'c0128d50b659507b2bbd4e81a9b803d810a9eacb6e3a703303d529cf8c8d30f5'
            'ccd43701b199952c426e3fab10a2fce04ef700716c8a0bb23e8b941cec164182'
            'da365cdd9db1f70014c0d1b7dc86174b58ded8cf38fe44a3a39cff6a2e52ba73'
            '05c863969829056d09e4fd0b54d37722e9f9624c4a5d87df1cbd9c31baa0a4bb'
            '464929c188583345d06e28deece30bfa13ade9a17ce430094d6a720d8ec4daca'
            '630777064ef4761eed3f0992479e7a59f0afdab8bfc087106f20f51c6ccbd449'
            'a8631007aceafe1f7ca333fe954c8b287fccef279e5dee24b4b8343ed7785e1a'
            'f19adde1f981d0b52ed3f48175c036144d3c0064473e0f5aa8232d77f6b6b042'
            '1b87fd438e07e18b7183c2174afab9f1bd98668613baa7506ee8e0abfb37c36f'
            '5c20e67a32bd90ef3f947fdce81cf58ea7eb3f6a9aae46ad5f3bd8c3dcd499a5'
            '53d3223c5f561fa6f9d72220b9f4f0b76d7151199f96f31e341970b3993e0609'
            '362020593069e14d273ad5ba10288be414fc089aa241f90c8e69a7b320aa7db2'
            'd25a11adb86fb17396ba78f4c5ece7ff808eb536593e289764fcf65f269413b5'
            '015463e8f60af74b85c6b53b1ed88302af32ad8d1bf295a4b1c6dc5fcba8ec20'
            'c7db0188e25257e2bcf3a12e0f0c6c0f1b204ee601a8b9adb558761918e1c085'
            '18f466925a563d10efd65c366ab2f9e0421e3775408c33e33c8ee3f45ddcebfc'
            'd08dd81945e1f103ca46dc05b378bd1f40c37f9adfec3d79b66e99d76a30f121'
            '8480a7f4a7fcda39d1875b9c84e33757d73014f0803ba9f80651e4903c43c4f2'
            '4724a34de7caf68cd6af066c10860ef85f11843508582648f3b08e4c243d3f0d'
            'b8164ebd593a6d60e08604889261119ba1f471bce1c7e1c69c94f9845a5235cc'
            '0ac63d276f31e57227e24d0ece07fdc3fdc55cb636a220a12b39ad7525baecf3'
            '649e28ff5a1c20c7036a178bb19a9c4cb901a7ea3aeca1a5d7972bd8dcd40b85'
            'dc94549db4960bead96c8c11ccfa2275b51958e9d8b42be299b3ee09e40d5307'
            '6b8ae034d73d95df3523adbd1127eceb4d437d24e8ce09f98750df9121b00922'
            '4ac664714f3b0089d17f4f2a8e520b911c2e397a424f947115279b652e15d399'
            'ab1ab9261b477bd0fbe736c8d05a5d414e70048361cbd136749400566f06d033'
            'e9bf96306ed7f0a1da27bb8ab29d73551f764eecbbe3d428b8e07404bb5e458f'
            '65395a6442e2c88a88cfda5a23776dde14d2eaafbee79de0d9ebe9d9c3c05fa8'
            '8f136ac0a3c3e28fc892dca4469f9bf410d36a82266a8189160cd25755484057'
            '9092823afdceea513653022e824a53b1f1251a6412cda0ea6cd2ce473c7bc094'
            'a1e5e61fa8a9f991faa909ea555cf10432d088e87303d1ae4c7232726a098161'
            'b4d3c7cdf6a81df4bbae4ee1101b228892b5bcd1db21d6d9c4dbcb1249675556'
            '57ce456567ce803ba7b719a9c2833202b237a8e8a68f58e1ad1588f4dcd698c9'
            '5b7b5225d227f7d76cdf4882f2b45800537ffe5bbb5ac3d35c40fff18b4c6112'
            'eb904802d1d511c2799dc7e04ffd078c45f498dfa82d1e8870487ffa6e68ce02'
            'be0d2d850f938f785f45cd698bb5717e85b2ade01e6c3c60a6288c0df3b639c4'
            '48ec33a54cdd992995b3ebc6628ac2b0cb6881293a8e46f8827f040537cf0ef4'
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
