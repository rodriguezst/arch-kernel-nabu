# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.15.6
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
sha256sums=('2bb586c954277d070c8fdf6d7275faa93b4807d9bf3353b491d8149cca02b4fc'
            'dbea7028dd7775e53b1d5ce891daf7f7b9e561428628bcc172a0384be9f087b1'
            '4cf338d60ae24a04259d25735449b0f0d3749db2f1c3b7cac578bb266336d191'
            '8c4c326a6b1fedb03794017cdd75cd6131f5772b0d2db25d59d6294bbbdf82fc'
            '8bddb825757f1fb52600018fa3f22fb140e357c1c526ab8022e8fdce4119a8e5'
            '850af0cbc7cbbf1f33810ccad95224c4751e3965dd20a82bdba3a041365c9c6b'
            'ce6ebf4113c37e87b34871356cb35f781b946226d469ee4bb2607ffe6d3ae8ae'
            '11be91339c8a1d349b26acffe0010c7c361648a028e8a7088483cede8bd84985'
            'ff7990cb03a6744dd8a0be24a03efdaf811553982dd115395224f4d65b1bcf26'
            '09a681f7e67eda0e4368b9ed848c3941542fe52cc9c69488c1384d65d82ec814'
            '39222946c14589969943d417d5674be5ade25c2e1633f61fa2c710520d1c42da'
            '8f82db48bfcdbd49e06d58ae99e7af54bf91e1da7ae01e9fb8ce379e46282816'
            'a46b0715322a7ac0595171aa76c2e6980bb4899a57287a9a03dd68139bee140a'
            'f0ab3f27bab4fefd590e599917a3f46f7e59e8e5776a764917c482a11a895f8d'
            '9d0f0c0d18535fab5cbae9a0301e60ea5f060167685a43db5cf0d871edc0733f'
            '64a0575e67ddb6a3bdebc716d40373dfd21fb78c8f779ced0834d2e9a0d0c895'
            '2be07b77378b024c4c74a7330f73512ed8be12afb7e8a3610e26ea398d8d2c60'
            '9a4da7d180d93c27c75e6c08e19737cca8744120a4614247731bfbfd2ea5af02'
            'd1998d67bf96e383a4caf17e10468463420cb5334918435d15f4fa58640161b7'
            'cde2700ab71cc9571275d3d50a6a6c5fdc20ba6b5a39583ad1d190f93715dc92'
            '1d8b7c6cacdb8724e9ba5db3af0e4574547dd6dc24cb09d73713d6b8711a1683'
            '4e2fa31250a7340101f54f7d0ef9f57a67a77ddcdc5d52d2db3adfc101c5bbb6'
            'e71c3f8447ec5f94197181a83bf8c798cd26b1c1ec39823f00e6bed75691ea53'
            '83a7fd3376acc437b840b477a0bfd709d2935e1d5954ccc8affe0f4af048dd15'
            '09c9fd7ff9f8f38f8fc8235097d88a33a99a881572775b36ae0955bf668374fb'
            'bcea97fe0b04cffb33b38bcc1968caae0d80bbe9504a56cbf2d0f3066feb19ce'
            '942d198d1668893c622b7cc3d09adedcd1599454a6e207751d4912c6bf07db9c'
            '9b26eda4fc70221dc4517c33c56082df707a51e2f1255d5dba0208cdf80e4eaa'
            '9d804f5bbb80341e3b614ea1c367a908a56bc538e7e7c56b85c4052e0abc63dd'
            'eadb8421bca7ccc083a8169dec15ae06fc893b5a315105b84e3cb464181c1ac7'
            '1dfab75ab8e671e53896f53c6fadaef5eee00f76b47104e020e593399cc4d3fd'
            'b080f2c2800fba40af102b7a310bb833076e49eadab9e1ff40c50bf13ffc123f'
            '86bffccf818b1035f78a37d49943fb404a8e72475f3f9c5a78a0ad93a57b89ad'
            '27d2736f20619a0127838b13ebb93e0a4d5e73babc48653a9f7356be3aeca4e7'
            '7703b8eb08b36d36b21cf5db2bde05edc00911f650368eb5bc292d447cae50a0'
            '512f00a45e1b30abccb67b5240fccf6c99da20e179f2d2da248f8538769200ff'
            'a233f39a28d2b9f64d1c8092c4c886ce9e3c539f8a7350fec2ae2e6f8dbfc918'
            '0e5c244b61c2afc6a7bd947f40dc4d891afdbdaf475217d64152e58c6643e4ae'
            '87041e623e7de84928f18adac9e9dd9dd5cc696168ac4d4acd9e01d3eb553c4f'
            '114177add434357ca5acd4eb00605a1ab71e4cda83fcf70ea8f4c754e9e0880c'
            'a16287ced5bf4daffe66f9d1636fca14739afa78b4e900880fd2f0d8e546dab1'
            '5d331750e8c3936351deb831d0ff3148539827574299d0f8416c5dd46a44cd3f'
            '8a43f619fdd0ccf9995d9a80fba9f887aa795e2cd90f49c23c8d83c79d998985'
            '4b0d8cd67b5ffb5233108fa4a0437b95a6645ee158a775dfd49d7ec84dd759c2'
            'be354ba126af805676330b96bdf6dbdf61cbdda602320f0443588a73e3845f9c'
            '5a0fc3a753fbd91d373d595cf7b5994ae7f1f48713857557fd163a7f61975732'
            '9826c8b7ff5946a8e121bd6e7f90c355756f1e354a9f9a063cb7a241de077966'
            '149f740898eb1ebd8dca5d609b184427579ece02d0557252d5e16f5195cda2d2'
            'caad20c28ccbb99f8e0ecf72733f9edae2106ddc4cd74673069aa79db3d4761c'
            'ce5dd570929c32d672584e19365400dd340cee085cb57304443b54bb3c8d87a7'
            'cfda59815d4278ee6fbfb333195301d5b5d3bd4a91e90d66ca5e485d3eba0407'
            '1e97026e9569340056100c072b225b0277ae260e1d43a07ea7bad6e9f0cb647d'
            'dab62e00433838f1dcdac1bd3d41fa0e6aff63bd00c2b432a3e247f4bd1b087c'
            '8f22ffc230d79b7643061491b237dc92cf97276d1d70822393e8d665a94bc0e0'
            '981d8cdb09d2bde80354b720365bb8fa2c7d949dae5da35435ac3e3f65fe0719'
            '7c4ddf361d3ab4b135250f2fe48acddec42e7bb9d730ebf9fc216594fb205b7e'
            '598af8391c324c34e7382f10cac11851129a311e3efdd15659d5891ac1aa339a'
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
