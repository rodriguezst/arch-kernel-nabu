# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.9
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
        'linux.preset')
sha256sums=('7ac8c8a3cf05476375deaaa85dfcee095a826ffe557b437f43774fc3b64ce58d'
            '2f6afc62417c3cbe46951c0c498390d6217e29f505bfdbb4351062169492a656'
            '9cec7d85d027f14277fe461c2e3f68811259b1cba43971e21232673241f621c1'
            'a176c734e254b9428331cad1fa28b278815f1b7f21e406e4e337e23fb0bd4afe'
            'a5c3f4f2eb209d500a78b6c990313bb548158f5acb8eed8c056e95bcf6013fc1'
            '35f0a4e6891f6351b86cdecf35b654c42afbfc4e1d93c257827d8c082e299f97'
            '390567e3e5300a450daa8de7c7c3228ba6f93abd6619823885ba4570fa032bcd'
            '568c03e82b60691da2b69043c1eb7e21f0ed1edb8b2ea9956a4bfb864c8fd845'
            '6598654dd2bcf0d90d9b1f21270978647a3f616e4d7d116dd949ad658c328d53'
            'a9a8f64adf9c1d3a2142be73dcba553c4a09737d527411c2fbd0187e5abb5b41'
            'b9823b11d7bdc0688baf6b7b18916d7a72175bd466ab98ab9c17607fc5ccfc03'
            '45cc5f37e62a12d30d7f5f8320f1c0eb2561f8a444cc205c1016a14f8e2ee8da'
            '4eada631d724bdaff2d5dfa64128017a76ad19629ca00603367d4a499ab78dfa'
            'd9483e3b1f1d5f9a47217b07a11eb13e8dc9a61cd55024a7a607ecb72267244a'
            '5021fe7ee43d1c23e68d2e891e1435a14b657fe304bf2bf6a1fa4893543aa23f'
            '2b58b386e918dcd702175d1f6bdde03631f6ec91173e7963929d9e83dd0ce1a0'
            '8ea73265bf49340341de3f2925bf9483b2f8145fc4f1a7346c93a2b65371e04c'
            'e1e2ad831c972e9fb191003da777afd0a628d3921df7befd708ceba2330766fd'
            '8dcf04ef20ace503240984e43eddb15f2a849fc8547320df7718ef007a5a2787'
            '8cede095f64de2241b57a393e092834561dff77b505181c75bf893b37bb36ae6'
            'acd598e19ec52a924d21930e37a1693f55c7fc624a59a371746e5223a89a75c5'
            '0325824fee4ff3da6cf32c1d9035386482c613d62b1cd900acd21b94ce9e96fb'
            '7758c1134c929b9abacef5458bc781a02b16208f1806f076bcd34d8ef30aa9e5'
            '68a833417602ff7aeb1e01f045637c56f09483871ad4d1a7e7bddd630921d50b'
            'f8fc7a8ae3c30411a1bd3897e5b006d7b277572d39690f753811a68535f02261'
            'a5fad54bd6239c311d8752a58419b44056a438547afbefe7c1c342a121d61fd9'
            '7e9ef54397d6cd3a35ffb4c8ca799bc00c156d15f91ffc5f9974aef76303565c'
            '8506f373277158aeb03741494d91c4044a032aec3858e32a1080379514fdc292'
            '39600c398fc6c5cafec661bb315245a09a75b764f8da7dcb7db09bcc82277390'
            '63d64b6905fb582d0a299e4908aef103500d906bc975e6bac610783b179365fd'
            'b65381d9f199b11960c61e7a9780fc036650aa83d9ccc2534fc3f9c8b6505a66'
            'ad75161099e256ad3d2ea6e414199d277118708a6a778a4d5d787981166bcd86'
            '5e99ee447107c1f298bb87ba4e3bd65137f661f96b19bd6579625c1054dc139d'
            '4549e851b31be3ab74cae17bca5b8d4860a8c4d5cff5c8772e271021e255133f'
            '72c8bb4085e7be4fefcce4bc29231a46a5f9acbe6b2305bd7371c3093eac87dd'
            '1ae9ea2d394ac44872391ec5be4108f44f5a1dcd27fecf8b064067a22b62688a'
            '9b4bf32babec14373623323b54262fd93aa81b76fd336b804c0be7a4dc3b98db'
            'b37e32aff5c509999e05833ca9c6bd811c03c067f699b12a7ddb382e8b3f3ff0'
            '207fc9d7f53d23b0dbe8e416c35fb8966914ca92d200d26efc32f92b53d59883'
            'e899101e15c84eef5c7688957f7d098f3985b253ccb3b6d16862155973348b1f'
            '0642c31ea5b7af58794ad0dd912bdfb0b0e023f398fc60a3e32d124ec2124a3b'
            '022aea56758febfc256c802aee6f9a1243c1f849ac10f520a382076c15d349c7'
            'fad75d239ab2a2246d37e96118e7bc670c42566a94ce9332443dc76d417f706a'
            '73020271ef83ceda770af78c1563b8d34a34e4ae68bf05fe93effe79507a4e70'
            '59d75af1bcfd0813d9f2faaf0c557887305c75e42b74d4bd702df88fd749bd1e'
            'f2195b70978cd306795bd92c2c2805679af5e49d8077164582e1191df3cf7b3c'
            '4e66d3120c1e25661b0acad6fe149abbc8f1b4bfad32f57aaf3279dc54a29b97'
            '68bd39745736f297571ef30bbe50b8dc7dd51de2191ba654c5720197f1e8f865'
            'f8aff9a320b9b4f9b609143562badb95521530791013f6ca3475c69f4f0a9971'
            'c9cc54290b5c0cf1c19b6c1ce2a6bb36323f2db67c77cbd41092198d97bec174'
            '2b24ec1ae62f83544ca6d0ca6db6b3409fb986ae27af270f4e7e0fb32fa92863'
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
