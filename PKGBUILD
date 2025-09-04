# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.16.0
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
sha256sums=('d6a5e3c71a10b533a756251387cc8bf48bbd5c76d842ba5e957d8b1c316ab622'
            '4c07380c77bf2e048300c7c517773c84d4fe5cc0df6b591b8afc69779b5e63a7'
            '1c9d3ba861211d92b6fea15c0fbe7d3e4af8f62a9a6d2225b5ca961d4e6bb06c'
            'e9bf6586ad65886fdba873fa7fafc5309c50c2cd5695e99be7290adb8dde9d4b'
            'e79c96c72480aee4442e084fad678254e2791ead85108fe12eb67a48ece51146'
            '4aa37ac08ec2875c7c3471c09d6ad6eef88bdaa58db22d1fe2a3028c12b5b812'
            '915758be68ddbd895d5d0f0acc44f720bf350177578cc878ae433c28e772843e'
            'c6d409a2536059a1b72cadf18286fd1df541ad4c8af0476d313f54e2d3767547'
            'c667fd97727b6d9dc0f85120625fd7ae136e719492800d87961bcb653c7187c6'
            '5c15914ae6195a1fc1b8d926c35a60f1e064c4b53bfd2d4a052606de95cea37b'
            'b41085d265530afd082c474848b355f13b034b8d4867d260303ddab9a8044b52'
            '17dccd5c584506d8001e0d19deb31b070cc062f6c9974b78ad5af79fcc13bddc'
            '05a25b54289cd65d19cdbd57fde7ab76afab36c04272c6132c2d7aad5fc2145f'
            'a3408fa9fe44af0a6d04ef97a1e38f3212a6ef07f70110b92c21dfa2d40d34b9'
            '31fc050289936afd9e1f7fd611bc942548d430f9f136cb128df686bcfa4555a9'
            '3b2cdc6467ccaf5eec0af851e71b6ed2b2c0740d1c0100dbe50bddc43ad03220'
            '0737263829a8bc6acd4af6a4908f3b979c411a276f32ddb964cc3fbbe96c39bc'
            '545485b471c5970c8769aac5a05fc147e70bc2e4eabe4e9ae32d491923479941'
            '95632d7fb0db937752647283d776141d2e8e23228395795b424c13ecbfcb5381'
            'b9011cd6fb42929fc73a6dc17be1dba92a2971571be3e1f88a43180623539e37'
            '6abf6a7a41c93b3de686fb17472f8975ac36c5c4bec085376ad835914e6f9b56'
            'cbaf5e8105ff4d2f2a2b6392e5b72e16473c54b133b84bd583eb7c4ed9dd2d8f'
            '790bb26086e72d40724cd4d44bfee5644b4c5163aefd73d52c9c4d8f21be0395'
            'f38c9523f511706b905ab3a499a368f1453f956c158496094727830b347a6a99'
            '6dc288317614603209720c72f9c56215caee49b6fbc9e6f5146ef2793071e3b4'
            'dab5e9cb465a524099f37edecfa1c54632b060a85abea0556d481b95fdada5ff'
            '75100eae10cc75f66c33dc916fc4de1c39c733315e1be484264b6b70ee7ad409'
            '445f5adfaf4d32b2e686a494bd8c8f11759450806ab09fd25b1f353155ec44d9'
            'e997a6bec82911fcdab5d6445eb81140ada50a5a31e9619c4de9ce0280e41ab0'
            'f5c6126804e292df7e6f152270705ee2346503a5e2894c67a81ce6bb2a4cb6fe'
            '9638cf33fa8790cd796c3445e05457bd93f94b470c641508043bc7f6b148aabd'
            'c4789dc971eb5a181b10f22673f02ed10a904266bbf83905daf1da7896b7b40d'
            'e4af254465b92d0ccdaae37ea1160f07f869ca1bf0e1382139e33f52f27a3130'
            '265f1552d67fe01665803612e198ed13197d5a4d96894cf29ab3d8a89e7edddd'
            '9589f38f48cbe8e13942504ee74375daa78652afebc7216ae479e4dbdcce671e'
            'd64bf4b5751a856a50da4b73b18116f66d4daa7a4942d7f187a8a35f4b969e18'
            '73ecde0ae17125333bc83068dfe138fdc7a998de31cc42ad69f6c81273842c77'
            '0dfb6c296878ff9cad600629fb6681330fb16a5617201713422c04fa7c24de30'
            '3bacfa8597bf046174cb6bb1078645d93aa1b14576c38877fbe92faf363d6607'
            '43b95e23885c2c840cbb9cedff687fcbbc3aff9ea2278283783f6972674ac11f'
            'c1424878f22849d1c5d745020064776ede693b8355ecf8f8649ebdc834ae1bc2'
            'c7c84e105df3adfdecbba2829eb7a04c07819937c9299f84ab34193e5204a345'
            '01febe38c279293b189b5553cd274bd4483718429ea3de7df9d0531029a1e0cf'
            '0d984068d2e4b0ffd49da7319450dae37bafa686b32e8c66f10a6b853e18ff79'
            'c3f439d61161b00dfeb7de882e8efe5602f65c16879642298178c94646d84887'
            'b61b89342c74400f6f82e80aa17d9c93ac69def1ae59342b3285084be79837c7'
            '9523d84d017eeac751157677f40b1a71468934e5fa4d76235e7b74378b207837'
            '1d83eb7afe5a291fa5353791fadc4b8589bf6e5da4849a20a50eb970386aafaf'
            'daaf855875439c4921c552bcf6baab8b50acbf327207c31eb373a8bbdbe61089'
            'd9155f783947ac481555987c37d8f5563c51d5e9d81e6de5837d380bcd74ac66'
            'a3c1a86de0aea97bf6a76fa33d8d1241cee19a0e15eadcc09731daf1442b1d18'
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
