# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.15.4
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
sha256sums=('0eafd627b602f58d73917d00e4fc3196ba18cba67df6995a42aa74744d8efa16'
            '64d5ed5bd25723410e56b5957de66aaf9864402bda408bc5d609765917e54b2d'
            '9a8c5f2e20b1b310f4d2e5249b84ccfdfc0b1e592bd45f19d1d6a2f81fa6b437'
            '1e9f58c1624b83b5c96046b7e979b7bae8c216d1618aa184129423ff9b8bd558'
            '841fe5b12b1e46e94bf3ece2075f8eb2c9f82d081d38888f191b89866a66ea32'
            'b0520a83814381929e60d009ee9c2a23405232feb93262176997c402fd2ba42e'
            '596ce0b425ef5c0784efd10477426a60ba951528759058df839eb671c26d000f'
            '3ad1b4d38f238898b1e99e0249cc9322d9657ab9333a9c261f747bdb9c36df20'
            'ea79a50e080cf0f328c2ba559b064da524059facd9b17ee8a5d2ec6fffc3d960'
            'f147c876111d0e1e9dff5a050bbe953305acec63b196d13492d61620388bf4ce'
            '3d35a709979fc1e38b21a192b07cd9ce004d66fa357d91e69ec1425c99a7abca'
            'f3c1795a5957778f8135389678a071be80600367fdcf501d8d76996c94ba8fe4'
            'd1ea7be079dc006225479896c77caba47a15bb8d4f2d6fee2d200fc0395b0925'
            '13a9b755c645782f5a6f33312499a32b0b4865bdd1f715156126f8f60ed3c3b3'
            'f1e85c5c55db4560c19adc4bbdaa69279cf2d9af14f2ad8f457fb236a96964bd'
            '41ccc35a4c7b20ba3227459364eb1f257bf74c181af944cdc5108a35a4f9d14e'
            'de66d70ff8f6486620755da8f5200962043600f5c76000c92a4f9b0ba0e44447'
            'dae73db68d2adf9ae0680ab1ce9e41b409fbc90dc1a45a3ed850f1442f8bf6ae'
            '2bee39fb597fa62931543d3bea34f2a5bff2d9533be6b3f868231d6be17c7bba'
            '2303fcbe07934e613fe10bba59533eef60b329a641cd7689feb17f9c056ce97f'
            'e4f4eb247a96a4f204f64ebad78b2908812e31c224e1da101b91bf6898eeaeaa'
            '4aab086dfa252d8f73da1431889e3263c2f1026c60a985db2d0f8a6b8d1a1cb1'
            '2fc95f1d7ac91eadbad117de0a7ca59f0f124fdfb28869003d2fe8fb4467095a'
            '225990a7bea7040494d9aff22831f8cac5aa3c8abc4d57bf03e5477ce9d8cdd0'
            '6238dc688800ceef86d73d4f1c131580fe5dc2d31fbec8c2fe8f6cf97096ae2e'
            '8fd89c12900b7328e35349f68f3409ccb236b90c2cabbcbb404112e43b70efaf'
            '1095d78ff18cffcb622c48f5ffc51c95a8fd51a3f936b9ea8f8ce962a435e1e9'
            '09f23cd4da5c59f290a7faa01189bb63f11f33b948fa440ed56e731c26cb6f8d'
            'c1b1f7eb183b8556993d0997691466ae4d2149e8d1ba2ef7087c84659d847071'
            '9a7dc3bf433462b6fd33f360ad2518dbed1c1c65b31423a6b0f8d63f9190c192'
            '67d000142877050c0219ddca638b309225867128df2b16fed7fa2eea08ca651a'
            '0ac84b5a4547f1b862ae43b2e94eab905e00aa74512e0f81038a1bf8b3b2ea20'
            '18b6e539451917ee58c2baf6568ee62240e94e535c40eb551e000c052534f17e'
            '301e5cb068798fd353c0a663d62a6a25333f42fb5d252ff8d7524a8cb209065f'
            '27aab694c658458e9e2be2912a330af3bc97ecc4b5ff4e224821213c31e9b04d'
            '879a7b95524645c3ed3c7d1d15c3ba088323bc7294179b6c58d99a450579c331'
            '18c96cbbe23ec8066912af5f8131d67c54cefed9834dfa2266f56bfb136693c2'
            '784494929b54cbce1632e471ab80b54594bc689d9421ad2f322542f010fb6924'
            '2b04266e471392fd4756a31607ee4a713e2e35d598e1046e6fcf5bdd6c9ec70d'
            '517e527eb6feaf98741d6a577eca2d52e7370ce693117582f27c34b7e7f564e6'
            'fe562774eb4da405ef92dd504b8e384ad26c159a56722421b2c9e39afbeea711'
            '50a4de351af7d78ce77b14a9f26d0b5caa5c48b70b1806450b1c939c6b07f299'
            'c4ab3ff111c6e360d9f3253626e2929c16694d26050a3edf5bd8c418bfc17e7e'
            '2906f8737e4a1346ce1d4fff464d73d5338956d52aba8cc9e87462f321421fcc'
            '59610984215cd11772f2fd1fbc0aba05b7b86154e8621908e776a85b3bcbc9d7'
            'afd004cf5f490702e10a8a255d1203d005b29cb65d753d623289162cee766249'
            '2c30106e9533f3bd1ca5116a872ce5142b5b5494b6e2a17ce55bff59933a3ee6'
            '3af6cde2332e7a03f62e454625d1a4422281abb5ccb761db1e79a9165cd9b5c0'
            'd2800fc7db111ef45f92b304333820f057edf05ee049915fac9c9dea341e4657'
            '92602f3d3a0d6bb611748440a3680916fc6b45ed033fe2791c5551643f746a87'
            'f0e8ec942ba99029a7a62e4158422aeb84de247e151137f590983212bcd4f14f'
            '9793c5cff8dbf6ea08ede46feb02c5388cb53accfa6ac9e3113b294e24d4ba28'
            '65a0f5a8f83e1577a71d6b083f070e83b0b40362af33ef4fefefaace03e79fd9'
            '7eedb97811e2da5869009b7aa40ddc6e598d6ff69774c74a0053c333ee2c481c'
            'd39e288b07b9cbfe901a7bb055ee8f49da57768a575d4531915d0659a5650f2b'
            '31ecabd92168bd93b62a23bfcd099885b30ccc2b55daef2bd71c04439aac210a'
            '0f8dbde1c972f847f12b7fe2d6781911ba6ff3366d94256eab0353690750cc0a'
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
