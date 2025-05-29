# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.14.9
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
sha256sums=('390cdde032719925a08427270197ef55db4e90c09d454e9c3554157292c9f361'
            '53a048bfb057ffbc157dac10dedc6ef00eb792c04f0e5f88b150dc9e332f5297'
            '8bedc95c816b489351673b81c3b83490acf2ac748a47d8d19264bbd3991b483d'
            'ce8e1a63067a9bc61fd13aa3d9b15f160379620dc424acd4bbe66d1923b24e7c'
            'b5835a8ec3d4d1866bf7aa5aa67ba9c8c06f9104773bfd0ef35225bbdfe49e77'
            'd4cb04a56a2e495a7c8cb800f1b0936a6d4c1a98ed24a200e0c4a6bf68cfd591'
            '3df993bc7a9087156138c57d606fa41045d80977405b6b73ba737e8c774b8b3a'
            '354c9ba1ddb0be63c03f66dad7052c11c4a6f717bb148f3c4e93b0c512849d21'
            'f02e88d0a2ddc590e7b27be4d65926755a1707c05a278df3f83a88b9bb43859a'
            '448079f91dd2588ea9587f9bf2b83dedf72a85b4d6ee3af97140b0e4d3534576'
            '6c42411919a2f9a3a8177fdb88a5ffdbb859d14c175c9d09a956c0bf93d162a8'
            'ee6c67c0ec36c575f074596adbea16d82b8f531281f6bb5a5a0d714d3a0ba4a7'
            '10bfaedae9443a35e6802bcd2fc74c598bf0b62faaf2bb70c8ca03a096db2304'
            '674b1b8b15e6d83264b0fc438f3603292bb7d1a27ecf109d8e178379052d677c'
            '5831c5407514a01b9e86f5e8feb43a89a6d8bc3a6d9ab1e0c0f28df91047ed3b'
            'ae7257d9886d8bf5a5f9c31c3a6d63022b8eca2f31073f19eda8d96cb40d0a83'
            '166055990ed9ddd2c0c45c055bfbc9b25978c996e09cd4ac49936653a4798a9b'
            'fcddb8b56f1cf23536d2f304ac64cf509b11bd182a8285b54d2c3536530bb052'
            '7507be2cf7f378770a7d37a34bba5292a0a4aa7c9dd14fbd0d0b6573b3b0e642'
            'b4d029bdbdb52dd6ec32a9de34a1d9b983e0428a76c675b06e051b440beed7ed'
            'c16bb07c3563979c19bb61f6d672af93204e7c0c30c6e0b57c73a50e8d95d0eb'
            '1003a2c578c1add297c9014cec90b167730888704b9fc1f5163ae81a0f17e786'
            'e13d7549e1c0a1bc2687798e5f0c2658ba454b00bc796ef4ab2f6c13b30966a8'
            'f320ec10bc0f97bc15caf48a2c279c0d6f7a7e64ae70043776817296cc110e13'
            '83be1524f503afe1d148459cc63eab74cfadf3557dc8c074a2cb52d43e0febdc'
            '2e5c76d09e2fea8e940beab17f77341fa35ac13381062a2809e3696fa1797526'
            'bb99e419c56c3534dc9d222143db04c86e9fb29017c7b6d54c3abbb59d89481d'
            'd8337102f388daeb3f3edc270faec7a2621e29543b65fd5566fd60a5e790ac3e'
            '05460abbc666ff615d80db9a4769c70d2aea034d18a6ff3f8753d5ba22a0cf94'
            '65a41b05d2c576d1ba8fb6c73f181b556a08acaa57389474b91a7969ef16bf17'
            'caffdfe2809e5053f815be49f69eae550d4209e573e9304d72dbfa3e0c6d779b'
            '32c9a7299a222d2ae844b9b8a8809f04377365dd5bd00de27f7853f933f1d035'
            '3e84045205d450b5a256de3fd5f691269f2e7cea776d369d9f94dd46d83128cb'
            '247fa21d626783d1c59b73148c70af293b4774dc390f8c0d406abc57487944a9'
            '6e33c3b15b6068f99613e6352b682d8223acbfa3b16b945ceeedb9dfbd5d7130'
            'cb055cbfd2d143df7e7a4c69075d9f69f9de0cce54c3151bf9ce4fd76be02839'
            'bf6d3717a4f5e1801240f1820a07744b1324704ba1946a82a4d0c18776397bc6'
            '1f81071aaa69f069bb146fd5d50bbcbbdc3cd2ec7968a9b5de2533bb20d3d51b'
            '2dd6676e0d06b6567beaf48dc3463126cb465ec4d68be8a001d33be6123cfe12'
            '5799408b8520700ff891c9a042ccd4aaea3db964fb98e72e32a7238dba025f1c'
            '09c7f0d61d3cb9804e7b888f4f8e86e0e6a33ade88df8a6c05fb32ca2df2c13e'
            '7f9680074133afc8d5ec79c3c7bf3b4b036ff7be99a1016d0c772cf922220458'
            '46956dce180cd2323e39c7afb9ffd8e53e27b7070900944c8a204d8603aa8ea8'
            'a6f898a4d3db3467cb78d04cc64dcf90828be908e759fc699fe8103e3e57a4da'
            '69daf347f1aea105a86e2f5baafdb33303e1af096b4926ec3b707b5a995f4b28'
            '27f275bc8be668fc6c3f270b86d5cb1fa1b7618b0d84fffa99887901e6edb2b3'
            '9186364165ec7c1ca0ffcccfc0319c9571b524d7764df4385ca867757c78f416'
            'eea9a30b8d034baf7cda505e09ef45f7b53950ddb7aeb50f0b7a8414e714f0cc'
            'ff7c0ec54199c37f10da46e169fb659d80cfcd3e86e46ed972ac3ed69ab409f4'
            '81cb25b370663b2b5a835393f5d7cd0db4b4d6d06be57d241d5efd35e5ef2daf'
            'f7a6079b9d7c89717e009f0b2d9ad553e95b5db970b2d4a391147c8bdf43661b'
            'f192cfb26f6c8966a423da78606bfed240e24f9dd7d3f8f4209ba6a2ac810434'
            'c76b950738b01889ea70699293f7f79ddd954637d0075236e00ae0be20db72ca'
            '4ace1e9f02b3fcc5ad37923f333fea95a193cb1c0d2b2357714f017bb462150a'
            'a7376a820da7cfd96ce5cd3e5b8339f0dfbfd755ec9968394c0bdccd0c363511'
            '6eab64ead8de096f916462415677ed9368e6dbf9ce1eedad952f20116466b128'
            '556dbe62d163d03834cc2fda5077b386f8112f227c3b8581455b3cdb4def431c'
            '154e49e25580a94e75db4a84521620cdeb9e94b29536ca15acfb9ccce7fb64f8'
            'bf740895e56fd3ddc52df2eefe459cc7e217343d763e9b159bdd5f52015eebf4'
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
