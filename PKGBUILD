# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.15.5
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
sha256sums=('2ca707939c14431232649874d438aa58f11b4b127290fa68d164f8bd79c688b5'
            'd97665ba4930f3a7f0a6a50ce38bdb8a490a7c6bd7d0e41f5664130bbc91db2d'
            '489903c971aabe02dadcc9be30a5067816559b447d631cd0953a13e30aa5bfad'
            '09dd629a1f440c6f4435ff05b111807a659c2a97ef5e290a1869bc4de0e03613'
            'a784dcfda16e37930d03e565c44e75f63e3af422a499f26316211f31bca6a2a8'
            '35daf6fa5c03811335ac1afaa1bfa72d91239bd5ce4d9e3a527f8a1638c407a4'
            '92b07de2de8350ee19d6b8418552a29871084be568e3a087c04325cea154a95c'
            '8be798e96471bd5bdba91574a2e7d48daf6ea5eaf9ed5caec673218840305484'
            'd22952bf3560eeec0d84af0719b142ef5cba9710e443111a073f3d29dda371ba'
            '24f7f517b7c1a863f47c8d35a5443fe320204c9cf9a9ee567867a817d461c4a6'
            '704093bd21abe38003bed5a81ab1d767884fd953830c22eb5faad11b2001a78b'
            '6655524f45011fd868afba49612ea081c4688262762f736a36f2443896408446'
            'b7d1a4e2e1f777e778059eb958f570d4a359d579a08ba15294c3e3d386714409'
            '450eaea52aadcb7f735c4a2cee809624423620e37c51545c7daf48376dadd1cd'
            '9d0cbe65c48b81c59484c6a44db0c01fccfd6bda6e03dd11c1d7a5d36affc296'
            '9cb7bd564ac6122f9571af4971581a874cc1cd7917fc37b8169ed8e224c0532c'
            'cc2f4206bffd0f339f54d69231c51c53caf2c2abd9caf994b0af1fc245e0fd1a'
            'c0750ef6f8ec829e06e521a22ad746a5ff463d5b6791c55ab14797271d1c0c4f'
            '7e109ed4fd23973a80feb8975b887e23246b56f66b737411dd6e759b475db375'
            '16a8723d46954fc3401f3cd8fbdeec77dee627d93bf4756bd0c2832a7622143c'
            'ebe6c59ed15364e255872864ab007bad219e18a3e857019bbc078df0cdfa13da'
            '99b83506acb2ce32aee6e03a4509cc6008d40c4abd50d999fdc29cb23b71ebae'
            'cda0064360940524ef1cfb1b1b17aa8d490f4d4553e6711df32757ecf95e0f9d'
            'b0bd001271809addb1789a87b8a907a1a2c57e8c54c847c4168a857841eecc0e'
            'cfd9cd183330ed239ba1e0a64566398ff788348efd5368d0dd814168244377c4'
            'b7ccb841d795e523efd6cc387417c97139b15e01801fb3d17a3c8c71e504837b'
            '4865b81ff25145f5230883ddca9d70bc4bd29f887fd7fc74558163c274f4421d'
            '977982520ced1325d37c200097e9e9ccf283cda9e042310f13b03cbcc0268aa9'
            '3ee43684c0ef1d78ded0815dc764c563c4e17603bef5f71e53924186a3c7c67d'
            '66b15072472c18882e0b165fe2495b40c81771f2231e413e6618b723138dc7f7'
            '73b1b868be841d2863480b98cdbf752d4ffa7282efa480a3b086bd759b042519'
            '057014bb5d282b82146b261e04a68dc267566a89b5e47de83cf5c9cbe8dc16ec'
            'eb7ca39091db2f7297adc15660d5d15afa08f856bab568f00fab89690472bd95'
            'f769c97a51516e290446e40dd7e13272735276de19d3c96516c339f74fc8f6f9'
            '1e609c33955d12639202693a24442ef4f63ab5b951b5c1573cbc7b73082a9a48'
            '70c4cb92a144574f02382a345abd2d00e8c63bc3bdcf38c87ac915b73d34a894'
            'a9b1e21e0ebab05febf9dcfdc369b79d50cdd8d7f288c1fe79dd75319ff2e5f0'
            '3d83b4b56988800f8f5bd717e648d1017bffc9131fe972169256352850608633'
            '49eb902848ec1e8a429604e7a7c548ffb829c664697719b3aae393d6e98462ee'
            '4a4094ed3fe2f9ebcc8bac0b07d72cbb8b2d952aa3cbbe986a8e6bec58a0edff'
            'f4809c3f754df04e28257598d6d39589a3b428e6750d85ac81083594dbe4519e'
            'c4223e3e943e5a5eb1b32bf0146a8358ebfac1621677692d5a7242b7204be3f9'
            '5c0afa26a879e75f87fb703fc7c6afe4e73eee5c59d6af4249be435dccccbb45'
            '85c3afbe09a3a13b418d575a29684aedfe620095b6313c8ae6ee5131ccf2ebad'
            'e10f1ab836a10f216386f0175f3410ff2570037150336094c4a2c764d26a9ccd'
            '3fda49326f850e61cba55f2970ed600361ec101b2f6c477cfa13491de6e9cf7e'
            'bb742c77e6758f9aa6ef97b15e663b7a5e2285d5b1182515e69fe4bb259bb7b1'
            'b8abd12be3303bb8c14136089bc9c616717153bf088feedb53a6bc5d43cab681'
            '628e988f9b53c2de1790e5f179edf811cd28af0963cc50a1b6c549bc28bad62f'
            'dca2ce22ffb8f198f9b6ed8335dce6123f2ec2f14225a2fed24b12e43623f531'
            '0a328e0c151daae0b569af556cbe48e510da0bdd0038505e6043778d141766b4'
            '96d1c3be6426977f83f77d21648a5e2417a76e9d8f77cda5da29187703adb556'
            'f362cadbcaf86b485022d6f6f589464f8f1a708cc8b5c508471ded1be3438809'
            '625522eeec7c42b2fffed62fdd53c04cb93ac531cebf2d6235ff7d91d93d38b7'
            '6d775acf94f9b6d6b19f281cfbe280effdd660b12d3c9f3f7c79886bc72962ab'
            '6e6dadc3623bff9fc21c453ef7136323c0553d70db35df5f08e3ba0d2669fb4a'
            '1fbfcb241e17a80c25093bbdd36664d70e564b42116b89e05c4c4147c6633455'
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
