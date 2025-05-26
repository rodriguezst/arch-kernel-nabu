# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.14.0
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
sha256sums=('62b12ecd3075a357eb320935657de84e01552803717dad383fa7cc3aa4aa2905'
            'b98b6d899d88b4840c4e5b4c67e0fa88fa425c2be22074125cf4668ef647905d'
            '3f84b0a4730d160341ade693c28bdeaefd1e7fc1974f7d14089b18d9000b472c'
            'e0f96a3cba0838a810b8cb56677db1a50562595759261a0df0ab269bba796a54'
            '7f515c7e82c1ea8891ab2ed8d74bc80712b28e95804b012a8a0bebf96c491406'
            '74a7e754f6eff6dc492d7b9ae1c6f90d44fd76958170ba843e27af83dde426c6'
            '113bad8e637a5056fe453b3142ca2b1179a99f3d124de37d42a196eb04ffc43b'
            '381097e68b63ad890cd61dfb1326b22b494e2804d9d0e2d09cbd7480b5c84452'
            '7bb470ca4c51c3da3ee5d5ab4ae625d4c62022cbadc470478ee6cdff76042b20'
            'd21bf2d4eb33acc9ba02cc2e5e241b5701155dff27529628d827d99a35cadbc5'
            '086a32e04e42c3d67bb3003733034f8277d50a8126284d21094354a080317048'
            '6e851544ead10b11965575ff025113da825526f07b876a8de20bc477a6a9e4c7'
            'ccaf8e6305df8e02db04a281ab15d40b543abe42d5aae58fbf21aba15e327610'
            '363fa58677db2633e3142412cced867514387908f32f8e82fc81987e1d0b0761'
            'c102a1bd8d2b6288e1dea03a23fa080cfbab43e8825695c3302af53d05e90833'
            '19af3f1f5ec484fb3d54da1bb1eaa841ff60325478f86bfd15e2ad7b925aedbc'
            '371f884a9c10a9c08b5bc54bc3c9847449bd58ae7ec5cd8abf2c22836872eecb'
            'b7f7fda759bad78ce1f96d4ba2a3875f9ab772f50cdf063e4feac51e90ee9b0d'
            '01337ace8c6b3112c390dee538c9c6d744e3f3af84222ed7a2ad68a767035642'
            '436a55a1a719eefe2edcd6108afa660a1d188b01fe069f3345fc8ca8cd1082ee'
            'ac9c430d48a70c6a124eb3264344534a90807b26eb6f1ced175cf9b1007836f3'
            '4ba686c6d7117f8aba83b96ec8a22d86fbb805c89dbf0e92054801f3835f4db5'
            '44b3ba020e021871244d0e38864456006138a1293f5ca0ebcc00d08c3a2e69a5'
            'dcf1e783073f3ed58c402c42661e90ad5e4ea7d7d4c09a5151fde1df994cd329'
            '5ab561abe5103a0a630332d069bfc775ab5a3725dad4b78d8f50a135329ede05'
            '6e82061d02f7dd82a4b01d6f3842a4d6be606c132d8c2d2c2dcd04d967070edb'
            'b7b569f0af73bb01edd6d6db23bbb51189a597f98b0e7ade7ddc54e5897364a4'
            'fe87915cf23d72b5018fbd4376c6e2701751ec4fea1f174eebd1f7a9ab7a097c'
            '18934833f57b079d5f60295b94305c05afb47697a53ae2a5afe935e26c513275'
            'c7f3d2544c4683e5275544f38d8624d356fc92f2ead9aa395966104053c197ed'
            '823209c6ade2bb776978eadb656c6be9faa3a577a7fc1ab12bd3501b9be8fb2e'
            'd8f9cd8f56810d6017b9928fcab4cba2dfd1981c8b7ec95cb2d5561cb905955c'
            '0312dfaf157f9d5f863dfb0423772e7ff60b0b7c8a4ac97c3430ae9cbd2d43af'
            '04f2ce20499c569d76f8e8b0e2a2998ee8c0b4049eb2f705bbf1d5be7884edcc'
            '5f53766aa8f4c16cc314d7e63d88fc3a3140adde8c882af502f68b846d37f715'
            '1669d8e8a32abbcac7b57b8ef0468a3a4add57bdc693b0ebe29065a93a5dfe41'
            '359b5ac6631fb585704dd0e6b1ed8924d0bfd6eb358f2134e0d82632d97e41f7'
            '87628101d1731bcb3d2b5c1cf73a591469a6bbb5a3273c69270c8099ab8d7256'
            'db0826844b8e485f632e7bf5d95caf2db927b980bf244d206286f80d3f8eb72c'
            '60a280b2c6a97af45dbe63ac2bafdbf3ab1a74624f9c6056c8622db8302c633f'
            '9fa3be4003cde96aa4d0e9f0f0b2e8ee04ffd7f4418fbf289dfdd175564ba966'
            '402a52653ab821bd313e0d6bbf95522893a5338206fdb387ee39f2a0877a09c0'
            '79231c3569f123c0f38052a7873446ebb8e5d1f27661ddf532a548f5eec045bd'
            'e345db4fadf2e4971ad5dd7608f0fd20c195f5a2b25885f13e1b27ae96b00a03'
            '49a82ede635433fb00031c95ccdc283a005d943c2d1fe952123d91789d957e5e'
            '9d5090f20062a3fea4d2054052677c422e72ac368fd9f3ab35319efbbcd2eadf'
            'ccf2092a987559cbb5b0b614f188b6eafb44d232308ee7deda601f5c017fc4e6'
            '7b5e4f285721eac6fdd3e5a2c6a396860a8bb408e4ae33cdfc8b94732530681c'
            '16a04dba9524429c82fee6fd65437aa15d23aabab439dbbb26c9549451a6cea0'
            'f61568b6fd8b0131d81b2aaba769a845ebac599382633e1551e9889b9d097076'
            '8af826e084722a8e298c8a82dfe4347d8496b86f3b28f9bd26821c10f8c80e94'
            '59d7a1771a58671376afee172a89c941b01bbffc67cb1177d94147d5428c75d5'
            '9d41174d35283fab482f3a6eb1268095e7bd66e1f06197a64992f6be44654d5c'
            '8831c319a7639463de414b528667a5d2c6d1df8806b7ec8d7451adb11f8572c3'
            'e348e9df6874dd24dd2a7bb93aeef8fa61948cb74790f66e0be1a2632997a261'
            '3fea4c70225034cd1547606b82444f71c2f116c761fa79b30e77e7a7085745ce'
            'c4eae5e94d4ed2b5daa16c213f5073f8a2ef381306a55b286da52f33f6d9fc75'
            '987881b66fc53e4487e20cc79dad5e6de88ae94db72081ac9eafda7c69bb4a75'
            '3233d156cca5e6715849d40f4e1dcbb130b599c97b1bbf505d2ad4f54008a8a2'
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
