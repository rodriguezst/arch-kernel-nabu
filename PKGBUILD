# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>

buildarch=8

pkgbase=linux-nabu
pkgver=6.14.6
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=2
arch=('aarch64')
url="http://www.kernel.org/"
license=('GPL2')
makedepends=('xmlto' 'docbook-xsl' 'kmod' 'inetutils' 'bc' 'git' 'uboot-tools' 'vboot-utils' 'dtc' 'python3')
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
sha256sums=('21817f1998e2230f81f7e4f605fa6fdcb040e14fa27d99c27ddb16ce749797a9'
            'c431d8591eab49aefcc9c5b04409e45eea4cfc952f3dc31ebb3bf03c8a787e82'
            'e54feaddf3655461d6dd17e3841e2279cba5978aae6839775d73c4c826ebde39'
            '6aeddfaf641689c2da7ee5ad50f290b54f706e58a1a7d3688c8ab098e3a656ac'
            '3da2d81de2eaf95c0780e5daa42fd284f4de9b5ad3cd2ad359c8301259522afc'
            '555232045fe455071d953c6ddb1969e580765fd316f1377750c99ab5ca7831d4'
            'da0923eb6a04bc80eff36fbd090e9f3756f806d4a11a0acdde86f12457c2ebac'
            'bd53651f97640c8b1238b40207fc02ff60410dafae4dfb115f6c47dd97e579ba'
            '757dfd1b53f335c2912067e54bbe0244ab1ee9a615cd709fb5190ba8083d65fd'
            '2a99c706af3b4ca3c115d1122db7ce73c5d2a81a2b34c0e4ded1ed6c0b205040'
            'da58be64964711181faa8d70cd850688ee2d66a8f6d93780986f7f4200911bfd'
            '607201deb65fa4319d0b9b84bdfb43516d486d1de6fafa47d8f748bf11d160b7'
            '76a83f9b45fd3e1eb8b9cdf2d3a60de06dca2aa2d66f303e72d14310d9fe1767'
            '237a50fc3a7290ba4a9bf84857f3cab9d36f00c9ba472406ceee979b15d9271b'
            '681ed3dc326fefd1746ac16cf4758438a85f9870c4d6341343d8191d145ece4e'
            '0bba7a37a18ae1ea430d1541df57e3b76bd69125a2b55fd1e3c49339e37941b0'
            '8360d99ad74b1315342e8ed07a0b6f76273182ffede3981a90e17e166a9972aa'
            '65a3ba7f4ee758ab0204b542405183a9e253756ed5bfbb618ad858e0a041dd28'
            'a214f010c6b99c3b92019d61edffe486285c4c520963348d2772703ac2f9a27e'
            'ca023b2634c1d7d836a22d8583ee786239f7c565fdb25a986b7070277b3e4154'
            '2fb87c7f4a0d4af356f724d5620f65720aaee73124b34aba7a0b2056958df49a'
            'e51f7875b9fd981c266bd3afc3b46cff30f61690b9695caf7364031e60d1b44f'
            '5204e4a4d8a52b7b7aa9e951a935184f66a6987a3fa791ebb8d1517cbd2c9bcd'
            '5322dc333efed4a4d5ec04fb6d110e1e8e57817d1b7c1f56ac0f165eec938756'
            '19d620cb3066ccaddcd15054be1e94579c639be194df37aea4368ffcd17347bc'
            '94da3f3bf89c282b0937d67a0fd8623110edef885afd93b0a04e0ba0a461c151'
            '5f64f4c1b374636ad843b0464c198d70df607dd1c77f4279303415199bd7b568'
            '7e1fd40a1a7c42a7df6dff507b1381b1b137b2b0fe87d214ed76db6b5ed77ead'
            '34c9cea4ee90092181882edf299d39ef7c4424be6c0ac095dbee3a42e8a5b301'
            'e94a3ed2c38abd02619fd181d66e0c89c3c2b7d7880609205a392278ac616a91'
            '120f91993a5f2858b5ec7f1bbaa34c9b056a3c48b02d44843c5c31173be40063'
            '7222d14c512d471824f072858288dc0fed98aa78406922c7784a93c66e807a6e'
            '8892ee7f68fdb78c76153734507a6c33855196b4eee162627e95c02df9b387ef'
            'dbd8d730bdd5b42a7ecefea0fc51256cb36c72e33332e738fbbdcdac543a84c7'
            '7c812fa5fb6dbf16191e7bab4de8c38706a237d1c7fabab886261e3b46ec83cc'
            '8f40974eadc093330a76a342285daee357fa10ec45c36ef7da0002e022427818'
            '9947ee919bbb4e4a0a0c16da03f37bd29a7fa70ec1cb65cf307da17db097a805'
            '6c02ff0bd85a564cb1bf0455082c8bd0799a6bff4cb95de8305970d4821b0963'
            '962c81f45aab13421e81fd98acfd21898665bf63ebd38f092712e53ea345f8ca'
            '5567780cd02429c7a6c002ae326065288d9838aaeb265618bc1eae0bce71f5a5'
            '9e099f086193b76159190709d4c5f81f5f758de33baeea6c7362495e5036dd9d'
            '08e82b6ff78749937259b4592dc6270a858e0cf21cdec280e40df39f27f12888'
            '4038b83c22b75700584ff0b4923983cd478b2013ae555cfc2da9decd2ff39181'
            '22c376f91427703ca379d3cf0eba9523285cf3b58dbbf873e5c0810ae0d8ce4d'
            '7af8fed6c78eab4bc95d2c577c6f9d8fb72fe044cd39e42a57c72f82d8d887a2'
            'e6210d5f273454eb26c0c2f638c48359f7e7b6e24009b1eaa58bd4f057be4bc8'
            'd365b9083c60320062befefee940cc70734bfae96c392e4b0cc5edfbabdf18e9'
            'cf88fdf83c320173a1e32cc86802010860766e31104dd0f6185a1c4c43aa7142'
            'e1feb5d87387d7f8925dca2d373464e7493aba598e02e8a7bac1dbeb06e470e8'
            'a6bb7d0c0c8f2eae06d45ba8e7b5513b64d50e29cecd5f1ec345ef20e212a146'
            '4171e1fd3263eb665d0bcdd2aa66ce720adb7f37173dfffa3b159b2a84274e0c'
            '87dfeec62a650337e28b2bb2d59df2674c350bb95abac36a2e5711abf7ca5afe'
            '7d619b1d3a77135e20b96e9f1cbe331eb385b859bbd5db8c7caedd9dd20c78e2'
            '85a14281637f63d062476f5e1985a43bb3acea40e617b1b254e91c563e504be3'
            'f7f3c840c66670bb1d2249749f9a21acd50c4b0e5853e5ca3fa58a17a641269a'
            '62c4ee60521944bf2a47d4ae33f1e97ae6f9e4a940b8449431b6da80b8676833'
            '502c814f380c1b5e0d11183ecc7b21d04207501c52d678324e76ee8c842ae364'
            '063f07e0975e178a10917d279f2353b2769f922da5bb95c78d2a1d31132116f3'
            '453bcefa5947d41e72c1c9dc71da40cd09e855a835e59abe4f894f56dcc59450'
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

_package() {
  pkgdesc="The Linux Kernel and modules - ${_desc}"
  depends=('coreutils' 'linux-firmware' 'kmod' 'mkinitcpio>=0.7')
  optdepends=('wireless-regdb: to set the correct wireless channels of your country')
  provides=("linux=${pkgver}" "KSMBD-MODULE" "WIREGUARD-MODULE")
  conflicts=('linux')
  install=${pkgname}.install

  cd $_srcname
  local kernver="$(<version)"
  local modulesdir="$pkgdir/usr/lib/modules/$kernver"

  echo "Installing boot image and dtbs..."
  install -Dm644 arch/arm64/boot/Image "${pkgdir}/boot/vmlinux-${kernver}"
  install -Dm644 arch/arm64/boot/Image.gz "${pkgdir}/boot/vmlinuz-${kernver}"
  install -Dm644 arch/arm64/boot/dts/${_dtbfile} "${pkgdir}/boot/dtb-${kernver}"

  echo "Installing modules..."
  make INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 DEPMOD=/doesnt/exist modules_install

  # remove build link
  rm "$modulesdir"/build

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

pkgname=("${pkgbase}" "${pkgbase}-headers")
for _p in ${pkgname[@]}; do
  eval "package_${_p}() {
    _package${_p#${pkgbase}}
  }"
done
