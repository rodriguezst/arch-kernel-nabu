# / AArch64 Xiaomi Pad 5
# Maintainer: rodriguezst <git@rodriguezst.es>
pkgbase=linux-nabu
pkgver=6.17.0
_kernelname=${pkgbase#linux}
_desc="AArch64 Xiaomi Pad 5"
_srcname="linux-${pkgver/%.0/}"
_dtbfile='qcom/sm8150-xiaomi-nabu.dtb'
pkgrel=106
arch=('aarch64')
url="http://www.kernel.org/"
license=('GPL2')
makedepends=('xmlto' 'docbook-xsl' 'kmod' 'inetutils' 'bc' 'git' 'uboot-tools' 'dtc' 'python3' 'systemd-ukify' 'sbsigntools')
options=('!strip')
source=("http://www.kernel.org/pub/linux/kernel/v6.x/${_srcname}.tar.xz"
        'config'
        '002-beb3b9d1-input-nt36xxx-enable-pen-support.patch'
        '003-f02a3907-nt36xxx-add-pen-input-resolution.patch'
        '004-e35ece78-add-sm8150.config-fragment.patch'
        '005-45bf5599-sm8150-config-added-display-panel-and-backlight-module..patch'
        '006-552c4598-sm8150-add-apr-nodes.patch'
        '007-00257df7-sm8150-add-slimbus-nodes.patch'
        '008-169fb43f-arm64dts-add-wcd9340-device-tree-binding-for-sm8150-platform.patch'
        '009-e9ffee7b-asoc-qcom-sm8150-add-slimbus-audio-support.patch'
        '011-2dde5389-sm8150-add-uart13-node.patch'
        '012-cdc069fa-arm64-dts-qcom-initial-xiaomi-mi-9-support-cepheus.patch'
        '013-a0bf27e2-arm64-boot-dts-qcom-add-oneplus-7prot.patch'
        '014-e6a93379-arm64-dts-sm8150-oneplus-guacamole-add-s6sy761-touch.patch'
        '015-8003c0ec-arm64-dts-sm8150-oneplus-enable-modem-and-wlan.patch'
        '016-0e3df7a2-fixup-dts-add-ts-pinctrl-and-rmtfs_mem-guard.patch'
        '017-c6882f93-sm8150-add-device-tree-for-xiaomi-pad-5.patch'
        '018-3f6c9bea-drmpanel-nt36523-add-xiaomi-pad-5-csot-panel.patch'
        '019-97b90fc4-drmpanel-nt36523-enable-120fps-for-nabu-csot.patch'
        '020-d8523d1c-arm64-dts-qcom-pm8150b-add-fuel-gauge.patch'
        '021-a031f108-drmpanel-novatek-nt36523-transition-to-mipi_dsi-wrapped-functions-for-nabu.patch'
        '022-39e4c526-drm-add-drm-notifier-support.patch'
        '023-f730ea02-drm-dsi-emit-panel-turn-onoff-signal-to-touchscreen.patch'
        '024-16091a94-input-add-nt36523-touchscreen-driver.patch'
        '025-42f14de9-input-nt36523-remove-fw-boot-delay..patch'
        '026-c80bc674-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on-phy-clock.patch'
        '027-5f37abd2-arch-arm64-boot-dts-qcom-xiaomi-nabu-add-rtc-nodes.patch'
        '028-2a7f4551-asoc-qcom-sm8150-add-machine-driver.patch'
        '029-1cdc3d69-of-property-fix-remote-endpoint-parse.patch'
        '030-91b3bcd6-nt36xxx-change-pen-resolution.patch'
        '031-b1edf936-power-supply-add-driver-for-qualcomm-pmic-fuel-gauge.patch'
        '032-ff0d1403-power-supply-qcom_fg-dont-put-battery-info-on-remove.patch'
        '033-1ab2f575-power-supply-qcom_fg-invert-charging-current.patch'
        '034-b1c33086-power-qcom_fg-add-initial-pm8150b-support.patch'
        '035-c75db0a7-power-supply-qcom_smbx-allow-disabling-charging.patch'
        '036-d723c527-power-supply-qcom_smbx-respect-battery-charge-term-current-microamp.patch'
        '037-1fa2083e-power-supply-qcom_smbx-bump-up-the-max-current.patch'
        '038-09f2bb9c-power-supply-qcom_smbx-remove-unused-registers.patch'
        '039-2977394f-power-supply-qcom_smbx-add-smb5-support.patch'
        '040-c6a41d31-maintainers-add-myself-as-smbx-charger-driver-maintainer.patch'
        '041-a2deb3a7-power-supply-qcom_smbx-program-aicl-rerun-time.patch'
        '042-774dcf8d-power-supply-qcom_smbx-default-case-handling-for-smb_get_prop_health.patch'
        '043-d2e9db61-power-supply-qcom_smbx-remove-unsupported-__counted_by-attribute.patch'
        '044-6fecb7fb-dt-bindings-power-supply-qcompmi89980-charger-add-pm8150b-and-7250b.patch'
        '045-4be09c75-dts-qcom-sm8150-enable-pm8150b_charger.patch'
        '046-8ad2ba26-defconfig-sm8150-add-smbx-and-compressed-fw-loader.patch'
        '047-435fcb32-drmmsmdsi-change-sync-mode-to-sync-on-dsi0-rather-than-dsi1.patch'
        '048-418f8b80-dt-bindings-crypto-ice-document-sm8150-inline-crypto-engine.patch'
        '049-27df6893-arm64-dts-qcom-sm8150-use-standalone-ice-node-for-ufs.patch'
        '050-4ce6db24-arm64-dts-qcom-pm8150-add-vph_pwr-and-vcoin-adc-channels.patch'
        '051-73194c3c-regulator-max77826-add-gpio-enable-support.patch'
        '052-1a82749b-dwc3-core-add-ssp-u3-u0-link-state-related-quirk.patch'
        '053-1a361189-dwc3-core-add-support-to-disable-clock-gating-with-usb-controller.patch'
        '054-a08ccf05-drm-panel-add-support-for-lh568wf3-ed01-amoled-panel-nt37280.patch'
        '055-dfb668bb-input-touchscreen-stmfts-driver.patch'
        '056-beb0e2af-arm64-dts-qcom-initial-google-pixel-4-support-google-flame.patch'
        '057-bb196881-defconfig-sm8150-hack-unset-config_efi_zboot.patch'
        '058-1e9a6048-arm64-dts-qcom-sm8150-add-refgen-regulator.patch'
        '059-2c5a06c8-arm64-dts-qcom-google-flame-add-charger-node.patch'
        '060-0f8c32d6-input-touchscreen-fts_touch-fix-all-compilation-warnings.patch'
        '061-fbcc52de-input-touchscreen-fts_touch-fix-firmware-loading.patch'
        '062-a4313cdf-power-supply-qcom_fg-fix-build-for-6.17.patch'
        '063-972944d1-arch-arm64-boot-dts-qcom-sm8150-add-reset-to-mdss.patch'
        '064-NABU-remove-resets-from-ufs-related-nodes-to-avoid-r.patch'
        '065-clk-qcom-clk-regmap-Add-udelay-in-clk_enable_regmap-.patch'
        'linux.preset')
sha256sums=('9b607166a1c999d8326098121222feb080a20a3253975fcdfa2de96ba7f757a7'
            '0aba21b4cc451cf99b75c76723ceed52080bf435c7d3a7dd6d3281c17afaee42'
            '80f0d8d3d3076692f2beab0f24967efcdd896d2bda75788839cef29dc84299d0'
            '5ed3bf14ded494d8389c8a5f78effe505f5f5a86145264650f5401cd2f85d106'
            'ba3a4fae3c2b3de425986d4ab0da3ca0df2e9841892a768a64dd3784b7c3c94f'
            '2167977f2f608925ec551633126812bf6199200cce66e8a3badba86cf2e4ea66'
            'b55e420f909137e2feb81cc9044af27f8b0ef777c7d3e5f3e25d845b78684e26'
            '07d7bf05eda2a1d54905420e0dbaacb8c2887eb028d16dd1c0f535147691efb7'
            'e79efe1302fb6fb06a7c0aa5dde81f360e78fe8d20b11576f30812afe179a8a3'
            'c961d992386924e0113a47e7808fb57890f4c506c4c5a461686dbba943005b78'
            '8071751ced873ea98643afd8b33114fbe50048b833c576abf8ffaf979861e3aa'
            '3ee191a23fc2505f74279dc1c9c16816d4ef116430563f37424173d633f659cf'
            '5addf1757045dc397c0f9b8ac9e6ff4229b0a06530681cf61eeef5a36e67d464'
            '4733d29e52edd1f895429be143c4f23b1298b937167523c445d5581d251280dc'
            '3b0a4de0888fdf75feac8e7c3aad2b78119eef7bb73c7d57aebd9b834580e54b'
            '2b00c960ebec5101477757472b6e5fd798b2ec46eb35ac96621e494669f3e266'
            '617beb8e33149e0e60ff6638630e616f204a73baded4172105e1ce2b8628f6d5'
            'eea83308635db2326e10c61afe7367891961811c55c8000e2eace665bf78cc1b'
            'f4f475d4c9c987ada87a5a6a2922f16a9bb78fdb10ac8baa7fbf02373feb85f0'
            '28b79bbce9a4a45e3cb09081276c68e7c230c9c58274cda86d666533f2d6b901'
            '4de263efa079912a938b7e3efa6d5eb6f566a17fd49ba39c5bce30f5f920fde1'
            '905adcbad9250c66907e8cc804d2bba6986ba12835d4c81bc714c77fe5059a5c'
            '6fa651161cef71b8388942a94a5b37751ac7387ac55956d58e97483729a68432'
            '5befb23a6412ca260cfa39c3c36583dc0be02e555076174e55952e75558171c1'
            'a68bdff8879293ca8dd61e0499a796374d01472162b4d71e580494ed77997cee'
            'c66d7ce1d2ae402ecddea6a792287e4c1d32b5f0c47442c47d8e37c8ced10669'
            '4c442fb2184ca044c5596f30fe467b60228029841bcb8e675bed181208f90dec'
            '8347aea1e6ae608bb3d9703dd6fb49706e18c1ddc5c27d8d0daa84c389d4d985'
            '6ba8ba93054a586e8d46ea24673f74c3129f70a64841a26bd17d5db1603cc356'
            '5ae328f8a51da46409cdd3f8803d1b0864e7afd87a5500dc8166da59ec29dd46'
            '3a95af79fb461d2d08cdb0f40ecbc22f49c279d1dc28148e1ec89f53ec060255'
            '859ca4246cd774c74136027935ab8f3783b9da14ba5e71fdd383a18a4052f470'
            'd40d8324bc7d4f649f902d7391cd493a63e9311a1b862f8f815c50e9f08c8ad6'
            'c36c8cd88ad8f554aa220c06ed808e0daf0a0486149a067abc0c93fdc4a1a18d'
            '68d4a2376340d8f2e51710ff800942821419d15401e604f31976fa3668af3af7'
            'c5982e841721b7e63d142701df339abd0fa6a2af57c1397a708afb10aa2c4b45'
            '239db000e5280e1c436e2a149a202010f342f4ac18a1c16e88a6124319b44fa4'
            'e85458a414eadd1b7f3778d04ffd9731fe13ecef0e1b1778b6a304d914f337d3'
            '077b50f6cb043f9f8e5373adc8fcd9c7c88e09cc967758408442d0ac4a1fdc7b'
            '0527ff8e81f048d30096f624478e885628aaae4124a747dc71e124049550bec4'
            '659af72aa37394224e39ff0f841a3b8a2f8a2c661be73d8a235d87c0ecfdc8a0'
            '0b78aebbb163afc5899cfc12da9522fea72e2bcd4c9577c643dfe31e1dfe0257'
            'c9d4ebbcedcc4264e836de0ee3741faa1743689c979fed31502afa35f3e2a8fb'
            'd04c816ff45023ff2809e38f28acf6a138b5492162cae4a5fd8f9cc64beefcd8'
            'e7e39bee6ee5c2a827031f58e840ee3921e94d462281391e07debae07f8f7548'
            '1a5957ce4d8120b63f7d6f93ab31ff5349fdbd78352641b7a0bf64ca451bb365'
            'e88fb42b7c85c02a22392ed10bf32072c5192134fcb8ce705d1c7c01527b0335'
            'e73e576fda8fbf6462012ba3a45626b28415283866717ef63f6dcf7eca2dfcc4'
            '4b104ecd10329b412efb2d5eb076623e575a009c703effa19b3193b03c4b6378'
            '53e705faaf6da0489dd54f994e98ade3ceee57b647cca342726e2eb8d4227561'
            '8089c4bca5d2a09ffe00e68f0903d1a5f77f12e406bbd3078a931f10d110f796'
            '98fc7d561723ca451c20767506d3d6d7694188e967dcf66395ccc632a598b1d8'
            '6b572ef60f8356592b04fb988c44adb270cd502fc082484dde936f7a57b0ec19'
            '055f04c52a6ce568fed69604a0eea0678147936f37d9c0a0eb150a4203136085'
            '367a540630b005d23edb7af89dca8b76f7a85872bfd3208fcc7303c5009bdfc2'
            'ca722af345c794e100b9cc01f97cb4fbf0fada7b868751d0abb5ad6a92667ed8'
            '7a52b883f8d5ce2e77b13fc004e4d68fe565fd7833f157fb2b95c3a7aa94c7ca'
            'fb20d4f2cf36c6b1d22a1652c5dd2af2bbf6c95fb8ae530cf18ff15338fefa55'
            '013f606cfc0793f8283a1718c0d68f8d55a6e10964877ae7dd84368d18ab9f12'
            'f6e72771201a9b732a1c98a79780718f3f11b72914b7cc74c82bd529bf2c5eec'
            '226731fe9e01d5700083f711323e4f8118e5687d08d50f3877c0ed5f6d71876b'
            '11642bd8b74bd9cd9b488829faec14e47e1d0590da32aab1a2b296be1fa9e398'
            '71f801b2e12c086126791adc3e1a65f16bd1891c15df045467dc3d795756da66'
            'dacd39ba3510e92ec15dcf2573654f94cb56543c7a6825aa525031134ee55e1a'
            '28873983c239155dd6df26cb2edbb1985e18dd2223798eef4e5700b7a3ac8f14'
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
