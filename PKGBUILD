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
        '0001-input-nt36xxx-Enable-pen-support.patch'
        '0002-nt36xxx-add-pen-input-resolution.patch'
        '0003-SM8150-Add-apr-nodes.patch'
        '0004-SM8150-Add-slimbus-nodes.patch'
        '0005-arm64-dts-add-wcd9340-device-tree-binding-for-sm8150.patch'
        '0006-ASoC-qcom-SM8150-Add-slimbus-audio-support.patch'
        '0007-SM8150-Add-uart13-node.patch'
        '0008-arm64-dts-qcom-Initial-Xiaomi-Mi-9-support-cepheus.patch'
        '0009-arm64-boot-dts-qcom-add-OnePlus-7-Pro-T.patch'
        '0010-arm64-dts-sm8150-oneplus-guacamole-add-s6sy761-touch.patch'
        '0011-arm64-dts-sm8150-oneplus-enable-modem-and-wlan.patch'
        '0012-fixup-dts-add-ts-pinctrl-and-rmtfs_mem-guard.patch'
        '0013-SM8150-Add-device-tree-for-Xiaomi-Pad-5.patch'
        '0014-NABU-Added-novatek-touchscreen-node.patch'
        '0015-drm-panel-nt36523-Add-Xiaomi-Pad-5-CSOT-panel.patch'
        '0016-NABU-Enable-gpu-dsi0-and-dsi1.-Added-panel-and-backl.patch'
        '0017-NABU-Add-sound-nodes.patch'
        '0018-NABU-Add-pmic-fg-and-battery-nodes.patch'
        '0019-NABU-Add-wcd9340-and-microphone-dais.patch'
        '0020-drm-panel-nt36523-Enable-120fps-for-nabu-csot.patch'
        '0021-NABU-Add-pm8150b-type-c-node-and-enable-otg.patch'
        '0022-NABU-Add-fsa4480-node.patch'
        '0023-NABU-Enable-secondary-usb-and-keyboard-MCU.patch'
        '0024-NABU-Add-flash-led-node.patch'
        '0025-NABU-Add-hall-sensor-for-magnetic-cover-detection.patch'
        '0026-NABU-Set-panel-rotation.patch'
        '0027-NABU-Remove-framebuffer-initialized-by-XBL.patch'
        '0028-NABU-Remove-deprecated-usb_1_role_switch_out-node.patch'
        '0029-arm64-dts-qcom-pm8150b-Add-fuel-gauge.patch'
        '0030-fix-whitelines.patch'
        '0031-drm-panel-nt36523-enable-prepare_prev_first.patch'
        '0032-drm-panel-novatek-nt36523-transition-to-mipi_dsi-wra.patch'
        '0033-drm-Add-drm-notifier-support.patch'
        '0034-drm-dsi-emit-panel-turn-on-off-signal-to-touchscreen.patch'
        '0035-Input-Add-nt36523-touchscreen-driver.patch'
        '0036-input-nt36523-Remove-fw-boot-delay.patch'
        '0037-arch-arm64-boot-dts-qcom-sm8150-add-ufs-dependecy-on.patch'
        '0038-arch-arm64-boot-dts-qcom-xiaomi-nabu-add-rtc-nodes.patch'
        '0039-arch-arm64-boot-dts-qcom-sm8150-xiaomi-nabu.dts-add-.patch'
        '0040-ASoC-qcom-SM8150-Add-machine-driver.patch'
        '0041-of-property-fix-remote-endpoint-parse.patch'
        '0042-Revert-NABU-Set-panel-rotation.patch'
        '0043-nt36xxx-Change-pen-resolution.patch'
        '0044-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch'
        '0045-power-supply-qcom_fg-dont-put-battery-info-on-remove.patch'
        '0046-power-supply-qcom_fg-invert-charging-current.patch'
        '0047-power-qcom_fg-Add-initial-pm8150b-support.patch'
        '0048-power-supply-qcom_pmi8998_charger-fix-wakeirq.patch'
        '0049-power-supply-pmi8998_charger-rename-to-qcom_smbx.patch'
        '0050-power-supply-qcom_smbx-allow-disabling-charging.patch'
        '0051-power-supply-qcom_smbx-respect-battery-charge-term-c.patch'
        '0052-power-supply-qcom_smbx-bump-up-the-max-current.patch'
        '0053-power-supply-qcom_smbx-remove-unused-registers.patch'
        '0054-power-supply-qcom_smbx-add-smb5-support.patch'
        '0055-MAINTAINERS-add-myself-as-smbx-charger-driver-mainta.patch'
        '0056-power-supply-qcom_smbx-program-aicl-rerun-time.patch'
        '0057-NABU-Add-ln8000-fast-charge-IC-for-testing.patch'
        '0058-NABU-dts-enable-ln8000-charger-reduce-charge-voltage.patch'
        '0059-power-supply-qcom_smbx-default-case-handling-for-smb.patch'
        '0060-power-supply-qcom_smbx-remove-unsupported-__counted_.patch'
        '0061-dt-bindings-power-supply-qcom-pmi89980-charger-add-p.patch'
        '0062-dts-qcom-sm8150-enable-pm8150b_charger.patch'
        '0063-drm-msm-dsi-change-sync-mode-to-sync-on-DSI0-rather-.patch'
        '0064-dt-bindings-crypto-ice-Document-sm8150-inline-crypto.patch'
        '0065-arm64-dts-qcom-sm8150-Use-standalone-ICE-node-for-UF.patch'
        '0066-arm64-dts-qcom-pm8150-add-vph_pwr-and-vcoin-ADC-chan.patch'
        '0067-regulator-max77826-Add-GPIO-enable-support.patch'
        '0068-dwc3-core-Add-ssp-u3-u0-link-state-related-quirk.patch'
        '0069-dwc3-core-Add-support-to-disable-clock-gating-with-U.patch'
        '0070-drm-panel-Add-support-for-LH568WF3-ED01-AMOLED-panel.patch'
        '0071-Input-touchscreen-stm-fts-driver.patch'
        '0072-arm64-dts-qcom-Initial-Google-Pixel-4-support-google.patch'
        '0073-arm64-dts-qcom-sm8150-add-refgen-regulator.patch'
        '0074-arm64-dts-qcom-google-flame-Add-charger-node.patch'
        '0075-Input-touchscreen-fts_touch-fix-all-compilation-warn.patch'
        '0076-Input-touchscreen-fts_touch-fix-firmware-loading.patch'
        'linux.preset')
sha256sums=('1a4be2fe6b5246aa4ac8987a8a4af34c42a8dd7d08b46ab48516bcc1befbcd83'
            '8ffad47f67493aebf51173e8d68caff8e4b79d4b3f3cb77f3415c86f1bc8f2fb'
            'b564017c3e01aa6fbe2797d90732aafa5b0234c23f1075c9d4e049b0a3bced14'
            '94da8508d4994fe20d504c9c3b4791b2fd6030238994c250d01e6680c09a1ad8'
            '0f82abaf71fc95a78deaba28e07ee9123eeb5e9ba46c98f640be9288a7ceb43e'
            'f41e6d8a71ceea8363b2c76e10db5bad08ecd2e86aff6f8fa24c528a25a3d0d1'
            '02c16b12f9d32b0448171c1a9d6d2b76113181e3d4957f2fb5817d1d87175b7c'
            'd9cc2ab14b27d7f72108006c68cf80e15d9da4dd43e725016bc89feddfb3deeb'
            'bf3562bff0f4dc1d2849d6e75bc3ff1e94dfe4ad97e0e57b0e787412f3a2af2d'
            '0c98c9f9f8904946f5ea58c9995e6bc2429963a60accdf28a4425d595400c752'
            '66641067bd3f6cd2fb618a7599ad701f862d5e56eb1d6bd8f8df0582142b86f5'
            'a4427a510436f5a0892c8af48e86faf454e0a852896990cfbd187f2fe0d64ef1'
            'a5d0a540603636a0155a8a6889355c878a329423acce7156879ab454cef44c5f'
            'a9bcbefde67bb305e4fd239347242cbd299ab12a2d93d63a4d7cde1cad59b1a5'
            '624d04c51d3a6f11b6eb8043f72fef2ca8e045ea0882394113fabfc7bb7bec8a'
            '9dcf645578a14a6ecfc4f3c5d6776ef4c9bf4fd8744c8f9b9b3978920858fed6'
            'e05c020dc3897dab856999b7289a89237457bf031d423f08edcb55c5ab1f1463'
            '96f717c2447b13b8f6488adfd517e5dfb5f51e2df54860f0531278fd37ab5b55'
            '0424feeae5803a9c9342206564c31ac3de366b2de1d6d18081830c9072adfdd1'
            'c7719b4ee5f42a92496678af205651f28a4322b94006dc29413d53ee49a0281a'
            '1d6410c81607fdaf063e2a071a26271988b26351ee663c22ecb576c159a63f26'
            'a801eb569014072165a2c7fb7d238d3fa88527c26d42e2c584e904675ea59b0b'
            'a098c92e1c6c16a47940143ba1896f71ac7c916f5f7b31de46834855d68898d5'
            '27e730757148018851490aebc26f0b18519c0057ee1e8128b9ab0a623742717c'
            'b3ec08ad9ec1914db3a54ab11f2255ad3905970e66bc3793cb631a828295a6b2'
            '281cab4cc9760e71ebf080b3d59c02c4526439d053a27c728c11879673c0e599'
            'b8fc30eb79a29e2c2d17f79e589d1c478d081138b23fd2d71e53482409f24d73'
            '1d67f408f8de8c2530749311801d9ea6baa2bd07687e5ea741d4d10b32b7fffc'
            '983a4b3f9e3431d7dd48b828229b66ffb20100ea6f6579c5480ae5c6c51ce306'
            '77d7cbd10ec8618674c71a9945271e5f4e3dbb0af50d524cb68110815faac56c'
            'c5af236ea4ffda383b217319c0888d3645646a55456e3b03fbcc091a1f8c048f'
            'd8d64d7890412bb9ae4b6ed7ec272eacd7e394aad325642b89467cfeceafd04b'
            '0bf58cbeca2bdb12563b96db93f06c8b85c713385ba5afb380077346c48a1cbd'
            '519ab728c234df9cd2f23ff13d869357162afd64f4815fa510aea7aea7725c16'
            '2e8d450de43112d1c1e49990d94ea7b667049ece27b0ed50c72b431fbbaf6084'
            'bf3602392ea8cff06ccd27b39db4fa4c41a3015c21a4dac49179cd89eb7179f7'
            'c872eb0d2ee578e44f94e222abde7a79503ff021ca37987b008f85a928f662f3'
            '3e84a08f67bc824357e87d6c0dd837a7b8cfca159cf38d907e484a72815152b4'
            'cd1ed025e1bcc067c7b829457899078f95c5140c7808147a45480084b4da518c'
            'f736d0ad75214856c01641420e5a974b376816102522b7dc925f5599387303ab'
            '53b8db8a2ffce9460027d4b8f5603af3b3c2e67ccffa3b98fecdfe36ae754981'
            'd9e5496c9eb668ba9b441d4e72de73896af010b49ab2c345f126725e97d19d60'
            '6022b58728bc9de9f02da0a3cfaa209527f43c5e1ebd47d7bb576b40b4c5df4f'
            '186edff69743e464eea0b229d9ff6738f0c4d17ac902bbbb97a5bbbc3716c18b'
            'f189a9b02639f35f8085c5322c83e14361f4eaa2817cb09bb5d4dc16853f431b'
            '94979be69580a52cb78829bac1e7ed1328532d6b25046d1b07a68c4b88826dce'
            'dd07abbea43c381c3a4127e6fdb9d01d3c00cfaf0124b108d3b5cd979393e865'
            '32e38ad474ff2de8b5ecfda6d6ebd43be971fe882f572d2e0e66706d4029c167'
            '6bf10349a10b5813399ebaf9fa33eb54ee5d895d852de098923e06951d139e72'
            'e59d93bc7d8cef39dc6823cd6e8621a9fe68673fd9edaac81708a65cd6481996'
            '0d96af5ce4cdb62ddeabf266d17c999208b818fe270fc2c5eae0ccefd810a561'
            'ac19d18632a47250037e3dd0551d38cb8d3b712ff4304cd05812c5ea14aa17a1'
            'cd89b27ff79beb7e0b2c0a762353180c75859db02053c42a3649fcdfd890d51a'
            'd4fc316165c401b3ed66b587631bf273b3fc5fe6f219cdea4117a914796079eb'
            '3aeb13cc908814adb1336f70fd25e72ec0eddb831d3fb3923f8acec8eb99e872'
            '738fb97291388a733edb694be9cccebdb76b57705bf11aa50e03200b928f2251'
            'f1a81b32c118ab8d80cdda2cf0b0ffdb655b31e1469cc8c84d1b967f478710c9'
            '5750f8e2c3f9076d723beeb170704f2744e940c33390a728aede4d2e975db8ae'
            '036e42fb22363e8d29026ad123641ddfdb6e48a20d13b6c451abe8fd47f71410'
            '86184a25034feea3c7b9174f65528e56e4f8638a1e5447afc3efe820ea7d1b44'
            '80acf868afadd579f636ba6b1c6471eacf6301806d9cb4b6a14abe6a335dbb28'
            '4182783c626cde11dfeb4f60917ead4901d87ff9fdd91e11c596671031da956f'
            'bca084664d958c8917eb3de0e43d5acb25c7d8ae26fcbb16f4ad0f1ff6dce2a1'
            'd27c17fe724fe387a05ebba0e96afb298c657f8a59e47220631af0f0d3dd2fa0'
            '33f6a245d489556328a4cc39ca9ebf4bb22169135c27d90e2bc854664957df3e'
            '3f524be38634b72d51be8ecef7499b84f22ec2d5b9d119c04d80cbf6b2f43878'
            'd1cf826be48da92eb498e5ac94549cc6919487056b88fcacb828682b6bbf8eb0'
            '091ae2ec589236baf7f1cc4fe96e6ed282513eb80bf46c5ba49704861e0b7cc0'
            'df83875d201801ec51512536de3aed09105db2a2f2a21a8435dfd02af5af5aa2'
            '7fb00fb6dcf7f7765ecdfbb11969a3fd64a802e0249ad938d7f4ac1ccc3be61d'
            'fccd214a7b90ebf5004ff1ace03b78002f246712f55082615b66d5deb92d998d'
            'f05a518c9640349a5f0e0c5f5dbea130aec43ae7b93bcd149dc2789d882c09c8'
            '7d564e2cf3fc792b7bd0c0a9949eba422f75b88b4908389fff162e489e0494da'
            'd09bbd350c28624b89949ce7336009d36e04a332d53d0d06c0e8fb587086fda5'
            'fd20ae380b09f5d8a33d6976cb176ed54dd31bb2330215f23e71ae2073635ff2'
            '014fe904855dbc25d280c3aaad606f06bfaf318dc6a01715f6045477d0dedd03'
            'e687f60b0edf714f24dbe3c831365480c562e91cb7dee5ca78b4647b279bca61'
            '66af2b7c4e447129b0f8ae952ae760d6075176bfa2dbb1da19981fbe8c40af2b'
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
