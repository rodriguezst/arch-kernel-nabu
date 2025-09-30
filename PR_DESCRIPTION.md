# Kernel Update: 6.16.0 → 6.17.0

## Summary
Automated kernel update with intelligent conflict and build issue resolution using Claude Code.

## Changes Made
- **Version Update**: 6.16.0 → 6.17.0
- **Package Release**: Reset to pkgrel=1
- **Configuration**: Updated for new kernel version
- **Patches**: 49 patch files regenerated

## ✅ Rebase Status
No conflicts encountered during rebase process.

## 🔨 Build Issue Resolution

<details><summary>Click to view build fix details</summary>

```markdown
# Build Fix Log - Kernel 6.17.0

## Summary
Fixed compilation errors caused by power_supply subsystem API changes in kernel 6.17.0 after rebasing patches against the latest stable kernel.

## Issues Fixed

### 1. Power Supply Configuration Structure Change
**Error:**
```
error: 'struct power_supply_config' has no member named 'of_node'; did you mean 'fwnode'?
```

**Root Cause:**
The `power_supply_config` structure was updated to use the generic firmware node API (`fwnode_handle`) instead of the device tree-specific API (`of_node`). This is part of the kernel's ongoing effort to provide a unified interface that works across different firmware types (DT, ACPI, etc.).

**Files Affected:**
- `drivers/power/supply/qcom_fg.c:1204`
- `drivers/power/supply/ln8000_charger.c:1495`

**Solution:**
Changed from `of_node` to `fwnode` and used the `dev_fwnode()` helper function:

**qcom_fg.c:**
```c
// Before:
supply_config.of_node = pdev->dev.of_node;

// After:
supply_config.fwnode = dev_fwnode(&pdev->dev);
```

**ln8000_charger.c:**
```c
// Before:
info->psy_cfg.of_node  = info->client->dev.of_node;

// After:
info->psy_cfg.fwnode  = dev_fwnode(&info->client->dev);
```

### 2. Power Supply Reference API Change
**Error:**
```
error: implicit declaration of function 'power_supply_get_by_phandle'
```

**Root Cause:**
The `power_supply_get_by_phandle()` function was removed in favor of the new `power_supply_get_by_reference()` API, which uses the firmware node interface. Additionally, the `devm_` managed version is now available for automatic resource cleanup.

**Files Affected:**
- `drivers/power/supply/qcom_fg.c:1307`
- `drivers/power/supply/ln8000_charger.c:1572`

**Solution:**
Replaced `power_supply_get_by_phandle()` with `devm_power_supply_get_by_reference()`:

**qcom_fg.c:**
```c
// Before:
chip->chg_psy = power_supply_get_by_phandle(chip->dev->of_node,
                                           "power-supplies");

// After:
chip->chg_psy = devm_power_supply_get_by_reference(chip->dev,
                                                   "power-supplies");
```

**ln8000_charger.c:**
```c
// Before:
info->typec_psy = power_supply_get_by_phandle(info->dev->of_node,"usb-tcpm");

// After:
info->typec_psy = devm_power_supply_get_by_reference(info->dev, "usb-tcpm");
```

## Build Warnings (Non-Critical)
The following warnings remain but do not block compilation:
- Frame size warnings in `arm-smmu-v3.c`, `binfmt_elf.c`, `wireguard/allowedips.c` (stack usage > 1024 bytes)
- Missing prototypes in `nt36xxx.c` and `qcom_fg.c`

These warnings are pre-existing and do not affect functionality.

## Patches Modified
The following patches contained code that was modified:
- `0013-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch` (qcom_fg.c)
- `0030-NABU-Add-ln8000-fast-charge-IC-for-testing.patch` (ln8000_charger.c)

## API Reference
- New API documentation: `include/linux/power_supply.h:810-813`
- Implementation: `drivers/power/supply/power_supply_core.c:505-568`
- Example usage: `drivers/power/supply/bq2415x_charger.c:1677-1679`

## Testing
- Full kernel build completed successfully: `make -j4 Image.gz dtbs modules`
- Build artifacts:
  - Kernel image: `arch/arm64/boot/Image.gz` (14M)
  - Device trees: Built successfully
  - Modules: All modules compiled

## Compatibility Notes
- Changes maintain backward compatibility at the functional level
- Device tree properties remain unchanged ("power-supplies", "usb-tcpm")
- The new API supports both device tree and ACPI firmware
- Using `devm_` version provides automatic resource management, preventing potential memory leaks

## Configuration Changes
No kernel configuration changes were required.```
</details>

## 📋 Upstream Changes

<details><summary>Recent upstream commits</summary>

```
e5f0a698b34e Linux 6.17
c68472b46416 Merge tag 'for-linus' of git://git.kernel.org/pub/scm/linux/kernel/git/rmk/linux
6855f06042ae Merge tag 'i2c-for-6.17-rc8' of git://git.kernel.org/pub/scm/linux/kernel/git/wsa/linux
8f9736633f8c Merge tag 'trace-v6.17-rc7' of git://git.kernel.org/pub/scm/linux/kernel/git/trace/linux-trace
a5b2a9f5056b Merge tag 'spi-fix-v6.17-rc7' of git://git.kernel.org/pub/scm/linux/kernel/git/broonie/spi
09d95bc80235 Merge tag 'mm-hotfixes-stable-2025-09-27-22-35' of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
095530512152 i2c: rtl9300: Drop unsupported I2C_FUNC_SMBUS_I2C_BLOCK
ed45b7a4da17 MAINTAINERS: add entry for SpacemiT K1 I2C driver
9036d0882cdc MAINTAINERS: Add me as maintainer of Synopsys DesignWare I2C driver
b49dde7aa4e0 MAINTAINERS: delete email for Tharun Kumar P
51a24b7deaae Merge tag 'trace-tools-v6.17-rc5' of git://git.kernel.org/pub/scm/linux/kernel/git/trace/linux-trace
0db0934e7f9b tracing: fgraph: Protect return handler from recursion loop
2227f273b7dc rtla/actions: Fix condition for buffer reallocation
b1e0ff7209e9 rtla: Fix buffer overflow in actions_parse
fec734e8d564 Merge tag 'riscv-for-linus-v6.17-rc8' of git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux
d4df17482e96 Merge tag 'x86-urgent-2025-09-26' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
083fc6d7fa0d Merge tag 'sched-urgent-2025-09-26' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
2cea0ed97963 Merge tag 'locking-urgent-2025-09-26' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
8b07f74c23a0 Merge tag 'core-urgent-2025-09-26' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
f26a24662cd2 Merge tag 'v6.17rc7-smb3-client-fixes' of git://git.samba.org/sfrench/cifs-2.6
```
</details>

## 🧪 Testing Performed
- ✅ Kernel compilation successful (Image.gz, dtbs, modules)
- ✅ Configuration validation completed
- ✅ Patch application verified

## 📝 Review Checklist
- [ ] Review conflict resolutions for correctness
- [ ] Validate build fixes maintain intended functionality
- [ ] Check that configuration changes are appropriate
- [ ] Verify patch files are properly formatted
- [ ] Test kernel functionality if possible

---
*This PR was generated automatically by the rebase-patches-with-claude workflow.*
*All conflicts and build issues were resolved using Claude Code intelligent analysis.*
