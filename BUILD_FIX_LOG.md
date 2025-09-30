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
No kernel configuration changes were required.