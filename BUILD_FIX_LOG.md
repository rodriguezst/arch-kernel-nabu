# Kernel Build Fix Log - Linux 6.17.0

## Summary
Successfully fixed kernel build failures after rebasing patches to Linux kernel v6.17. All compilation errors were resolved by adapting to power_supply subsystem API changes introduced in this kernel version.

## Build Environment
- **Kernel Version**: 6.17.0
- **Target Platform**: arm64 (Xiaomi Pad 5 - NABU)
- **Build Command**: `make -j4 Image.gz dtbs modules`
- **Date**: 2025-09-29

## Build Failures Identified

### 1. Power Supply API Changes in qcom_fg.c
**File**: `drivers/power/supply/qcom_fg.c`

**Error 1**: Line 1204
```
error: 'struct power_supply_config' has no member named 'of_node'; did you mean 'fwnode'?
```

**Error 2**: Line 1307
```
error: implicit declaration of function 'power_supply_get_by_phandle'; did you mean 'power_supply_get_by_name'?
warning: assignment to 'struct power_supply *' from 'int' makes pointer from integer without a cast
```

**Warning 1**: Line 1066
```
warning: no previous prototype for 'qcom_fg_handle_soc_delta' [-Wmissing-prototypes]
```

**Warning 2**: Line 1077
```
warning: no previous prototype for 'qcom_fg_handle_mem_avail' [-Wmissing-prototypes]
```

### 2. Power Supply API Changes in ln8000_charger.c
**File**: `drivers/power/supply/ln8000_charger.c`

**Error 1**: Line 1495
```
error: 'struct power_supply_config' has no member named 'of_node'; did you mean 'fwnode'?
```

**Error 2**: Line 1572
```
error: implicit declaration of function 'power_supply_get_by_phandle'; did you mean 'power_supply_get_by_name'?
warning: assignment to 'struct power_supply *' from 'int' makes pointer from integer without a cast
```

## Root Cause Analysis

### Power Supply Subsystem API Changes
The Linux kernel v6.17 introduced significant changes to the power_supply subsystem:

1. **Firmware Node API Migration**:
   - The `struct power_supply_config` structure replaced the `of_node` field with `fwnode`
   - This change aligns with the kernel's move towards firmware-agnostic device handling
   - Device tree nodes must now be accessed through `dev_fwnode()` helper

2. **Power Supply Lookup API Changes**:
   - The function `power_supply_get_by_phandle()` was removed
   - Replaced by `power_supply_get_by_reference()` which uses firmware node handles
   - New API signature: `power_supply_get_by_reference(struct fwnode_handle *fwnode, const char *property)`

### API Reference
From `include/linux/power_supply.h` (kernel 6.17):
```c
struct power_supply_config {
	struct fwnode_handle *fwnode;    // Changed from: struct device_node *of_node
	void *drv_data;
	const struct attribute_group **attr_grp;
	char **supplied_to;
	size_t num_supplicants;
};

extern struct power_supply *power_supply_get_by_reference(
    struct fwnode_handle *fwnode,
    const char *property);
```

## Fixes Applied

### Fix 1: qcom_fg.c - Power Supply Config (Line 1204)
**Original Code**:
```c
supply_config.drv_data = chip;
supply_config.of_node = pdev->dev.of_node;
```

**Fixed Code**:
```c
supply_config.drv_data = chip;
supply_config.fwnode = dev_fwnode(&pdev->dev);
```

**Rationale**: Use `dev_fwnode()` helper to get firmware node handle from platform device.

### Fix 2: qcom_fg.c - Power Supply Lookup (Line 1307)
**Original Code**:
```c
chip->chg_psy = power_supply_get_by_phandle(chip->dev->of_node,
                                            "power-supplies");
```

**Fixed Code**:
```c
chip->chg_psy = power_supply_get_by_reference(dev_fwnode(chip->dev),
                                               "power-supplies");
```

**Rationale**: Updated to use the new firmware-node-based power supply lookup API.

### Fix 3: qcom_fg.c - Missing Static Keywords (Lines 1066, 1077)
**Original Code**:
```c
irqreturn_t qcom_fg_handle_soc_delta(int irq, void *data)
irqreturn_t qcom_fg_handle_mem_avail(int irq, void *data)
```

**Fixed Code**:
```c
static irqreturn_t qcom_fg_handle_soc_delta(int irq, void *data)
static irqreturn_t qcom_fg_handle_mem_avail(int irq, void *data)
```

**Rationale**: These IRQ handlers are only used within the same compilation unit and should be declared static to avoid namespace pollution and enable better optimization.

### Fix 4: ln8000_charger.c - Power Supply Config (Line 1495)
**Original Code**:
```c
info->psy_cfg.drv_data = info;
info->psy_cfg.of_node  = info->client->dev.of_node;
```

**Fixed Code**:
```c
info->psy_cfg.drv_data = info;
info->psy_cfg.fwnode   = dev_fwnode(&info->client->dev);
```

**Rationale**: Same firmware node API migration as in qcom_fg.c.

### Fix 5: ln8000_charger.c - Power Supply Lookup (Line 1572)
**Original Code**:
```c
info->typec_psy = power_supply_get_by_phandle(info->dev->of_node,"usb-tcpm");
```

**Fixed Code**:
```c
info->typec_psy = power_supply_get_by_reference(dev_fwnode(info->dev), "usb-tcpm");
```

**Rationale**: Updated to use the new firmware-node-based power supply lookup API.

## Patches Modified

The following patches were regenerated with the fixes:

1. **0013-power-supply-Add-driver-for-Qualcomm-PMIC-fuel-gauge.patch**
   - Updated qcom_fg.c with API compatibility changes

2. **0014-power-qcom_fg-Add-initial-pm8150b-support.patch**
   - Maintained compatibility with base driver changes

3. **0031-NABU-Add-ln8000-fast-charge-IC-for-testing.patch**
   - Updated ln8000_charger.c with API compatibility changes

4. **0043-NABU-enable-ln8000-charger-driver.patch**
   - Maintained compatibility with base driver changes

5. **0050-power-supply-Fix-power_supply-API-compatibility-with.patch** (NEW)
   - Consolidated fix commit for all power_supply API changes

## Verification

### Build Test Results
```bash
make -j4 Image.gz dtbs modules
```

**Status**: ✅ SUCCESS
- Kernel Image: `arch/arm64/boot/Image.gz` (14 MB)
- Device Tree Blobs: Successfully built
- Modules: All modules built successfully
- Warnings: Resolved (only benign frame size warnings in unrelated drivers)

### Build Output Summary
- **No compilation errors**
- **All critical warnings resolved**
- **Full kernel build completed successfully**

## Code Quality
- All changes follow Linux kernel coding standards
- Maintained backward compatibility where possible
- Minimal invasive changes - only what was necessary for compilation
- Preserved all original functionality of the drivers
- No changes to driver logic or behavior

## Testing Recommendations
1. Verify fuel gauge driver functionality on PM8150B-based devices
2. Test battery monitoring and charging state detection
3. Verify ln8000 fast charging IC operation
4. Test power supply relationship and notifications between charger and fuel gauge

## References
- Linux Kernel v6.17 Documentation
- Power Supply Subsystem API: `include/linux/power_supply.h`
- Power Supply Core: `drivers/power/supply/power_supply_core.c`
- Device Firmware Node API: `include/linux/property.h`

## Conclusion
All build failures have been successfully resolved through systematic API migration. The kernel now compiles cleanly with all original functionality preserved. The patches have been regenerated and are ready for use with Linux kernel v6.17.