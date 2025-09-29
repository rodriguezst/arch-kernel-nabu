# Kernel Update: 6.16.0 → 6.17.0

## Summary
Automated kernel update with intelligent conflict and build issue resolution using Claude Code.

## Changes Made
- **Version Update**: 6.16.0 → 6.17.0
- **Package Release**: Reset to pkgrel=1
- **Configuration**: Updated for new kernel version
- **Patches**: 50 patch files regenerated

## 🔧 Rebase Conflict Resolution

<details><summary>Click to view conflict resolution details</summary>

```markdown
# Rebase Conflict Resolution Log

## Overview
This document details the resolution of conflicts encountered during the rebase from v6.16 to master (v6.17) for the arch-kernel-nabu custom patches.

## Rebase Information
- **Source Branch**: Custom patches based on v6.16
- **Target Branch**: master (v6.17, commit e5f0a698b34e)
- **Total Patches**: 49 patches to rebase
- **Conflicts Encountered**: 1 file
- **Date**: 2025-09-29

---

## Conflict 1: drivers/gpu/drm/panel/panel-novatek-nt36523.c

### Commit Being Applied
- **Commit**: 096810caf5ea
- **Message**: "drm/panel: nt36523: enable prepare_prev_first"

### Conflict Type
**API Initialization Order Conflict** - The incoming patch adds a new API call (`drm_panel_init`) and sets a flag (`prepare_prev_first`), but the HEAD already has the flag set in a different location.

### Analysis

#### Three-Way Merge Context:
1. **BASE (common ancestor)**: Did not have `prepare_prev_first` set or `drm_panel_init` called at this location
2. **HEAD (current state at line 1455)**: Added `pinfo->panel.prepare_prev_first = true;` AFTER the orientation check
3. **INCOMING (patch at lines 1446-1447)**:
   - Adds `drm_panel_init(&pinfo->panel, dev, &nt36523_panel_funcs, DRM_MODE_CONNECTOR_DSI);`
   - Adds `pinfo->panel.prepare_prev_first = true;` (duplicate of HEAD's change)

#### Conflict Location (line 1448):
```c
pinfo->dsi[0] = dsi;
mipi_dsi_set_drvdata(dsi, pinfo);
<<<<<<< HEAD
=======
pinfo->panel.prepare_prev_first = true;
drm_panel_init(&pinfo->panel, dev, &nt36523_panel_funcs, DRM_MODE_CONNECTOR_DSI);
>>>>>>> 096810caf5ea (drm/panel: nt36523: enable prepare_prev_first)

ret = of_drm_get_panel_orientation(dev->of_node, &pinfo->orientation);
```

### Root Cause
The patch was created when `prepare_prev_first` needed to be set, and the author added it along with the required `drm_panel_init()` call. Between v6.16 and master, upstream changes moved or also added the `prepare_prev_first = true` line to a different location (after the orientation check). This created a duplicate.

### Resolution Strategy
1. **Keep the new API call**: Add `drm_panel_init()` from the incoming patch as it's necessary for proper panel initialization
2. **Avoid duplication**: Remove the duplicate `prepare_prev_first = true` from the incoming patch
3. **Preserve HEAD's placement**: Keep the existing `prepare_prev_first = true` at line 1455 (after orientation check) as this is where upstream/HEAD has it

### Final Resolution
```c
pinfo->dsi[0] = dsi;
mipi_dsi_set_drvdata(dsi, pinfo);
drm_panel_init(&pinfo->panel, dev, &nt36523_panel_funcs, DRM_MODE_CONNECTOR_DSI);

ret = of_drm_get_panel_orientation(dev->of_node, &pinfo->orientation);
if (ret < 0) {
	dev_err(dev, "%pOF: failed to get orientation %d\n", dev->of_node, ret);
	return ret;
}

pinfo->panel.prepare_prev_first = true;
```

### Changes Made
1. Added `drm_panel_init(&pinfo->panel, dev, &nt36523_panel_funcs, DRM_MODE_CONNECTOR_DSI);` after `mipi_dsi_set_drvdata()`
2. Removed duplicate `prepare_prev_first = true` from incoming patch
3. Kept existing `prepare_prev_first = true` at its current location after the orientation check

### Rationale
- **Preserves patch intent**: The patch wanted to enable `prepare_prev_first` and properly initialize the panel - both goals are achieved
- **Respects upstream changes**: Keeps the `prepare_prev_first` location that upstream has chosen
- **Minimal changes**: Only adds the necessary `drm_panel_init()` call without disrupting other code
- **Maintains initialization order**: Panel is initialized before orientation check, and `prepare_prev_first` is set before backlight and panel add operations

### Validation
- ✅ No conflict markers remain in file
- ✅ Code structure is syntactically correct
- ✅ Proper C indentation maintained
- ✅ All function calls follow kernel coding standards
- ✅ Panel initialization order is logical: init → check orientation → set flags → add panel

---

## Summary
- **Total Conflicts Resolved**: 1
- **Files Modified**: 1
- **Resolution Method**: Manual merge with careful analysis of both versions
- **Patch Compatibility**: Fully compatible with upstream changes
- **Functional Impact**: None - patch intent preserved while respecting upstream modifications

## Rebase Completion Status
✅ **SUCCESSFULLY COMPLETED**

- **Total Patches Applied**: 49/49
- **Conflicts Encountered**: 1
- **Conflicts Resolved**: 1
- **Final HEAD**: b96fd90b4069 (nt36xxx: Change pen resolution)
- **Base**: e5f0a698b34e (Linux 6.17)
- **Working Tree**: Clean

All patches from the v6.16-based branch have been successfully rebased onto Linux 6.17 (master). The rebase completed without any additional conflicts after resolving the single conflict in panel-novatek-nt36523.c.

### Verification
- ✅ All 49 patches applied successfully
- ✅ No remaining conflicts
- ✅ Working tree is clean
- ✅ Git history is linear and properly ordered
- ⏳ Build validation pending (as per workflow)```
</details>

## 🔨 Build Issue Resolution

<details><summary>Click to view build fix details</summary>

```markdown
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
All build failures have been successfully resolved through systematic API migration. The kernel now compiles cleanly with all original functionality preserved. The patches have been regenerated and are ready for use with Linux kernel v6.17.```
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
