# Claude Code Configuration for Kernel Patch Management

## Project Context
This repository maintains a Linux kernel package with custom patches. The kernel is based on the stable Linux kernel tree and includes custom modifications for specific hardware or functionality requirements.

## Coding Standards
- Follow Linux kernel coding style (scripts/checkpatch.pl)
- Maintain compatibility with existing kernel APIs
- Preserve original patch functionality when possible
- Use minimal changes to resolve conflicts

## Rebase Conflict Resolution Guidelines

### Priority Order for Conflict Resolution
1. **Preserve functionality**: The original purpose of patches must be maintained
2. **Adapt to upstream changes**: Prefer using new upstream APIs over maintaining old ones  
3. **Minimize changes**: Make the smallest possible modifications to resolve conflicts
4. **Follow kernel standards**: Ensure all changes conform to kernel coding practices

### Common Conflict Types and Handling
- **API Changes**: Update function calls to match new signatures, add missing parameters
- **Code Movement**: Find where functions/structures were moved and update references
- **Context Changes**: Update surrounding code context while preserving patch logic
- **Duplicate Functionality**: Evaluate if upstream changes make our patches redundant

### Documentation Requirements
For every conflict resolution, document:
- What conflict occurred and in which file
- Analysis of the upstream changes that caused the conflict  
- Strategy used to resolve the conflict
- Any functionality changes or compromises made

## Build Issue Resolution Guidelines

### Error Classification Priority
1. **Critical**: Undefined symbols, missing functions (must fix)
2. **API Incompatibility**: Wrong function signatures (must adapt) 
3. **Configuration**: Missing config dependencies (resolve dependencies)
4. **Warnings**: Deprecated usage (fix when practical)

### Resolution Strategies
- **Missing Symbols**: Locate definition or enable required CONFIG options
- **API Mismatches**: Adapt to new function signatures, handle new parameters appropriately
- **Header Issues**: Update include paths, find moved declarations
- **Config Conflicts**: Resolve dependencies, enable/disable options as needed

### Patch Modification Guidelines
When modifying patches due to build issues:
- Preserve the original intent and functionality
- Make minimal necessary changes for compilation
- Test that modifications don't break intended behavior
- Regenerate patch files properly after modifications
- Document all changes made and reasoning

## Review Criteria
- All conflicts must be resolved with documented rationale
- Build must complete successfully for all targets (Image.gz, dtbs, modules)
- Configuration must be consistent and complete
- Patch functionality must be preserved or clearly documented if changed
- Follow kernel coding standards throughout

## Project Structure
- `PKGBUILD`: Package build configuration
- `config`: Kernel configuration file  
- `*.patch`: Individual kernel patches
- `REBASE_RESOLUTION_LOG.md`: Auto-generated conflict resolution documentation
- `BUILD_FIX_LOG.md`: Auto-generated build fix documentation

## Special Considerations
- This is an automated workflow - prioritize correctness and stability over clever solutions
- When in doubt about a change, document the uncertainty and opt for conservative approaches
- Preserve hardware-specific configurations and functionality
- Test build incrementally when making multiple changes
- Always backup files before making modifications

## Escalation Criteria
Escalate for manual review if:
- Patches become fundamentally incompatible with new kernel changes
- Build failures cannot be resolved without major architectural changes
- Security-related changes are needed
- Hardware-specific functionality would be compromised

## Success Metrics
- Rebase completes without unresolved conflicts
- Full kernel build succeeds (Image.gz, dtbs, modules)  
- All patch functionality is preserved or properly documented
- Configuration remains consistent and complete
- Documentation clearly explains all changes made