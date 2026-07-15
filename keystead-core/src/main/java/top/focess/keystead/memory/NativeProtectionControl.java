package top.focess.keystead.memory;

/** Stable ordered identifiers for native-memory protection capabilities. */
public enum NativeProtectionControl {
    PLATFORM,
    NATIVE_ACCESS,
    ABI_LAYOUTS,
    SYMBOLS,
    ALLOCATION,
    PAGE_LOCK,
    DUMP_EXCLUSION,
    WIPE,
    PAGE_UNLOCK,
    RELEASE
}
