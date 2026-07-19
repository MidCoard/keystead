package top.focess.keystead.memory;

/** Stable ordered identifiers for native-memory protection capabilities. */
public enum NativeProtectionControl {
    /** Detection of the native platform. */
    PLATFORM,
    /** Verification that the module has native access. */
    NATIVE_ACCESS,
    /** Verification of the platform ABI memory layouts. */
    ABI_LAYOUTS,
    /** Resolution of the required native library symbols. */
    SYMBOLS,
    /** Allocation of native memory. */
    ALLOCATION,
    /** Locking of native pages into physical memory. */
    PAGE_LOCK,
    /** Exclusion of native pages from OS crash dumps (Linux only). */
    DUMP_EXCLUSION,
    /** Wiping native memory contents. */
    WIPE,
    /** Unlocking of native pages. */
    PAGE_UNLOCK,
    /** Release of native memory back to the operating system. */
    RELEASE
}
