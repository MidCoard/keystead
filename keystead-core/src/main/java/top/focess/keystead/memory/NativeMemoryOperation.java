package top.focess.keystead.memory;

/** Stable redacted identifiers for native-memory setup and lifecycle operations. */
public enum NativeMemoryOperation {
    PLATFORM,
    NATIVE_ACCESS,
    ABI_LAYOUTS,
    SYMBOLS,
    ALLOCATION,
    PAGE_LOCK,
    DUMP_EXCLUSION,
    COPY,
    WIPE,
    PAGE_UNLOCK,
    RELEASE
}
