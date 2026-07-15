package top.focess.keystead.memory;

/** Status of a native-memory protection capability at inspection time. */
public enum NativeProtectionStatus {
    VERIFIED,
    UNAVAILABLE,
    FAILED,
    NOT_APPLICABLE,
    NOT_ATTEMPTED
}
