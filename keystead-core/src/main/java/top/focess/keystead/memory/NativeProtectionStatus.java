package top.focess.keystead.memory;

/** Status of a native-memory protection capability at inspection time. */
public enum NativeProtectionStatus {
    /** The capability was exercised and verified. */
    VERIFIED,
    /** A prerequisite for the capability is unavailable. */
    UNAVAILABLE,
    /** An OS operation for the capability failed. */
    FAILED,
    /** The capability does not apply to the detected platform. */
    NOT_APPLICABLE,
    /** The capability was not attempted because a prerequisite failed. */
    NOT_ATTEMPTED
}
