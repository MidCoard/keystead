package top.focess.keystead.memory;

/** Stable native platform identifiers reported by Keystead Core. */
public enum NativePlatform {
    /** Windows on 64-bit x86. */
    WINDOWS_X86_64,
    /** Linux on 64-bit x86. */
    LINUX_X86_64,
    /** Linux on 64-bit ARM (AArch64). */
    LINUX_AARCH64,
    /** macOS on 64-bit x86. */
    MACOS_X86_64,
    /** macOS on 64-bit ARM (Apple silicon). */
    MACOS_AARCH64,
    /** Any platform without a supported native backend. */
    UNSUPPORTED
}
