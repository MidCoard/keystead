package top.focess.keystead.memory.internal;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/** Checked, side-effect-free native ABI tuple and size utilities. */
final class NativeAbi {

    private NativeAbi() {}

    static @NonNull NativePlatform detectPlatform(
            @NonNull String osName,
            @NonNull String osArchitecture,
            @NonNull String dataModel,
            @NonNull String virtualMachineName) {
        String os = normalize(osName);
        String architecture = normalize(osArchitecture);
        String model = Objects.requireNonNull(dataModel, "dataModel").trim();
        String virtualMachine = normalize(virtualMachineName);

        if (!"64".equals(model) || !isHotSpotCompatible(virtualMachine)) {
            return NativePlatform.UNSUPPORTED;
        }

        boolean x86_64 = architecture.equals("amd64") || architecture.equals("x86_64");
        boolean aarch64 = architecture.equals("aarch64") || architecture.equals("arm64");
        if (os.startsWith("windows") && x86_64) {
            return NativePlatform.WINDOWS_X86_64;
        }
        if (os.equals("linux") && x86_64) {
            return NativePlatform.LINUX_X86_64;
        }
        if (os.equals("linux") && aarch64) {
            return NativePlatform.LINUX_AARCH64;
        }
        if ((os.equals("mac os x") || os.equals("macos") || os.equals("darwin")) && x86_64) {
            return NativePlatform.MACOS_X86_64;
        }
        if ((os.equals("mac os x") || os.equals("macos") || os.equals("darwin")) && aarch64) {
            return NativePlatform.MACOS_AARCH64;
        }
        return NativePlatform.UNSUPPORTED;
    }

    static @NonNull NativePlatform requireSupportedPlatform(
            @NonNull String osName,
            @NonNull String osArchitecture,
            @NonNull String dataModel,
            @NonNull String virtualMachineName) {
        NativePlatform platform =
                detectPlatform(osName, osArchitecture, dataModel, virtualMachineName);
        if (platform == NativePlatform.UNSUPPORTED) {
            throw new IllegalArgumentException("Unsupported native ABI tuple");
        }
        return platform;
    }

    static long roundToPage(long logicalLength, long pageSize) {
        if (logicalLength < 0L) {
            throw new IllegalArgumentException("Logical length must not be negative");
        }
        if (pageSize <= 0L || (pageSize & (pageSize - 1L)) != 0L) {
            throw new IllegalArgumentException("Page size must be a positive power of two");
        }
        long protectedLength = Math.max(1L, logicalLength);
        long pageCount = Math.floorDiv(Math.addExact(protectedLength, pageSize - 1L), pageSize);
        return Math.multiplyExact(pageCount, pageSize);
    }

    static void requireCanonicalLayouts(
            @NonNull NativePlatform platform,
            @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts) {
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(canonicalLayouts, "canonicalLayouts");
        if (platform == NativePlatform.UNSUPPORTED) {
            throw new IllegalArgumentException("Cannot validate an unsupported native ABI tuple");
        }

        requireValueLayout(canonicalLayouts, "int", 4L, 4L, int.class);
        requireValueLayout(canonicalLayouts, "size_t", 8L, 8L, long.class);
        MemoryLayout pointer = requireLayout(canonicalLayouts, "void*", 8L, 8L);
        if (!(pointer instanceof AddressLayout)) {
            throw new IllegalArgumentException("Canonical void pointer layout has wrong carrier");
        }

        if (platform == NativePlatform.WINDOWS_X86_64) {
            requireValueLayout(canonicalLayouts, "long", 4L, 4L, int.class);
            requireValueLayout(canonicalLayouts, "short", 2L, 2L, short.class);
            MemoryLayout systemInfo = windowsSystemInfoLayout(canonicalLayouts);
            requireSizeAndAlignment(systemInfo, "SYSTEM_INFO", 48L, 8L);
            return;
        }

        requireValueLayout(canonicalLayouts, "long", 8L, 8L, long.class);
        requireValueLayout(canonicalLayouts, "int64_t", 8L, 8L, long.class);
        MemoryLayout rlimit = posixRlimitLayout(canonicalLayouts);
        requireSizeAndAlignment(rlimit, "struct rlimit", 16L, 8L);
    }

    static @NonNull MemoryLayout windowsSystemInfoLayout(
            @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts) {
        MemoryLayout cInt = requireLayout(canonicalLayouts, "int", 4L, 4L);
        MemoryLayout cShort = requireLayout(canonicalLayouts, "short", 2L, 2L);
        MemoryLayout pointer = requireLayout(canonicalLayouts, "void*", 8L, 8L);
        MemoryLayout sizeT = requireLayout(canonicalLayouts, "size_t", 8L, 8L);
        MemoryLayout processorUnion =
                MemoryLayout.unionLayout(
                                cInt.withName("dwOemId"),
                                MemoryLayout.structLayout(
                                                cShort.withName("wProcessorArchitecture"),
                                                cShort.withName("wReserved"))
                                        .withName("processor"))
                        .withName("processorInfo");
        return MemoryLayout.structLayout(
                        processorUnion,
                        cInt.withName("dwPageSize"),
                        pointer.withName("lpMinimumApplicationAddress"),
                        pointer.withName("lpMaximumApplicationAddress"),
                        sizeT.withName("dwActiveProcessorMask"),
                        cInt.withName("dwNumberOfProcessors"),
                        cInt.withName("dwProcessorType"),
                        cInt.withName("dwAllocationGranularity"),
                        cShort.withName("wProcessorLevel"),
                        cShort.withName("wProcessorRevision"))
                .withName("SYSTEM_INFO");
    }

    static @NonNull MemoryLayout posixRlimitLayout(
            @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts) {
        MemoryLayout rlimT = requireLayout(canonicalLayouts, "int64_t", 8L, 8L);
        return MemoryLayout.structLayout(rlimT.withName("rlim_cur"), rlimT.withName("rlim_max"))
                .withName("rlimit");
    }

    static @NonNull String captureStateName(@NonNull NativePlatform platform) {
        return switch (Objects.requireNonNull(platform, "platform")) {
            case WINDOWS_X86_64 -> "GetLastError";
            case LINUX_X86_64, LINUX_AARCH64, MACOS_X86_64, MACOS_AARCH64 -> "errno";
            case UNSUPPORTED ->
                    throw new IllegalArgumentException(
                            "Cannot resolve capture state for unsupported platform");
        };
    }

    static void requireCaptureStateName(
            @NonNull MemoryLayout captureStateLayout, @NonNull String captureStateName) {
        Objects.requireNonNull(captureStateLayout, "captureStateLayout");
        Objects.requireNonNull(captureStateName, "captureStateName");
        final MemoryLayout selected;
        try {
            selected =
                    captureStateLayout.select(
                            MemoryLayout.PathElement.groupElement(captureStateName));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Required native capture state is unavailable");
        }
        requireSizeAndAlignment(selected, "native capture state", 4L, 4L);
        if (!(selected instanceof ValueLayout valueLayout) || valueLayout.carrier() != int.class) {
            throw new IllegalArgumentException("Native capture state has wrong carrier");
        }
    }

    private static boolean isHotSpotCompatible(@NonNull String virtualMachineName) {
        return virtualMachineName.contains("hotspot") || virtualMachineName.contains("openjdk");
    }

    private static @NonNull String normalize(@NonNull String value) {
        return Objects.requireNonNull(value, "value").trim().toLowerCase(Locale.ROOT);
    }

    private static @NonNull MemoryLayout requireLayout(
            @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts,
            @NonNull String name,
            long byteSize,
            long byteAlignment) {
        MemoryLayout layout = canonicalLayouts.get(name);
        if (layout == null) {
            throw new IllegalArgumentException("Required canonical layout is unavailable");
        }
        requireSizeAndAlignment(layout, "canonical layout", byteSize, byteAlignment);
        return layout;
    }

    private static void requireValueLayout(
            @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts,
            @NonNull String name,
            long byteSize,
            long byteAlignment,
            @NonNull Class<?> carrier) {
        MemoryLayout layout = requireLayout(canonicalLayouts, name, byteSize, byteAlignment);
        if (!(layout instanceof ValueLayout valueLayout) || valueLayout.carrier() != carrier) {
            throw new IllegalArgumentException("Canonical value layout has wrong carrier");
        }
    }

    private static void requireSizeAndAlignment(
            @NonNull MemoryLayout layout,
            @NonNull String description,
            long byteSize,
            long byteAlignment) {
        if (layout.byteSize() != byteSize || layout.byteAlignment() != byteAlignment) {
            throw new IllegalArgumentException(description + " has unexpected size or alignment");
        }
    }
}
