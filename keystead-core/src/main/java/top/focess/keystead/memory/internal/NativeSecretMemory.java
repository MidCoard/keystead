package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Cleaner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.SecretMemory;

/**
 * One independently protected native secret mapping and its ownership lifecycle.
 *
 * <p>Construction advances {@code ALLOCATED -> LOCKED -> DUMP_EXCLUDED (Linux) -> COPY_STARTED ->
 * LIVE}. Every exit at or after {@code COPY_STARTED} wipes the full page-rounded mapping before
 * unlock and release, attempting every cleanup step even when an earlier one fails. A best-effort
 * {@link Cleaner} state, which cannot retain the owner, performs the same one-pass cleanup for
 * abandoned objects; deterministic {@link #close()} remains required.
 */
public final class NativeSecretMemory implements SecretMemory {

    private static final @NonNull Cleaner CLEANER = Cleaner.create();

    private final @NonNull State state;
    private final int logicalLength;

    private int callbackDepth;
    private boolean closed;
    private boolean closeRequested;

    private NativeSecretMemory(@NonNull State state, int logicalLength) {
        this.state = state;
        this.logicalLength = logicalLength;
        CLEANER.register(this, state);
    }

    static @NonNull NativeSecretMemory create(
            byte @NonNull [] value, @NonNull NativeOperations operations) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(operations, "operations");
        long byteSize = NativeAbi.roundToPage(value.length, operations.pageSize());
        State state = new State(operations, byteSize, value.length);
        try {
            state.allocate();
            state.lock();
            if (isLinux(operations.platform())) {
                state.dumpExclude();
            }
            state.copyIn(value);
        } catch (NativeMemoryUnavailableException construction) {
            List<NativeMemoryUnavailableException> cleanupErrors = state.cleanup();
            for (NativeMemoryUnavailableException error : cleanupErrors) {
                construction.addSuppressed(error);
            }
            throw construction;
        }
        return new NativeSecretMemory(state, value.length);
    }

    public static @NonNull SecretMemory protect(byte @NonNull [] value) {
        Objects.requireNonNull(value, "value");
        return create(value, resolveDefaultOperations());
    }

    private static @NonNull NativeOperations resolveDefaultOperations() {
        NativePlatform platform =
                NativeAbi.detectPlatform(
                        System.getProperty("os.name"),
                        System.getProperty("os.arch"),
                        System.getProperty("sun.arch.data.model"),
                        System.getProperty("java.vm.name"));
        if (platform == NativePlatform.UNSUPPORTED) {
            throw new NativeMemoryUnavailableException(platform, NativeMemoryOperation.PLATFORM);
        }
        if (!NativeSecretMemory.class.getModule().isNativeAccessEnabled()) {
            throw new NativeMemoryUnavailableException(
                    platform, NativeMemoryOperation.NATIVE_ACCESS);
        }
        return switch (platform) {
            case WINDOWS_X86_64 -> new WindowsNativeOperations();
            // Linux and macOS FFM backends are wired in the following task.
            default ->
                    throw new NativeMemoryUnavailableException(
                            platform, NativeMemoryOperation.SYMBOLS);
        };
    }

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    @Override
    public synchronized int length() {
        requireOpen();
        return logicalLength;
    }

    @Override
    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void copyBytes(@NonNull Consumer<byte[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        callbackDepth++;
        try {
            byte[] copy = state.copyOut();
            try {
                consumer.accept(copy);
            } finally {
                Arrays.fill(copy, (byte) 0);
            }
        } finally {
            callbackDepth--;
            if (closeRequested && callbackDepth == 0) {
                runCleanup();
            }
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        closeRequested = true;
        if (callbackDepth == 0) {
            runCleanup();
        }
    }

    private void runCleanup() {
        List<NativeMemoryUnavailableException> errors = state.cleanup();
        if (errors.isEmpty()) {
            return;
        }
        NativeMemoryUnavailableException first = errors.get(0);
        for (int i = 1; i < errors.size(); i++) {
            first.addSuppressed(errors.get(i));
        }
        throw first;
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretDestroyedException();
        }
    }

    /** Owner-free cleaner state holding the native resources and one-pass cleanup logic. */
    private static final class State implements Runnable {

        private final @NonNull NativeOperations operations;
        private final long byteSize;
        private final int logicalLength;

        private @Nullable Arena arena;
        private @Nullable MemorySegment segment;
        private long address;
        private @NonNull LifecycleState lifecycleState = LifecycleState.INITIAL;
        private final @NonNull AtomicBoolean cleaned = new AtomicBoolean(false);

        State(@NonNull NativeOperations operations, long byteSize, int logicalLength) {
            this.operations = operations;
            this.byteSize = byteSize;
            this.logicalLength = logicalLength;
        }

        void allocate() {
            NativeOperationResult result = operations.allocate(byteSize);
            if (!result.successful()) {
                throw toException(NativeMemoryOperation.ALLOCATION, result);
            }
            this.address = result.value();
            this.arena = Arena.ofShared();
            this.segment = MemorySegment.ofAddress(address).reinterpret(byteSize, arena, null);
            this.lifecycleState = LifecycleState.ALLOCATED;
        }

        void lock() {
            NativeOperationResult result = operations.lock(address, byteSize);
            if (!result.successful()) {
                throw toException(NativeMemoryOperation.PAGE_LOCK, result);
            }
            lifecycleState = LifecycleState.LOCKED;
        }

        void dumpExclude() {
            NativeOperationResult result = operations.dumpExclude(address, byteSize);
            if (!result.successful()) {
                throw toException(NativeMemoryOperation.DUMP_EXCLUSION, result);
            }
            lifecycleState = LifecycleState.DUMP_EXCLUDED;
        }

        void copyIn(byte @NonNull [] value) {
            lifecycleState = LifecycleState.COPY_STARTED;
            NativeOperationResult result = operations.copyIn(segment, value);
            if (!result.successful()) {
                throw toException(NativeMemoryOperation.COPY, result);
            }
            lifecycleState = LifecycleState.LIVE;
        }

        byte @NonNull [] copyOut() {
            assert segment != null;
            return segment.asSlice(0, logicalLength).toArray(ValueLayout.JAVA_BYTE);
        }

        @Override
        public void run() {
            try {
                cleanup();
            } catch (Throwable ignored) {
                // Best-effort cleaner; cleanup failures must never propagate from a GC action.
            }
        }

        @NonNull List<@NonNull NativeMemoryUnavailableException> cleanup() {
            if (!cleaned.compareAndSet(false, true)) {
                return List.of();
            }
            synchronized (this) {
                List<NativeMemoryUnavailableException> errors = new ArrayList<>();
                LifecycleState reached = lifecycleState;
                if (reached.ordinal() >= LifecycleState.COPY_STARTED.ordinal()) {
                    attempt(
                            NativeMemoryOperation.WIPE,
                            () -> operations.wipe(segment, byteSize),
                            errors);
                }
                if (reached.ordinal() >= LifecycleState.LOCKED.ordinal()) {
                    attempt(
                            NativeMemoryOperation.PAGE_UNLOCK,
                            () -> operations.unlock(address, byteSize),
                            errors);
                }
                if (reached.ordinal() >= LifecycleState.ALLOCATED.ordinal()) {
                    attempt(
                            NativeMemoryOperation.RELEASE,
                            () -> operations.release(address, byteSize),
                            errors);
                }
                if (arena != null) {
                    try {
                        arena.close();
                    } catch (Throwable ignored) {
                        // Scope invalidation is best effort after the native release attempt.
                    }
                }
                return errors;
            }
        }

        private void attempt(
                @NonNull NativeMemoryOperation operation,
                @NonNull Supplier<@NonNull NativeOperationResult> call,
                @NonNull List<@NonNull NativeMemoryUnavailableException> errors) {
            try {
                NativeOperationResult result = call.get();
                if (!result.successful()) {
                    errors.add(toException(operation, result));
                }
            } catch (NativeMemoryUnavailableException error) {
                errors.add(error);
            }
        }

        private @NonNull NativeMemoryUnavailableException toException(
                @NonNull NativeMemoryOperation operation, @NonNull NativeOperationResult result) {
            @Nullable Long code = result.osErrorCode();
            return code == null
                    ? new NativeMemoryUnavailableException(operations.platform(), operation)
                    : new NativeMemoryUnavailableException(operations.platform(), operation, code);
        }
    }

    private enum LifecycleState {
        INITIAL,
        ALLOCATED,
        LOCKED,
        DUMP_EXCLUDED,
        COPY_STARTED,
        LIVE
    }
}
