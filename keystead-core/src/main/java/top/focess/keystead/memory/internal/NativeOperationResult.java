package top.focess.keystead.memory.internal;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Internal, fixed-code result of one checked native operation. */
record NativeOperationResult(
        boolean successful, long value, @NonNull String detail, @Nullable Long osErrorCode) {

    static final @NonNull String DETAIL_SUCCESS = "SUCCESS";
    static final @NonNull String DETAIL_OPERATION_FAILED = "OPERATION_FAILED";
    static final @NonNull String DETAIL_ZERO_ADDRESS_REJECTED = "ZERO_ADDRESS_REJECTED";

    NativeOperationResult {
        Objects.requireNonNull(detail, "detail");
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
        if (successful) {
            if (!DETAIL_SUCCESS.equals(detail) || osErrorCode != null) {
                throw new IllegalArgumentException("Successful native result is inconsistent");
            }
        } else {
            if (value != 0L) {
                throw new IllegalArgumentException("Failed native result must not retain a value");
            }
            if (DETAIL_OPERATION_FAILED.equals(detail)) {
                if (osErrorCode == null) {
                    throw new IllegalArgumentException("Native failure requires an OS error code");
                }
            } else if (DETAIL_ZERO_ADDRESS_REJECTED.equals(detail)) {
                if (osErrorCode != null) {
                    throw new IllegalArgumentException(
                            "Policy rejection must not report an OS error");
                }
            } else {
                throw new IllegalArgumentException("Unsupported native operation detail code");
            }
        }
    }

    static @NonNull NativeOperationResult success(long value) {
        return new NativeOperationResult(true, value, DETAIL_SUCCESS, null);
    }

    static @NonNull NativeOperationResult operationFailed(long osErrorCode) {
        return new NativeOperationResult(false, 0L, DETAIL_OPERATION_FAILED, osErrorCode);
    }

    static @NonNull NativeOperationResult zeroAddressRejected() {
        return new NativeOperationResult(false, 0L, DETAIL_ZERO_ADDRESS_REJECTED, null);
    }

    @Override
    public @NonNull String detail() {
        return detail;
    }

    @Override
    public @Nullable Long osErrorCode() {
        return osErrorCode;
    }

    @Override
    public @NonNull String toString() {
        return "NativeOperationResult[successful="
                + successful
                + ", detail="
                + detail
                + ", osErrorCode="
                + osErrorCode
                + "]";
    }
}
