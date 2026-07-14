package top.focess.keystead.memory;

import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

public interface SecretMemory extends AutoCloseable {

    int length();

    boolean isClosed();

    void copyBytes(@NonNull Consumer<byte[]> consumer);

    @Override
    void close();
}
