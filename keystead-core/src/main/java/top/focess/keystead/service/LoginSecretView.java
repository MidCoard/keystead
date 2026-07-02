package top.focess.keystead.service;

import top.focess.keystead.model.SecretMetadata;

import java.util.Optional;
import java.util.function.Consumer;

public interface LoginSecretView {

    SecretMetadata metadata();

    Optional<String> url();

    void withUsername(Consumer<char[]> consumer);

    void withPassword(Consumer<char[]> consumer);

    void withNotes(Consumer<char[]> consumer);
}
