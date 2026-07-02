package top.focess.keystead.service;

import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.VaultId;

import java.util.List;
import java.util.function.Consumer;

public interface VaultHandle extends AutoCloseable {

    VaultId vaultId();

    SecretId saveLogin(Consumer<LoginDraft> draftConsumer);

    void withLogin(SecretId secretId, Consumer<LoginSecretView> viewConsumer);

    List<SecretMetadata> listSecrets();

    boolean isClosed();

    @Override
    void close();
}
