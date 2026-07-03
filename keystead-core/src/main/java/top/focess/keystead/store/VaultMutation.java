package top.focess.keystead.store;

@FunctionalInterface
public interface VaultMutation {

    void commit(long revision);
}
