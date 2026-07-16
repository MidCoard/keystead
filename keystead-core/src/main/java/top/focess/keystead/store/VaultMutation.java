package top.focess.keystead.store;

/**
 * Functional callback for a single atomic vault mutation, invoked with the next monotonic
 * revision assigned by the store.
 */
@FunctionalInterface
public interface VaultMutation {

    /** Applies the mutation at the given revision.
     *
     * @param revision the monotonic revision assigned to this mutation */
    void commit(long revision);
}
