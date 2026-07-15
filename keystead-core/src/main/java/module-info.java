module top.focess.keystead.core {
    requires com.google.crypto.tink;
    requires java.management;
    requires jdk.management;
    requires org.bouncycastle.pg;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires transitive org.jspecify;

    exports top.focess.keystead.aigc;
    exports top.focess.keystead.crypto;
    exports top.focess.keystead.generator;
    exports top.focess.keystead.memory;
    exports top.focess.keystead.model;
    exports top.focess.keystead.recovery;
    exports top.focess.keystead.security;
    exports top.focess.keystead.service;
    exports top.focess.keystead.store;
}
