package top.focess.keystead.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretTypeCatalogTest {

    @Test
    void catalogCombinesSchemasWithZeroKnowledgeTaxonomyDefaults() {
        List<SecretTypeCatalogEntry> entries = SecretTypeCatalog.defaults();

        assertEquals(SecretType.values().length, entries.size());
        assertEquals(SecretType.LOGIN_PASSWORD, entries.getFirst().type());
        assertEquals(SecretTaxonomy.CATEGORY_COMMUNICATION, entries.getFirst().defaultCategory());
        assertNull(entries.getFirst().defaultProvider());
        assertNull(entries.getFirst().defaultSoftware());
        assertEquals(
                List.of("username", "password", "url", "notes"), entries.getFirst().fieldNames());

        SecretTypeCatalogEntry ssh = SecretTypeCatalog.forType(SecretType.SSH_KEY);
        assertEquals(SecretTaxonomy.CATEGORY_DEVELOPMENT, ssh.defaultCategory());
        assertEquals(SecretTaxonomy.PROVIDER_SSH, ssh.defaultProvider());
        assertEquals(SecretTaxonomy.SOFTWARE_OPENSSH, ssh.defaultSoftware());
        assertEquals(SecretFieldType.TEXT, ssh.fields().getFirst().type());
        assertEquals(SecretFieldType.SECRET, ssh.fields().get(1).type());

        SecretTypeCatalogEntry api = SecretTypeCatalog.forType(SecretType.API_TOKEN);
        assertEquals(SecretTaxonomy.CATEGORY_DEVELOPMENT, api.defaultCategory());
        assertEquals(SecretTaxonomy.PROVIDER_API, api.defaultProvider());
        assertNull(api.defaultSoftware());

        SecretTypeCatalogEntry generic = SecretTypeCatalog.forType(SecretType.GENERIC_SECRET);
        assertTrue(generic.allowsCustomFields());
        assertEquals(SecretFieldType.SECRET, generic.customFieldType());
        assertTrue(generic.customFieldsRevealable());
        assertTrue(generic.fields().isEmpty());
    }

    @Test
    void catalogEntriesAreImmutableSnapshots() {
        List<SecretTypeCatalogEntry> entries = SecretTypeCatalog.defaults();
        SecretTypeCatalogEntry login = SecretTypeCatalog.forType(SecretType.LOGIN_PASSWORD);

        assertThrows(UnsupportedOperationException.class, () -> entries.add(login));
        assertThrows(UnsupportedOperationException.class, () -> login.fields().clear());
    }

    @Test
    void catalogRejectsEntriesThatContradictSchemaCustomFieldPolicy() {
        SecretTypeSchema generic = SecretTypeSchema.forType(SecretType.GENERIC_SECRET);
        SecretTypeSchema login = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);

        assertThrows(
                IllegalArgumentException.class,
                () -> new SecretTypeCatalogEntry(generic, null, null, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new SecretTypeCatalogEntry(login, null, null, null, SecretFieldType.SECRET));
    }

    @Test
    void catalogEntryCanonicalizesDefaultTaxonomyFields() {
        SecretTypeSchema login = SecretTypeSchema.forType(SecretType.LOGIN_PASSWORD);

        SecretTypeCatalogEntry canonical =
                new SecretTypeCatalogEntry(
                        login, " Development ", " GitHub ", " GitHub.COM ", null);
        SecretTypeCatalogEntry blankDefaults =
                new SecretTypeCatalogEntry(login, " ", "", null, null);

        assertEquals(SecretTaxonomy.CATEGORY_DEVELOPMENT, canonical.defaultCategory());
        assertEquals(SecretTaxonomy.PROVIDER_GITHUB, canonical.defaultProvider());
        assertEquals(SecretTaxonomy.SOFTWARE_GITHUB, canonical.defaultSoftware());
        assertNull(blankDefaults.defaultCategory());
        assertNull(blankDefaults.defaultProvider());
        assertNull(blankDefaults.defaultSoftware());
    }
}
