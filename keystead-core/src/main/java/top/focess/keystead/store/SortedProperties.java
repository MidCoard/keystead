package top.focess.keystead.store;

import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import org.jspecify.annotations.NonNull;

/** Properties whose standard serializer enumerates keys in deterministic lexical order. */
public final class SortedProperties extends Properties {

    @Override
    public synchronized @NonNull Enumeration<Object> keys() {
        TreeSet<Object> sorted = new TreeSet<>(Comparator.comparing(value -> (String) value));
        sorted.addAll(super.keySet());
        return Collections.enumeration(sorted);
    }

    @Override
    public synchronized @NonNull Enumeration<?> propertyNames() {
        TreeSet<String> sorted = new TreeSet<>();
        Enumeration<?> names = super.propertyNames();
        while (names.hasMoreElements()) {
            sorted.add((String) names.nextElement());
        }
        return Collections.enumeration(sorted);
    }

    @Override
    public @NonNull Set<String> stringPropertyNames() {
        return Collections.unmodifiableSet(new TreeSet<>(super.stringPropertyNames()));
    }

    @Override
    public synchronized @NonNull Set<Map.Entry<Object, Object>> entrySet() {
        LinkedHashSet<Map.Entry<Object, Object>> sorted = new LinkedHashSet<>();
        super.entrySet().stream()
                .sorted(Comparator.comparing(entry -> (String) entry.getKey()))
                .forEach(sorted::add);
        return Collections.unmodifiableSet(sorted);
    }
}
