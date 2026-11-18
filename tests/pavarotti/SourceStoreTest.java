package pavarotti;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

public final class SourceStoreTest {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory(Path.of(args[0]), "case-");
        SourceStore store = new SourceStore(dir);
        Path sample = Path.of(args[1]);
        SourceStore.Document original = store.ingest(sample);
        Finding finding = original.rows().getFirst();
        check(finding.id().equals("101") && finding.assets().equals("https://example.org/docs"));
        check(finding.verification().equals("Sin evaluar"));
        store.ingest(sample);
        check(store.load().rows().size() == 1);
        Path archived = dir.resolve(original.digest() + ".json");
        check(Arrays.equals(Files.readAllBytes(sample), Files.readAllBytes(archived)));
        String stale = "[{\"finding_id\":\"4\",\"vulnclass\":\"Prueba\",\"report\":\"versión antigua\","
                + "\"evidence_version\":2,\"report_evidence_version\":1,\"traffic_bindings\":[{"
                + "\"id\":\"8\",\"snapshot\":{\"method\":\"GET\",\"url\":\"https://example.org\",\"status\":200}}]}]";
        Finding quality = SourceStore.parse(stale.getBytes(StandardCharsets.UTF_8)).rows().getFirst();
        check(quality.details().contains("Informe anterior") && quality.details().contains("GET https://example.org 200"));
        check(quality.verification().equals("Sin verificar") && quality.title().equals("Prueba"));
        store.observe("Manual", "https://example.org", "Cita");
        check(new SourceStore(dir).load().rows().size() == 2);
        try { store.observe("Sin protocolo", "//example.org", "Cita"); throw new AssertionError(); }
        catch (IOException expected) { }
        Path bad = Files.createTempFile(dir.getParent(), "bad-", ".json");
        Files.writeString(bad, "[{\"id\":\"unrelated\"}]");
        try { store.ingest(bad); throw new AssertionError(); } catch (IOException expected) { }
        check(store.load().rows().size() == 2);
        Files.writeString(archived, "[]");
        check(store.load().errors().size() == 1 && store.load().rows().size() == 1);
        try { store.ingest(sample); throw new AssertionError(); } catch (IOException expected) { }
        System.out.println("OK · importación, deduplicación, procedencia, verificación y persistencia.");
    }
    static void check(boolean ok) { if (!ok) throw new AssertionError(); }
}
