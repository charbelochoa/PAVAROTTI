package pavarotti;

import com.google.gson.*;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

/** One immutable document per hash. Parsing and size checks precede publication. */
final class SourceStore {
    static final int MAX_BYTES = 16 * 1024 * 1024;
    private final Path directory;
    record Document(String digest, List<Finding> rows) {}
    record Library(List<Finding> rows, List<String> errors) {}

    SourceStore(Path directory) { this.directory = directory; }

    private static byte[] read(Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(MAX_BYTES + 1);
            if (bytes.length > MAX_BYTES) throw new IOException("El documento supera 16 MiB.");
            return bytes;
        }
    }

    static Document parse(byte[] bytes) throws IOException {
        final String digest;
        try {
            digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException ex) { throw new AssertionError(ex); }
        String json = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        try {
            JsonElement root = JsonParser.parseString(json.startsWith("\uFEFF") ? json.substring(1) : json);
            if (!root.isJsonArray()) throw new IllegalArgumentException("Se esperaba una lista de hallazgos.");
            List<Finding> rows = new ArrayList<>();
            Set<String> ids = new HashSet<>();
            for (JsonElement element : root.getAsJsonArray()) {
                JsonObject row = element.getAsJsonObject();
                if (!row.has("name") && !row.has("vulnclass") && !row.has("summary"))
                    throw new IllegalArgumentException("El registro carece de campos de hallazgo.");
                Finding finding = Finding.read(digest, row);
                if (!ids.add(finding.id())) throw new IllegalArgumentException("ID duplicado: " + finding.id());
                rows.add(finding);
            }
            return new Document(digest, List.copyOf(rows));
        } catch (RuntimeException ex) {
            throw new IOException("Documento ARTEX no válido. " + ex.getMessage(), ex);
        }
    }

    Document ingest(Path file) throws IOException { return save(read(file)); }

    Document observe(String title, String url, String note) throws IOException {
        URI uri;
        try { uri = URI.create(url.strip()); }
        catch (IllegalArgumentException ex) { throw new IOException("URL no válida.", ex); }
        if (title.isBlank() || note.isBlank() || uri.getHost() == null ||
                !("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme())))
            throw new IOException("Introduce título, URL HTTP(S) y una nota de la fuente.");
        JsonObject row = new JsonObject();
        row.addProperty("id", UUID.randomUUID().toString());
        row.addProperty("name", title.strip());
        row.addProperty("task_description", "Observación manual");
        row.addProperty("evidence", note.strip());
        row.addProperty("ts", Instant.now().toString());
        JsonObject asset = new JsonObject();
        asset.addProperty("label", uri.toString());
        JsonArray assets = new JsonArray(); assets.add(asset); row.add("assets", assets);
        JsonArray document = new JsonArray(); document.add(row);
        return save(document.toString().getBytes(StandardCharsets.UTF_8));
    }

    private Document save(byte[] bytes) throws IOException {
        if (bytes.length > MAX_BYTES) throw new IOException("El documento supera 16 MiB.");
        Document document = parse(bytes);
        Files.createDirectories(directory);
        Path target = directory.resolve(document.digest() + ".json");
        if (Files.exists(target)) {
            if (!Arrays.equals(bytes, read(target))) throw new IOException("La copia archivada fue modificada.");
            return document;
        }
        Path temp = Files.createTempFile(directory, ".import-", ".tmp");
        try {
            Files.write(temp, bytes);
            // All writers of a given target hash have identical bytes.
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (FileAlreadyExistsException concurrentImport) {
            if (!Arrays.equals(bytes, read(target))) throw new IOException("Conflicto en el archivo de fuentes.");
        } finally { Files.deleteIfExists(temp); }
        return document;
    }

    Library load() throws IOException {
        List<Finding> rows = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        if (!Files.exists(directory)) return new Library(rows, errors);
        try (Stream<Path> paths = Files.list(directory)) {
            for (Path path : paths.filter(p -> p.getFileName().toString().endsWith(".json")).sorted().toList()) {
                try {
                    Document document = parse(read(path));
                    if (!path.getFileName().toString().equals(document.digest() + ".json"))
                        throw new IOException("La huella SHA-256 no coincide.");
                    rows.addAll(document.rows());
                } catch (IOException ex) { errors.add(path.getFileName() + " · " + ex.getMessage()); }
            }
        }
        return new Library(rows, errors);
    }
}
