// SPDX-License-Identifier: AGPL-3.0-only
package pavarotti;

import com.google.gson.*;
import java.util.ArrayList;
import java.util.List;

/** Presentation of ARTEX FindingDTO. Title and verification rules adapted from ARTEX/report. */
record Finding(String digest, String id, String title, String level, String verification,
               String assets, String details, List<String> urls) {
    static Finding read(String digest, JsonObject row) {
        String id = text(row, "finding_id", text(row, "id", ""));
        if (id.isBlank()) throw new IllegalArgumentException("Falta el identificador del hallazgo.");
        String title = text(row, "name", text(row, "vulnclass", "Sin clasificar"));
        String verification = switch (text(row, "verification_status", "unverified")) {
            case "verified" -> "Verificado";
            case "unverified" -> "Sin verificar";
            case "blocked" -> "Bloqueado";
            case "not_assessed" -> "Sin evaluar";
            case "false_positive" -> "Falso positivo";
            default -> text(row, "verification_status", "");
        };
        List<String> labels = new ArrayList<>();
        for (JsonElement item : array(row, "assets")) {
            JsonObject asset = item.getAsJsonObject();
            labels.add(text(asset, "label", text(asset, "id", "")));
        }
        StringBuilder detail = new StringBuilder(title);
        add(detail, "Fecha de la fuente", text(row, "ts", ""));
        add(detail, "Tarea", text(row, "task_description", text(row, "task_id", "")));
        add(detail, "Estado de revisión", text(row, "status", ""));
        add(detail, "Activos", String.join(", ", labels));
        add(detail, "Resumen", text(row, "summary", ""));
        add(detail, "Evidencia", text(row, "evidence", ""));
        add(detail, "Verificación de la fuente", verification);
        add(detail, "Nota de verificación", text(row, "verification_note", ""));
        add(detail, "Contraevidencia", text(row, "counterevidence", ""));
        add(detail, "Fundamento", text(row, "confidence_rationale", ""));
        String report = text(row, "report", "");
        boolean stale = Boolean.parseBoolean(text(row, "report_stale", "false")) ||
                (!report.isEmpty() && !text(row, "evidence_version", "0")
                        .equals(text(row, "report_evidence_version", "0")));
        add(detail, stale ? "Informe anterior a la evidencia actual" : "Informe", report);
        for (JsonElement item : array(row, "traffic_bindings")) {
            JsonObject binding = item.getAsJsonObject();
            JsonObject snap = binding.has("snapshot") && !binding.get("snapshot").isJsonNull()
                    ? binding.getAsJsonObject("snapshot") : new JsonObject();
            add(detail, "Registro HTTP #" + text(binding, "id", "?"),
                    String.join(" ", text(snap, "method", ""), text(snap, "url", ""),
                            text(snap, "status", "")).strip() + "\n" + text(binding, "note", ""));
        }
        add(detail, "ID de la fuente", id);
        add(detail, "SHA-256 del documento", digest);
        return new Finding(digest, id, title, text(row, "severity", "info"), verification,
                String.join(", ", labels), detail.toString(), labels.stream().filter(Finding::webUrl).distinct().toList());
    }

    private static boolean webUrl(String label) {
        try {
            var uri = java.net.URI.create(label);
            return uri.getHost() != null && uri.getRawUserInfo() == null &&
                    ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()));
        } catch (IllegalArgumentException invalid) { return false; }
    }

    private static String text(JsonObject obj, String key, String fallback) {
        JsonElement value = obj.get(key);
        if (value == null || value.isJsonNull()) return fallback;
        if (!value.isJsonPrimitive()) throw new IllegalArgumentException("Campo no válido: " + key);
        String result = value.getAsString();
        return result.isBlank() ? fallback : result;
    }

    private static JsonArray array(JsonObject obj, String key) {
        JsonElement value = obj.get(key);
        return value == null || value.isJsonNull() ? new JsonArray() : value.getAsJsonArray();
    }

    private static void add(StringBuilder out, String label, String value) {
        if (!value.isBlank()) out.append("\n\n").append(label).append("\n").append(value);
    }
}
