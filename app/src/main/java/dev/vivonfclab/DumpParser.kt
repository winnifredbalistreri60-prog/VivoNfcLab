package dev.vivonfclab

/** Parse page-oriented *unencrypted* Type 2 tag dump files. Does not emulate or program cards. */
data class DumpSummary(
    val format: String,
    val byteCount: Int,
    val pageCount: Int,
    val uidHex: String?,
    val bcc0Correct: Boolean?,
    val bcc1Correct: Boolean?,
    val notes: List<String>
) {
    fun maskedUid(): String = when {
        uidHex == null -> "не определён"
        uidHex.length <= 6 -> "скрыт"
        else -> uidHex.take(4) + "••••••••" + uidHex.takeLast(4)
    }

    /** Intentionally excludes UID, raw pages, passwords, and authentication material. */
    fun safeReport(): String = buildString {
        appendLine("Тип данных: $format")
        appendLine("Размер: $byteCount байт, $pageCount страниц по 4 байта")
        appendLine("UID: ${maskedUid()} (замаскирован)")
        appendLine("BCC0: ${checkResult(bcc0Correct)}")
        appendLine("BCC1: ${checkResult(bcc1Correct)}")
        notes.forEach { appendLine("Примечание: $it") }
        append("Дамп загружен только в оперативную память. Эмуляция не реализована.")
    }

    private fun checkResult(value: Boolean?): String = when (value) {
        true -> "совпадает"
        false -> "не совпадает"
        null -> "неизвестно"
    }
}

/** In-memory data only; never included in reports and never persisted. */
class ParsedDump internal constructor(val summary: DumpSummary, private val data: ByteArray) {
    val pageCount: Int get() = data.size / 4

    fun uidBytes(): ByteArray = byteArrayOf(data[0], data[1], data[2], data[4], data[5], data[6], data[7])

    fun matchesPage(page: Int, observed: ByteArray): Boolean {
        if (page < 0 || page >= pageCount || observed.size != 4) return false
        return data.copyOfRange(page * 4, (page + 1) * 4).contentEquals(observed)
    }

    fun clear() = data.fill(0)
}

object DumpParser {
    private const val MAX_BYTES = 65536
    const val MF0UL21_PAGE_COUNT = 41
    const val MF0UL21_BYTE_COUNT = MF0UL21_PAGE_COUNT * 4
    private val hexPage = Regex("^[0-9A-Fa-f]{8}$")
    private val hexAll = Regex("^[0-9A-Fa-f]+$")
    private val numberedPage = Regex("^(?:(?i:page)\\s*)?(?:0x[0-9A-Fa-f]+|[0-9]+)\\s*[:\\]]\\s*(.+)$")

    fun parse(input: ByteArray, fileName: String = ""): DumpSummary = parseDetailed(input, fileName).summary

    fun parseDetailed(input: ByteArray, fileName: String = ""): ParsedDump {
        require(input.isNotEmpty()) { "Файл пуст" }
        require(input.size <= MAX_BYTES) { "Файл слишком большой (лимит $MAX_BYTES байт)" }

        val ext = fileName.substringAfterLast('.', "").lowercase()
        val isText = when (ext) {
            "eml", "hex", "txt" -> true
            "bin" -> false
            else -> input.all { c ->
                val n = c.toInt() and 0xff
                n in 32..126 || n == 10 || n == 13 || n == 9
            }
        }
        val (bytes, format) = if (isText) {
            parseText(input.decodeToString()) to when (ext) {
                "nfc" -> "FLIPPER NFC / MFU"
                else -> "HEX/EML"
            }
        } else {
            input.copyOf() to if (input.size == MF0UL21_BYTE_COUNT) {
                "CHAMELEON MF0UL21 BIN"
            } else "BIN"
        }
        require(bytes.size >= 16) { "Не хватает данных: нужно минимум 4 страницы" }
        require(bytes.size % 4 == 0) { "Количество байтов не кратно четырём" }

        val notes = mutableListOf<String>()
        val uid = if (bytes.size >= 12) {
            byteArrayOf(bytes[0], bytes[1], bytes[2], bytes[4], bytes[5], bytes[6], bytes[7]).toHex()
        } else null
        val bcc0 = if (bytes.size >= 4) {
            ((0x88 xor uint(bytes[0]) xor uint(bytes[1]) xor uint(bytes[2])) and 0xff) == uint(bytes[3])
        } else null
        val bcc1 = if (bytes.size >= 9) {
            ((uint(bytes[4]) xor uint(bytes[5]) xor uint(bytes[6]) xor uint(bytes[7])) and 0xff) == uint(bytes[8])
        } else null
        if (bcc0 == false || bcc1 == false) {
            notes += "Контрольные BCC не совпадают: проверьте, что это полный дамп со страницы 0, а не фрагмент"
        }
        if (bytes.size / 4 !in setOf(16, 20, 36, 41, 42, 45, 48, 64, 128, 135, 231)) {
            notes += "Число страниц не соответствует типичным вариантам; проверьте формат экспорта"
        }
        notes += "По дампу нельзя автоматически установить, эмулирует ли его NFC-контроллер телефона"
        val summary = DumpSummary(format, bytes.size, bytes.size / 4, uid, bcc0, bcc1, notes)
        return ParsedDump(summary, bytes)
    }

    private fun parseText(text: String): ByteArray {
        val pages = mutableListOf<String>()
        for ((index, sourceLine) in text.lineSequence().withIndex()) {
            val line = sourceLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
            // Flipper .nfc files contain metadata before page records.
            // Chameleon/EML exports may contain only page records.
            if (isNfcMetadata(line)) continue
            val content = numberedPage.matchEntire(line)?.groupValues?.get(1) ?: line
            val collapsed = content.replace(" ", "").replace("\t", "")
            if (hexPage.matches(collapsed)) {
                pages += collapsed
            } else if (pages.isEmpty() && hexAll.matches(collapsed) && collapsed.length % 8 == 0) {
                // Single-line hex export with multiple consecutive 4-byte pages.
                pages += collapsed.chunked(8)
            } else {
                throw IllegalArgumentException("Строка ${index + 1}: ожидалось 8 HEX-символов (одна страница)")
            }
        }
        require(pages.isNotEmpty()) { "Не найдено страниц с HEX-данными" }
        return ByteArray(pages.size * 4) { i ->
            pages[i / 4].substring((i % 4) * 2, (i % 4) * 2 + 2).toInt(16).toByte()
        }
    }

    private fun isNfcMetadata(line: String): Boolean {
        val lower = line.lowercase()
        return lower.startsWith("filetype:") ||
            lower.startsWith("version:") ||
            lower.startsWith("device type:") ||
            lower.startsWith("uid:") ||
            lower.startsWith("atqa:") ||
            lower.startsWith("sak:") ||
            lower.startsWith("signature:") ||
            lower.startsWith("memory size:") ||
            lower.startsWith("data format version:") ||
            lower.startsWith("mifare version:") ||
            lower.startsWith("ntag/ultralight type:") ||
            lower.startsWith("pages total:") ||
            lower.startsWith("pages read:") ||
            lower.startsWith("counter ") ||
            lower.startsWith("tearing ") ||
            lower.startsWith("flipper") ||
            lower.startsWith("#")
    }

    private fun uint(byte: Byte): Int = byte.toInt() and 0xff
    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it.toInt() and 0xff) }
}
