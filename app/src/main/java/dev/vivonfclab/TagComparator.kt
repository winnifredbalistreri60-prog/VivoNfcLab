package dev.vivonfclab

/** A read-only comparison between a locally imported dump and a tag seen by Android. */
data class ReadWindow(val startPage: Int, val bytes: ByteArray)

data class TagAssessment(
    val uidMatches: Boolean?,
    val pagesCompared: Int,
    val pagesMatched: Int,
    val pagesRead: Int,
    val totalDumpPages: Int?,
    val attemptedRead: Boolean,
    val readError: String?
) {
    /** Safe to share: this excludes full UID, raw pages and credentials. */
    fun safeReport(): String = buildString {
        appendLine("UID с дампом: ${when (uidMatches) { true -> "совпадает"; false -> "не совпадает"; null -> "дамп не загружен" }}")
        appendLine("Прочитано страниц: $pagesRead (профиль MF0UL21: не более 41)")
        appendLine("Сравнено с дампом: $pagesCompared, совпадает: $pagesMatched")
        appendLine("Чтение Type 2: ${if (attemptedRead) "проводилось" else "не проводилось"}")
        if (totalDumpPages != null && pagesCompared < totalDumpPages) {
            appendLine("Внимание: не все страницы дампа проверены (${totalDumpPages - pagesCompared} не проверено)")
        }
        if (readError != null) appendLine("Чтение остановлено: $readError")
        append("Совпадение страниц НЕ доказывает возможность эмуляции телефоном.")
    }
}

object TagComparator {
    fun compare(
        dump: ParsedDump?,
        tagUid: ByteArray,
        windows: List<ReadWindow>,
        attemptedRead: Boolean,
        readError: String? = null
    ): TagAssessment {
        val uidMatches = dump?.uidBytes()?.contentEquals(tagUid)
        var compared = 0
        var matched = 0
        if (dump != null) {
            // Every returned window contains 4-byte pages; ignore malformed responses.
            val seen = mutableSetOf<Int>()
            for (window in windows) {
                if (window.startPage < 0 || window.bytes.size != 16) continue
                for (i in 0 until (window.bytes.size / 4)) {
                    val page = window.startPage + i
                    if (page >= dump.pageCount || !seen.add(page)) continue
                    val chunk = window.bytes.copyOfRange(i * 4, (i + 1) * 4)
                    compared++
                    if (dump.matchesPage(page, chunk)) matched++
                }
            }
        }
        val readPages = windows
            .filter { it.startPage >= 0 && it.bytes.isNotEmpty() && it.bytes.size % 4 == 0 }
            .flatMap { window ->
                (window.startPage until window.startPage + window.bytes.size / 4).toList()
            }
            .filter { it >= 0 && (dump == null || it < dump.pageCount) }
            .distinct()
            .count()
        return TagAssessment(uidMatches, compared, matched, readPages, dump?.pageCount, attemptedRead, readError)
    }
}
