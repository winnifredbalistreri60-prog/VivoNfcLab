package dev.vivonfclab

object TagComparatorTest {
    @JvmStatic
    fun main(args: Array<String>) {
        val dump = ByteArray(64) { it.toByte() }
        val uid = byteArrayOf(dump[0],dump[1],dump[2],dump[4],dump[5],dump[6],dump[7])
        val parsed = DumpParser.parseDetailed(dump, "key.bin")
        val matching = TagComparator.compare(parsed, uid,
            listOf(ReadWindow(0, dump.copyOfRange(0, 16)), ReadWindow(4, dump.copyOfRange(16, 32))), true)
        check(matching.uidMatches == true)
        check(matching.pagesCompared == 8 && matching.pagesMatched == 8)
        check(!matching.safeReport().contains(uid.joinToString("") { "%02X".format(it.toInt() and 255) }))

        val altered = dump.copyOfRange(0, 16).also { it[7] = 0 }
        val different = TagComparator.compare(parsed, ByteArray(7), listOf(ReadWindow(0, altered)), true)
        check(different.uidMatches == false && different.pagesCompared == 4 && different.pagesMatched == 3)
        val noDump = TagComparator.compare(null, uid, emptyList(), false)
        check(noDump.uidMatches == null && noDump.pagesCompared == 0)
        val malformed = TagComparator.compare(parsed, uid, listOf(ReadWindow(0, ByteArray(3)), ReadWindow(150, ByteArray(16))), true)
        check(malformed.pagesCompared == 0)
        val duplicate = TagComparator.compare(parsed, uid, listOf(ReadWindow(0, dump.copyOfRange(0, 16)), ReadWindow(0, dump.copyOfRange(0, 16))), true)
        check(duplicate.pagesCompared == 4)
        parsed.clear()
        check(!parsed.matchesPage(1, dump.copyOfRange(4, 8)))
        println("PASS: TagComparator — UID, matching pages, changed page, deduplication, redaction, memory clearing")
    }
}
