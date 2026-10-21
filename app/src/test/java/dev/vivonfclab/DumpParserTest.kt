package dev.vivonfclab

// Pure JVM smoke tests: no Android SDK needed. Run with scripts/test-parser.sh.
object DumpParserTest {
    @JvmStatic
    fun main(args: Array<String>) {
        val valid = ByteArray(64)
        val uid = intArrayOf(0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
        valid[0] = uid[0].toByte()
        valid[1] = uid[1].toByte()
        valid[2] = uid[2].toByte()
        valid[3] = (0x88 xor uid[0] xor uid[1] xor uid[2]).toByte()
        valid[4] = uid[3].toByte()
        valid[5] = uid[4].toByte()
        valid[6] = uid[5].toByte()
        valid[7] = uid[6].toByte()
        valid[8] = (uid[3] xor uid[4] xor uid[5] xor uid[6]).toByte()

        val bin = DumpParser.parse(valid, "key.bin")
        check(bin.pageCount == 16)
        check(bin.bcc0Correct == true && bin.bcc1Correct == true)
        check(bin.uidHex == "04112233445566")
        check(!bin.safeReport().contains(bin.uidHex!!)) { "Full UID leaked in report" }
        check(bin.format == "BIN")

        val emlText = valid.toList().chunked(4).mapIndexed { i, page ->
            "$i: " + page.joinToString(" ") { "%02X".format(it.toInt() and 0xff) }
        }.joinToString("\n")
        val eml = DumpParser.parse(emlText.toByteArray(), "key.eml")
        check(eml.uidHex == bin.uidHex)
        check(eml.bcc0Correct == true)
        check(eml.format == "HEX/EML")

        val mf0ul21 = ByteArray(DumpParser.MF0UL21_BYTE_COUNT)
        valid.copyInto(mf0ul21, endIndex = valid.size)
        val chameleon = DumpParser.parse(mf0ul21, "mf0ul21.bin")
        check(chameleon.pageCount == 41)
        check(chameleon.format == "CHAMELEON MF0UL21 BIN")

        val flipper = buildString {
            appendLine("Filetype: Flipper NFC device")
            appendLine("Version: 4")
            appendLine("Device type: NTAG")
            appendLine("Pages total: 41")
            appendLine("Pages read: 41")
            mf0ul21.asList().chunked(4).forEachIndexed { i, page ->
                appendLine("Page $i: " + page.joinToString(" ") { "%02X".format(it.toInt() and 0xff) })
            }
        }
        val flipperParsed = DumpParser.parse(flipper.toByteArray(), "mf0ul21.nfc")
        check(flipperParsed.pageCount == 41)
        check(flipperParsed.format == "FLIPPER NFC / MFU")

        val broken = valid.copyOf().also { it[3] = 0 }
        check(DumpParser.parse(broken, "bad.bin").bcc0Correct == false)
        expectFailure("non-multiple-of-4") { DumpParser.parse(ByteArray(17), "bad.bin") }
        expectFailure("unsupported text header") { DumpParser.parse("Flipper NFC device\n00: 041122BF".toByteArray(), "bad.eml") }
        expectFailure("too large") { DumpParser.parse(ByteArray(65537), "bad.bin") }
        expectFailure("empty") { DumpParser.parse(byteArrayOf(), "empty.bin") }
        println("PASS: 10 assertions/scenarios — BIN/EML, UID, BCC, redaction, invalid input")
    }

    private fun expectFailure(name: String, action: () -> Unit) {
        val result = runCatching(action)
        check(result.isFailure) { "Expected failure: $name" }
    }
}
