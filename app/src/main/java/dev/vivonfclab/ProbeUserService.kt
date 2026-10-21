package dev.vivonfclab

import android.os.Process
import java.util.concurrent.TimeUnit

/**
 * Opt-in Shizuku UserService running with adb shell UID (not root on unrooted phones).
 * Fixed allowlisted read-only commands; never accepts arbitrary user commands or dumpsys output.
 * Does not touch card contents, NFC settings, secure elements, or vivo Wallet app-private data.
 */
class ProbeUserService : IProbeService.Stub() {
    override fun getSafeReport(): String = buildString {
        appendLine("Диагностика Shizuku UserService — только чтение")
        appendLine("UID сервиса: ${Process.myUid()} (2000 = ADB shell)")
        appendLine("Службы NFC / Wallet (имена, если разрешены):")
        appendLine(runFixedCommand("service list | grep -i -E '(nfc|wallet)' | head -n 20"))
        appendLine("Доступные NFC cmd-службы:")
        appendLine(runFixedCommand("cmd -l | grep -i nfc | head -n 12"))
        appendLine("Список доступных команд NFC (если служба cmd nfc разрешена):")
        appendLine(runFixedCommand("cmd nfc help 2>&1 | head -n 32"))
        appendLine("Системные пакеты NFC / vivo Wallet:")
        appendLine(runFixedCommand("pm list packages | grep -i -E '(nfc|wallet|vivo.pay|vivo.card)' | head -n 25"))
        appendLine("Это НЕ проверка эмуляции Type 2. Не выполнены операции изменения ОС или записи ключей.")
    }

    private fun runFixedCommand(command: String): String {
        // All invocations are from fixed source constants above, never UI input.
        return try {
            val process = ProcessBuilder("/system/bin/sh", "-c", command)
                .redirectErrorStream(true).start()
            val finished = process.waitFor(4, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                "  Превышено время ожидания\n"
            } else {
                val output = process.inputStream.bufferedReader().use { it.readText().take(4096) }
                if (output.isBlank()) "  Нет доступных совпадений\n" else output.trimEnd() + "\n"
            }
        } catch (e: Exception) {
            "  Команда недоступна: ${e.javaClass.simpleName}\n"
        }
    }
}
