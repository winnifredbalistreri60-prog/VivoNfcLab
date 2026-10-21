package dev.vivonfclab

import android.app.Activity
import android.app.role.RoleManager
import android.content.ComponentName
import android.content.ServiceConnection
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.cardemulation.CardEmulation
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareUltralight
import android.nfc.tech.NfcA
import android.provider.Settings
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import rikka.shizuku.Shizuku

/**
 * Read-only, no-root diagnostics for Vivo NFC / Wallet and MIFARE Ultralight dumps.
 * Shizuku is used only for an opt-in, read-only shell diagnostics service.
 * Does not attempt hidden API calls, impersonate Wallet, or claim Type 2 tag emulation.
 */
class MainActivity : Activity() {
    companion object {
        private const val REQUEST_DUMP = 1001
        private const val REQUEST_SHIZUKU = 1002
        private const val WALLET_PACKAGE = "com.vivo.wallet"
        private const val MAX_DUMP_BYTES = 65536
        private const val TARGET_PAGE_COUNT = DumpParser.MF0UL21_PAGE_COUNT
    }

    private lateinit var deviceView: TextView
    private lateinit var dumpView: TextView
    private lateinit var readerView: TextView
    private lateinit var readerButton: Button
    private lateinit var shizukuView: TextView
    private var lastShizukuReport: String = "Shizuku не проверялся."
    private var probeBound = false
    private var probeBusy = false

    private val probeArgs by lazy {
        Shizuku.UserServiceArgs(ComponentName(packageName, ProbeUserService::class.java.name))
            .daemon(false)
            .processNameSuffix("nfclab_probe")
            .tag("nfclab_readonly_probe")
            .version(1)
    }
    private val binderReceived = Shizuku.OnBinderReceivedListener {
        refreshShizukuStatus()
    }
    private val binderDead = Shizuku.OnBinderDeadListener {
        probeBound = false
        probeBusy = false
        lastShizukuReport = "Shizuku остановлен. Запусти его снова и обнови статус."
        refreshShizukuStatus()
    }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { code, result ->
        if (code == REQUEST_SHIZUKU) {
            if (result == PackageManager.PERMISSION_GRANTED) {
                lastShizukuReport = "Доступ Shizuku предоставлен. Нажми 'Системная NFC-диагностика'."
            } else {
                lastShizukuReport = "Разрешение Shizuku не предоставлено."
            }
            refreshShizukuStatus()
        }
    }
    private val probeConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            probeBound = true
            Thread {
                val result = try {
                    IProbeService.Stub.asInterface(binder)?.getSafeReport()
                        ?: "Сервис вернул пустой результат."
                } catch (e: Exception) {
                    "Ошибка диагностического сервиса: ${e.javaClass.simpleName}"
                }
                runOnUiThread {
                    lastShizukuReport = result
                    probeBusy = false
                    refreshShizukuStatus()
                    // Unbind to avoid keeping the shell process alive.
                    stopProbeService()
                }
            }.start()
        }
        override fun onServiceDisconnected(name: ComponentName) {
            probeBound = false
            probeBusy = false
        }
    }
    private var readerActive = false
    private var loadedDump: ParsedDump? = null
    private var dumpSummary: DumpSummary? = null
    private var lastTagReport = "Метка ещё не проверялась."
    private var lastDeviceReport = "Диагностика не запускалась."

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(24))
        }
        val scroll = ScrollView(this).apply { addView(container) }
        setContentView(scroll)

        addTitle(container, "Vivo NFC Lab", 25f)
        addDescription(container, "OriginOS 7 · vivo X300 CN · диагностика без root · v0.3")
        addDescription(container, "Цель: MIFARE Ultralight EV1 MF0UL21. Только диагностика; эмуляция Ultralight без системного доступа не заявляется.")

        addTitle(container, "1. Система и NFC", 19f)
        addButton(container, "Обновить диагностику") { refreshDeviceReport() }
        deviceView = addReport(container)

        addTitle(container, "2. Shizuku (необязательно)", 19f)
        addButton(container, "Проверить Shizuku") { refreshShizukuStatus() }
        addButton(container, "Запросить разрешение Shizuku") { requestShizukuAccess() }
        addButton(container, "Системная NFC-диагностика (только чтение)") { runShizukuProbe() }
        shizukuView = addReport(container)
        addDescription(container, "Используется отдельный read-only процесс Shizuku от имени ADB shell. Команды ограничены поиском NFC-служб и пакетов vivo Wallet. Без записи ключей, без изменения настроек.")

        addTitle(container, "3. Дамп Chameleon Ultra", 19f)
        addButton(container, "Открыть дамп .bin / .eml / .hex") { pickDump() }
        dumpView = addReport(container)
        dumpView.text = "Файл не выбран. Дамп остаётся в оперативной памяти и не сохраняется приложением."

        addTitle(container, "4. Сравнение с NFC-меткой", 19f)
        readerButton = addButton(container, "Сканировать NFC-метку") { toggleReader() }
        readerView = addReport(container)
        readerView.text = lastTagReport

        addTitle(container, "5. vivo Wallet", 19f)
        addButton(container, "Открыть установленный vivo Wallet") { launchWallet() }
        addButton(container, "Настройки NFC") {
            try { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) }
            catch (e: Exception) { toast("Настройки NFC не открылись: ${e.javaClass.simpleName}") }
        }
        addButton(container, "Поделиться безопасным отчётом") { shareSafeReport() }
        addButton(container, "Скопировать безопасный отчёт") { copySafeReport() }
        addDescription(container, "Дамп хранится только в памяти до закрытия приложения; в отчёте нет полного UID, страниц памяти и секретов. Нет разрешения INTERNET.")
        addDescription(container, "Публичный HCE Android работает через ISO-DEP/APDU, а не произвольные команды Ultralight. Наличие HCE не доказывает возможность воспроизведения ключа VIZIT.")

        refreshDeviceReport()
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)
        refreshShizukuStatus()
    }

    private fun shizukuReady(): Boolean = try {
        Shizuku.pingBinder() && !Shizuku.isPreV11()
    } catch (_: Exception) { false }

    private fun refreshShizukuStatus() {
        if (!::shizukuView.isInitialized) return
        val ready = shizukuReady()
        val status = if (!ready) "не запущен или API слишком старый" else "работает"
        val permission = if (!ready) "неизвестно" else try {
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) "разрешено" else "не разрешено"
        } catch (_: Exception) { "недоступно" }
        val uid = if (ready) try { Shizuku.getUid().toString() } catch (_: Exception) { "неизвестен" } else "—"
        val version = if (ready) try { Shizuku.getVersion().toString() } catch (_: Exception) { "неизвестна" } else "—"
        shizukuView.text = "Shizuku: $status\nAPI сервера: $version\nUID процесса Shizuku: $uid (2000 = shell, 0 = root)\nДоступ: $permission\n\n$lastShizukuReport"
    }

    private fun requestShizukuAccess() {
        if (!shizukuReady()) {
            lastShizukuReport = "Сначала запусти Shizuku через беспроводную отладку."
            refreshShizukuStatus()
            return
        }
        try {
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                lastShizukuReport = "Доступ уже предоставлен."
                refreshShizukuStatus()
            } else if (Shizuku.shouldShowRequestPermissionRationale()) {
                lastShizukuReport = "Доступ ранее отклонён; разреши Vivo NFC Lab в настройках Shizuku."
                refreshShizukuStatus()
            } else {
                Shizuku.requestPermission(REQUEST_SHIZUKU)
            }
        } catch (e: Exception) {
            lastShizukuReport = "Не удалось запросить доступ: ${e.javaClass.simpleName}"
            refreshShizukuStatus()
        }
    }

    private fun runShizukuProbe() {
        if (!shizukuReady()) {
            lastShizukuReport = "Shizuku не запущен."
            refreshShizukuStatus()
            return
        }
        if ((try { Shizuku.checkSelfPermission() } catch (_: Exception) { -1 }) != PackageManager.PERMISSION_GRANTED) {
            requestShizukuAccess()
            return
        }
        if (probeBusy) {
            toast("Диагностика уже выполняется")
            return
        }
        probeBusy = true
        lastShizukuReport = "Подключение диагностического сервиса…"
        refreshShizukuStatus()
        try {
            Shizuku.bindUserService(probeArgs, probeConnection)
            probeBound = true
        } catch (e: Exception) {
            probeBusy = false
            lastShizukuReport = "Не удалось подключить Shizuku UserService: ${e.javaClass.simpleName}"
            refreshShizukuStatus()
        }
    }

    private fun stopProbeService() {
        if (!probeBound) return
        probeBound = false
        if (shizukuReady()) {
            try { Shizuku.unbindUserService(probeArgs, probeConnection, false) } catch (_: Exception) { }
        }
    }

    override fun onPause() {
        stopReader()
        super.onPause()
    }

    private fun refreshDeviceReport() {
        val pm = packageManager
        val features = listOf(
            "NFC (чтение)" to PackageManager.FEATURE_NFC,
            "HCE ISO-DEP" to PackageManager.FEATURE_NFC_HOST_CARD_EMULATION,
            "HCE-F (FeliCa)" to PackageManager.FEATURE_NFC_HOST_CARD_EMULATION_NFCF,
            "off-host eSE" to PackageManager.FEATURE_NFC_OFF_HOST_CARD_EMULATION_ESE,
            "off-host UICC" to PackageManager.FEATURE_NFC_OFF_HOST_CARD_EMULATION_UICC
        )
        lastDeviceReport = buildString {
            appendLine("Устройство: ${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine("Android ${Build.VERSION.RELEASE}, API ${Build.VERSION.SDK_INT}")
            appendLine("Сборка ОС: ${Build.DISPLAY}")
            appendLine("Версия приложения: 0.3.0")
            if (Build.VERSION.SDK_INT >= 35) {
                try {
                    val manager = getSystemService(RoleManager::class.java)
                    appendLine("Системная роль Wallet: ${yesNo(manager?.isRoleAvailable(RoleManager.ROLE_WALLET) == true)}")
                } catch (e: Exception) {
                    appendLine("Системная роль Wallet: недоступна (${e.javaClass.simpleName})")
                }
            }
            features.forEach { (title, feature) ->
                appendLine("$title: ${yesNo(pm.hasSystemFeature(feature))}")
            }
            try {
                val adapter = NfcAdapter.getDefaultAdapter(this@MainActivity)
                if (adapter == null) {
                    appendLine("NFC-адаптер: не обнаружен")
                } else {
                    appendLine("NFC включён: ${yesNo(adapter.isEnabled)}")
                    if (Build.VERSION.SDK_INT >= 29) {
                        appendLine("Secure NFC поддерживается: ${yesNo(adapter.isSecureNfcSupported)}")
                    }
                    if (pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
                        try {
                            val ce = CardEmulation.getInstance(adapter)
                            appendLine("AID prefix routing: ${yesNo(ce.supportsAidPrefixRegistration())}")
                        } catch (e: Exception) {
                            appendLine("Диагностика маршрутизации AID: ${e.javaClass.simpleName}")
                        }
                    }
                }
            } catch (e: Exception) {
                appendLine("Ошибка NFC: ${e.javaClass.simpleName}")
            }
            appendLine()
            appendLine(walletReport())
            appendLine()
            append("Доступ к низкоуровневой Type 2 эмуляции: публичного Android API нет.")
        }
        deviceView.text = lastDeviceReport
    }

    private fun walletReport(): String = buildString {
        appendLine("vivo Wallet ($WALLET_PACKAGE):")
        try {
            @Suppress("DEPRECATION")
            val flags = PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES
            @Suppress("DEPRECATION")
            val info = packageManager.getPackageInfo(WALLET_PACKAGE, flags)
            appendLine("  Установлен: да")
            appendLine("  Версия: ${info.versionName ?: "неизвестна"}")
            val services = info.services.orEmpty()
            val exported = services.filter { it.exported }
            val withoutPermissions = exported.filter { it.permission.isNullOrBlank() }
            appendLine("  Экспортированных служб: ${exported.size}")
            appendLine("  Экспортированных Activity: ${info.activities.orEmpty().count { it.exported }}")
            appendLine("  Из них без объявленного permission: ${withoutPermissions.size}")
            withoutPermissions.take(8).forEach { service ->
                appendLine("    ${service.name}")
            }
            if (withoutPermissions.size > 8) appendLine("    ... ещё ${withoutPermissions.size - 8}")
            appendLine("  ВНИМАНИЕ: exported ≠ документированный API импорта дампа.")
        } catch (_: PackageManager.NameNotFoundException) {
            appendLine("  Не обнаружен по этому имени пакета (имя может отличаться).")
        } catch (e: Exception) {
            appendLine("  Информация недоступна: ${e.javaClass.simpleName}")
        }
    }

    private fun launchWallet() {
        try {
            val intent = packageManager.getLaunchIntentForPackage(WALLET_PACKAGE)
            if (intent == null) {
                toast("Не удалось найти запускаемую Activity vivo Wallet")
            } else {
                startActivity(intent)
            }
        } catch (e: Exception) {
            toast("Ошибка запуска Wallet: ${e.javaClass.simpleName}")
        }
    }

    private fun pickDump() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQUEST_DUMP)
    }

    @Deprecated("Uses platform Activity result API to keep this project dependency-free")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_DUMP || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val name = displayName(uri)
            val bytes = readLimited(uri)
            val parsed = DumpParser.parseDetailed(bytes, name)
            require(parsed.pageCount == TARGET_PAGE_COUNT) {
                "Для цели MIFARE Ultralight EV1 MF0UL21 нужен дамп ровно $TARGET_PAGE_COUNT страниц (164 байта); получено ${parsed.pageCount}"
            }
            loadedDump?.clear()
            loadedDump = parsed
            dumpSummary = parsed.summary
            lastTagReport = "После загрузки дампа просканируй NFC-метку для сравнения."
            readerView.text = lastTagReport
            dumpView.text = "Файл: ${name.take(100)}\n${parsed.summary.safeReport()}"
        } catch (e: Exception) {
            lastTagReport = "Новый файл не загружен; ранее выбранный дамп сохранён."
            readerView.text = lastTagReport
            dumpView.text = "Ошибка импорта: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    private fun displayName(uri: Uri): String {
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val i = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (i >= 0) return cursor.getString(i)
                }
            }
        } catch (_: Exception) { /* Fall back to URI segment */ }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "dump.bin"
    }

    private fun readLimited(uri: Uri): ByteArray {
        contentResolver.openInputStream(uri)?.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                require(total <= MAX_DUMP_BYTES) { "Дамп больше $MAX_DUMP_BYTES байт" }
                output.write(buffer, 0, read)
            }
            return output.toByteArray()
        }
        throw IllegalArgumentException("Нет доступа к файлу")
    }

    private fun toggleReader() {
        if (readerActive) stopReader() else startReader()
    }

    private fun startReader() {
        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter == null || !adapter.isEnabled) {
            toast("Включи NFC в настройках")
            return
        }
        try {
            adapter.enableReaderMode(
                this,
                { tag: Tag -> onTagSeen(tag) },
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null
            )
            readerActive = true
            readerButton.text = "Остановить сканирование"
            readerView.text = "Приложи MIFARE Ultralight EV1 MF0UL21 или Chameleon в режиме эмуляции.\nТолько чтение; никаких команд записи."
        } catch (e: Exception) {
            readerView.text = "Не удалось запустить чтение: ${e.javaClass.simpleName}"
        }
    }

    /** Runs on the NFC reader callback thread, not the Android UI thread. */
    private fun onTagSeen(tag: Tag) {
        val technologies = tag.techList.joinToString(", ") { it.substringAfterLast('.') }
        val nfca = NfcA.get(tag)
        val ultralight = MifareUltralight.get(tag)
        val dump = loadedDump
        val windows = mutableListOf<ReadWindow>()
        var attemptedRead = false
        var readError: String? = null
        if (nfca != null && IsoDep.get(tag) == null && (nfca.sak.toInt() and 0xff) == 0) {
            try {
                // MIFARE Ultralight EV1 FAST_READ (0x3A), pages 0..40.
                // This is read-only and covers the complete 41-page MF0UL21 profile.
                nfca.connect()
                nfca.timeout = 1500
                for ((startPage, endPage) in listOf(0 to 15, 16 to 31, 32 to 40)) {
                    attemptedRead = true
                    val response = try {
                        nfca.transceive(byteArrayOf(0x3A.toByte(), startPage.toByte(), endPage.toByte()))
                    } catch (e: Exception) {
                        if (readError == null) readError = "FAST_READ $startPage-$endPage: ${e.javaClass.simpleName}"
                        null
                    }
                    if (response != null) {
                        val expected = (endPage - startPage + 1) * 4
                        if (response.size != expected) {
                            if (readError == null) {
                                readError = "Неожиданная длина ответа FAST_READ $startPage-$endPage: ${response.size} байт, ожидалось $expected"
                            }
                        } else {
                            windows += ReadWindow(startPage, response)
                        }
                    }
                }
            } catch (e: Exception) {
                readError = e.javaClass.simpleName
            } finally {
                try { nfca.close() } catch (_: Exception) { }
            }
        } else {
            readError = "Прямое чтение Type 2 не подходит для этой NFC-технологии"
        }

        val comparison = TagComparator.compare(dump, tag.id, windows, attemptedRead, readError)
        val report = buildString {
            appendLine("NFC-метка обнаружена")
            appendLine("Длина UID: ${tag.id.size} байт (сам UID скрыт)")
            appendLine("Технологии: $technologies")
            appendLine("MifareUltralight API: ${yesNo(ultralight != null)}")
            if (ultralight != null) {
                val type = when (ultralight.type) {
                    MifareUltralight.TYPE_ULTRALIGHT -> "Ultralight"
                    MifareUltralight.TYPE_ULTRALIGHT_C -> "Ultralight C"
                    else -> "не определён"
                }
                appendLine("Тип по Android: $type (предварительно)")
            }
            appendLine("IsoDep API: ${yesNo(IsoDep.get(tag) != null)}")
            if (nfca != null) {
                appendLine("ATQA: ${nfca.atqa.toHex()}")
                appendLine("SAK: %02X".format(nfca.sak.toInt() and 0xff))
            }
            appendLine(comparison.safeReport())
        }
        runOnUiThread {
            lastTagReport = report
            readerView.text = report
            stopReader()
        }
    }

    private fun stopReader() {
        if (!readerActive) return
        try { NfcAdapter.getDefaultAdapter(this)?.disableReaderMode(this) } catch (_: Exception) { }
        readerActive = false
        readerButton.text = "Сканировать NFC-метку"
    }

    private fun safeReportText(): String = buildString {
            appendLine("Vivo NFC Lab v0.3 — безопасный отчёт")
            appendLine(lastDeviceReport)
            appendLine()
            appendLine("Shizuku:")
            appendLine(lastShizukuReport)
            appendLine()
            appendLine("Дамп:")
            appendLine(dumpSummary?.safeReport() ?: "Не загружен")
            appendLine()
            appendLine("Последняя считанная NFC-метка:")
            appendLine(lastTagReport)
        }

    private fun shareSafeReport() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, safeReportText())
        }
        startActivity(Intent.createChooser(send, "Поделиться диагностикой"))
    }

    private fun copySafeReport() {
        val text = safeReportText()
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Vivo NFC Lab Report", text))
        toast("Отчёт скопирован без полного UID и дампа")
    }

    private fun addTitle(parent: LinearLayout, value: String, sizeSp: Float) {
        val view = TextView(this).apply {
            text = value
            textSize = sizeSp
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(12), 0, dp(8))
        }
        parent.addView(view)
    }

    private fun addDescription(parent: LinearLayout, value: String) {
        val view = TextView(this).apply {
            text = value
            textSize = 14f
            setPadding(0, dp(4), 0, dp(12))
        }
        parent.addView(view)
    }

    private fun addButton(parent: LinearLayout, title: String, action: () -> Unit): Button {
        val view = Button(this).apply {
            text = title
            isAllCaps = false
            setOnClickListener { action() }
        }
        parent.addView(view, LinearLayout.LayoutParams(-1, -2))
        return view
    }

    private fun addReport(parent: LinearLayout): TextView {
        val view = TextView(this).apply {
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(dp(5), dp(6), dp(5), dp(16))
        }
        parent.addView(view)
        return view
    }


    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it.toInt() and 0xff) }
    override fun onDestroy() {
        stopProbeService()
        Shizuku.removeBinderReceivedListener(binderReceived)
        Shizuku.removeBinderDeadListener(binderDead)
        Shizuku.removeRequestPermissionResultListener(permissionResult)
        loadedDump?.clear()
        loadedDump = null
        super.onDestroy()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
    private fun yesNo(b: Boolean): String = if (b) "да" else "нет"
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
