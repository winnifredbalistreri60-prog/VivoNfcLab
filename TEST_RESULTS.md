# Vivo NFC Lab 0.3 — проверка исходников

Дата: 2026-10-21

- **PASS ранее / расширено в исходниках** — JVM-тесты `DumpParserTest` и `TagComparatorTest` (добавлены сценарии raw MF0UL21 BIN на 164 байта и Flipper `.nfc` на 41 страницу; реальные ключи не передавались).
- **PASS** — XML-манифест и XML-ресурсы разобраны. В APK-манифесте нет INTERNET permission.
- **PASS** — исходники Shizuku-диагностики содержат проверку разрешения, подключение UserService, ограниченный набор read-only команд.
- **PASS** — `ProbeUserService.kt` компилируется `kotlinc` с тестовыми заглушками AIDL/Android Process. Это не сборка APK.
- **НЕ ПРОВЕРЕНО** — полная Android/Gradle сборка APK, поскольку локальный Android SDK и Gradle не доступны.
- **НЕ ПРОВЕРЕНО** — соединение с Shizuku, право доступа и NFC-службы на vivo X300 CN / OriginOS 7, так как устройство не подключено.
- **РЕАЛИЗОВАНО в диагностическом режиме** — импорт raw Chameleon Ultra MF0UL21, page-oriented EML/HEX и Flipper `.nfc`; read-only FAST_READ окон страниц 0–40. Эмуляция MIFARE Ultralight на встроенном NFC по-прежнему не реализована: Android HCE ISO-DEP не предоставляет эту функцию.

- **Текущая среда** — `kotlinc`, Gradle и Android SDK отсутствуют, поэтому расширенные JVM-тесты и APK-сборка здесь не запускались.

Требуется подтверждение работы диагностического APK, собранного по workflow `.github/workflows/build-apk.yml`.
