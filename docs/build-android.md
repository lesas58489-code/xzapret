# Build Android APK

Pipeline:

```
Linux dev box ──gomobile bind──→ xzapcore.aar
                                        │ scp
                                        ▼
                            Windows dev box (Android Studio)
                            ──Build APK──→ app-debug.apk
                                                │ scp
                                                ▼
                                        Server /var/www/html/xzap.apk
                                                │ http
                                                ▼
                                        Phone install
```

Linux нужен для **gomobile bind** (компилит Go в native libraries для Android, требует NDK). Windows нужен для **Android Studio** (gradle build, signing, packaging APK).

В принципе всё это делается и на одной Linux-машине (Android Studio есть для Linux). Но у нас сложилось что dev — Linux + Windows.

## Prerequisites

### Linux dev box (Tokyo)

```bash
# Go 1.22+
go version  # должно показать 1.22 или новее

# Android NDK
ls /opt/android-sdk/ndk/  # должен содержать NDK (например 26.1.10909125)
export ANDROID_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=$(ls -d /opt/android-sdk/ndk/*/ | head -1 | sed 's:/$::')

# gomobile / gobind
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
export PATH="$PATH:$(go env GOPATH)/bin"

gomobile init  # один раз, инициализирует gomobile (несколько минут)
```

### Windows dev box

- **Android Studio** последний (Hedgehog или новее)
- **Android SDK** через Android Studio (Build Tools 34+, Platform 34)
- **OpenSSH** Windows native (`C:\Windows\System32\OpenSSH\ssh.exe`) — для scp
- Проект склонирован: `C:\Users\sokolov\xzapret\xzapret`

## Шаг 1 — Build AAR на Linux

```bash
cd /root/xzapret
git pull  # если нужно подтянуть последние правки

# Собрать
export ANDROID_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
export PATH="$PATH:/root/go/bin"

gomobile bind \
  -target=android \
  -androidapi 24 \
  -ldflags="-s -w" \
  -o /root/xzapret/clients/android/app/libs/xzapcore.aar \
  ./mobile

ls -lh /root/xzapret/clients/android/app/libs/xzapcore.aar
```

Что флаги делают:
- `-target=android` — компилировать под Android
- `-androidapi 24` — минимум Android 7.0 (Nougat). Покрывает практически все юзаемые телефоны
- `-ldflags="-s -w"` — strip symbols + debug info → размер падает в 2 раза (с 37MB → 20MB)
- `-o ...` — куда положить
- `./mobile` — Go package для bind (содержит exported functions для Java)

Ожидаемое время: 1-5 минут (зависит от CPU).

Размер AAR ~20MB. Включает:
- 4 ABI: arm64-v8a, armeabi-v7a, x86, x86_64
- Go runtime + stdlib
- uTLS, tun2socks, mux, наша логика
- ~1MB overhead на каждую ABI

### Опционально: только arm64-v8a (-50% APK размера)

Все современные телефоны (Xiaomi, Samsung, Pixel с 2017+) — arm64. Можно сэкономить ~10MB:

```bash
gomobile bind \
  -target=android/arm64 \
  -androidapi 24 \
  -ldflags="-s -w" \
  -o ...
```

APK станет ~30MB вместо 55MB. **Минус**: не запустится на старых 32-битных телефонах и Android emulator x86.

## Шаг 2 — Передать AAR на Windows dev box

```bash
# С Linux:
scp /root/xzapret/clients/android/app/libs/xzapcore.aar \
  windows-user@WINDOWS_IP:C:/path/to/project/clients/android/app/libs/xzapcore.aar
```

Или (более типично) — закинуть на сервер, скачать с Windows:

```bash
# Linux → Server
scp -i ~/.ssh/sweden /root/xzapret/clients/android/app/libs/xzapcore.aar root@202.155.11.110:/tmp/xzapcore.aar
```

```powershell
# Windows ← Server
scp root@202.155.11.110:/tmp/xzapcore.aar C:\Users\sokolov\xzapret\xzapret\clients\android\app\libs\xzapcore.aar

# Verify SHA matches
Get-FileHash C:\Users\sokolov\xzapret\xzapret\clients\android\app\libs\xzapcore.aar
```

Сверь SHA с тем что показал Linux после build (`sha256sum xzapcore.aar`).

## Шаг 3 — Build APK в Android Studio (Windows)

1. Open Android Studio
2. **File → Open** → `C:\Users\sokolov\xzapret\xzapret\clients\android`
3. Подождать пока gradle загрузит зависимости (первый раз 5-10 мин)
4. Если хотите чистую сборку: **Build → Clean Project**
5. **Build → Rebuild Project**
6. **Build → Build Bundle(s)/APK(s) → Build APK(s)**
7. После завершения внизу появится «APK(s) generated successfully» с ссылкой
8. APK путь: `app\build\outputs\apk\debug\app-debug.apk`
9. Размер ~55MB

Если **в процессе ругается на `xzapcore.aar`** — значит файл не подхватился gradle'ом. Проверь:
- Файл лежит ровно в `app\libs\xzapcore.aar`
- В `app\build.gradle.kts` есть строка `implementation(files("libs/xzapcore.aar"))`

### CLI build (без Android Studio UI)

Если есть `gradlew` в проекте, можно из терминала:

```powershell
cd C:\Users\sokolov\xzapret\xzapret\clients\android
.\gradlew clean assembleDebug
# APK тут же: app\build\outputs\apk\debug\app-debug.apk
```

Быстрее, если знаешь что делаешь.

## Шаг 4 — Загрузить APK на сервер

```powershell
scp C:\Users\sokolov\xzapret\xzapret\clients\android\app\build\outputs\apk\debug\app-debug.apk \
    root@202.155.11.110:/tmp/xzap.apk

# Скопировать в nginx-served location
ssh root@202.155.11.110 "cp /tmp/xzap.apk /var/www/html/xzap.apk"
```

После этого APK доступен по `http://202.155.11.110/xzap.apk` (или с любого relay сервера, если файл везде).

Опционально на ВСЕ серверы:
```powershell
foreach ($srv in @("202.155.11.110", "151.244.111.186")) {
  scp C:\Users\sokolov\xzapret\xzapret\clients\android\app\build\outputs\apk\debug\app-debug.apk root@${srv}:/tmp/xzap.apk
  ssh root@$srv "cp /tmp/xzap.apk /var/www/html/xzap.apk"
}
```

## Шаг 5 — Установить на телефон

На телефоне в Chrome:
```
http://151.244.111.186/xzap.apk
```
(или любой другой relay IP — APK везде свежий после Шага 4)

Скачается, нажми установить. Если впервые — Android попросит **«Allow from this source»** для Chrome → разрешить.

После установки:
- Open XZAP
- Заполни Server / Port / Key
- Connect → Allow VPN dialog → done

## Прокачка SHA-проверки

Чтобы убедиться что APK на телефоне = тот что собрал:

```powershell
# SHA на твоей Windows
Get-FileHash app\build\outputs\apk\debug\app-debug.apk

# SHA на сервере
ssh root@202.155.11.110 "sha256sum /var/www/html/xzap.apk"
```

Если совпадает — гарантия что юзер ставит то что собрал ты.

## Версионирование

Пока проект не использует semver / build numbers. Идентификация:
- `git log -1 --oneline` — последний commit на Linux перед build
- SHA256 AAR — гарантия что Linux собрал точно нужный код
- SHA256 APK — гарантия что Windows собрал из этого AAR

Когда понадобится — добавить в `build.gradle.kts`:
```kotlin
android {
    defaultConfig {
        versionCode = 42  // bump при каждом release
        versionName = "1.5.3"
    }
}
```

И в код:
```kotlin
val versionInfo = "$BuildConfig.VERSION_NAME ($BuildConfig.VERSION_CODE)"
```

Пока что используется last-commit-SHA как ID.

## Cycle time

| Шаг | Время |
|---|---|
| `git pull` на Linux | <5s |
| `gomobile bind` (full rebuild) | 1-5 min (зависит от CPU) |
| `scp` AAR Linux → Windows | <30s |
| Android Studio Rebuild + Build APK | 1-3 min |
| `scp` APK Windows → Server | 5-30s |
| Phone install | 30s (плюс reboot если нужен) |
| **Total** | **~5-10 min** |

Для dev iteration быстро. Reboot phone не нужен между билдами обычно — Force Stop + Open хватает (новый APK перезагрузит code).

## Troubleshooting build

### `gomobile bind` fails: "no Android NDK"
- `ANDROID_NDK_HOME` не выставлен или указывает на несуществующую папку
- `ls /opt/android-sdk/ndk/` — должно показать версию NDK
- export правильный путь

### Android Studio: "Cannot find xzapcore.aar"
- Файл не в `clients/android/app/libs/xzapcore.aar`
- Перетащи файл туда вручную через Explorer

### APK устанавливается но не запускается, мгновенный crash
- AAR содержит .so для wrong ABI (например только arm64, а телефон 32-bit)
- Пересобери AAR без `-target=android/arm64` (полный default = все ABI)
- Или telephoned ABI: `adb shell getprop ro.product.cpu.abi`

### `gomobile bind` warnings про deprecated API
- Игнорировать обычно. Если много error'ов — обновить gomobile: `go install golang.org/x/mobile/cmd/gomobile@latest`

### Connect в app зависает
- Это runtime issue, не build. См. `docs/troubleshooting.md`
