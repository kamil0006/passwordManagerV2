# Instalacja na Windows

## Wymagania

- **Node.js** 18+ (zalecane LTS) – [nodejs.org](https://nodejs.org)
- **Visual Studio Build Tools** (dla `better-sqlite3`) – [Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) – wybierz „Desktop development with C++”

## Kroki instalacji (dla użytkownika końcowego)

1. Pobierz plik instalatora z folderu `electron-builder-output/`:
   - **NSIS** (instalator): `Password Manager Setup 1.0.0.exe`
   - **Portable**: `Password Manager 1.0.0.exe` (bez instalacji)

2. Uruchom plik `.exe` i postępuj według instrukcji.

3. Po instalacji aplikacja będzie dostępna w menu Start i na pulpicie.

---

## Budowanie instalatora (dla developera)

### 1. Zainstaluj zależności

```powershell
cd c:\Users\Kamil\passwordManager
npm install
```

### 2. Zbuduj frontend i utwórz instalator

```powershell
npm run build
```

To polecenie:
- buduje frontend (Vite → `frontend/dist/`)
- pakuje aplikację Electron
- tworzy instalator NSIS i wersję portable w `electron-builder-output/`

### 3. Wynik

W folderze `electron-builder-output/` znajdziesz:

| Plik | Opis |
|------|------|
| `Password Manager Setup 1.0.0.exe` | Instalator NSIS (zalecany do dystrybucji) |
| `Password Manager 1.0.0.exe` | Wersja portable (bez instalacji) |

### Szybki test (bez instalatora)

```powershell
npm run build:dir
```

Tworzy rozpakowaną aplikację w `electron-builder-output/win-unpacked/`. Uruchom `Password Manager.exe` z tego folderu.

---

## Rozwiązywanie problemów

### Błąd: „node-gyp” / „MSBuild”

Zainstaluj Visual Studio Build Tools z komponentem „Desktop development with C++”.

### Błąd: „better-sqlite3” nie buduje się

```powershell
npx electron-rebuild -f -w better-sqlite3
```

### Błąd: „Cannot create symbolic link” (winCodeSign)

Na Windows bez uprawnień administratora może wystąpić błąd przy rozpakowywaniu winCodeSign. W `package.json` jest ustawione `signAndEditExecutable: false`, co omija ten problem. Alternatywnie uruchom terminal jako Administrator.

### Baza danych po instalacji

Dane są zapisywane w:
`%APPDATA%\passwordmanager\` (lub w katalogu `userData` aplikacji Electron).
