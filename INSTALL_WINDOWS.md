# Windows Installation

## Requirements

- **Node.js** 18+ (LTS recommended) – [nodejs.org](https://nodejs.org)
- **Visual Studio Build Tools** (for `better-sqlite3`) – [Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) – select "Desktop development with C++"

## Installation Steps (for end users)

1. Download the installer from the `electron-builder-output/` folder:
   - **NSIS** (installer): `Password Manager Setup 1.0.0.exe`
   - **Portable**: `Password Manager 1.0.0.exe` (no installation required)

2. Run the `.exe` file and follow the instructions.

3. After installation, the app will be available in the Start menu and on the desktop.

---

## Building the Installer (for developers)

### 1. Install dependencies

```powershell
cd c:\Users\Kamil\passwordManager
npm install
```

### 2. Build frontend and create installer

```powershell
npm run build
```

This command:
- builds the frontend (Vite → `frontend/dist/`)
- packages the Electron app
- creates the NSIS installer and portable version in `electron-builder-output/`

### 3. Output

In the `electron-builder-output/` folder you will find:

| File | Description |
|------|-------------|
| `Password Manager Setup 1.0.0.exe` | NSIS installer (recommended for distribution) |
| `Password Manager 1.0.0.exe` | Portable version (no installation) |

### Quick test (without installer)

```powershell
npm run build:dir
```

Creates an unpacked app in `electron-builder-output/win-unpacked/`. Run `Password Manager.exe` from that folder.

---

## Troubleshooting

### Error: "node-gyp" / "MSBuild"

Install Visual Studio Build Tools with the "Desktop development with C++" component.

### Error: "better-sqlite3" fails to build

```powershell
npx electron-rebuild -f -w better-sqlite3
```

### Error: "Cannot create symbolic link" (winCodeSign)

On Windows without administrator privileges, an error may occur when extracting winCodeSign. The `package.json` has `signAndEditExecutable: false` set to work around this. The app icon (in the window, on the taskbar) is still applied via the `afterPack` hook.

### App icon

The icon is located at `build/icon.png` (min. 256×256 px). The `afterPack` hook embeds it in the exe (installer, portable, app window) instead of the Electron logo.

### Database after installation

Data is stored in:
`%APPDATA%\passwordmanager\` (or in the Electron app's `userData` directory).
