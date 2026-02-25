# Adaptix-inject-auto BOF
auto injection (stable for Adaptix v0.11 and later)

BOF that enables the `inject-auto` command (running as Admin or SYSTEM) to inject into random PIDs of system processes: `svchost.exe` (SYSTEM only), `winlogon.exe`, and `spoolsv.exe`. You can specify custom target processes in the `inject_pid.c` file.

To use it, generate a shellcode and specify its path in the .axs file, or run `inject-auto </path/to/shellcode.bin>` to provide an alternative shellcode.

> [!IMPORTANT]
> **Note:** If "inject-auto" is executed as Administrator, injection is restricted to `svchost.exe` (SYSTEM). To enable injection into `winlogon.exe` and `spoolsv.exe`, you must first escalate privileges to SYSTEM (e.g., using `getsystem token`).

> [!CAUTION]
> **Risk of System Crash:** Using the **"terminate process"** command on core system processes (like `winlogon.exe` or `svchost.exe`) will result in an immediate OS failure and a **Blue Screen of Death (BSOD)**. For safe cleanup, always use the **"terminate thread"** method.

# Configuration

The BOF is pre-configured to target common system processes (`svchost.exe`, `winlogon.exe`, `spoolsv.exe`). 

To target additional processes, simply modify the `target_procs` array in `inject_pid.c` before compiling:
```
const char* target_procs[] = { "svchost.exe", "explorer.exe", "custom_proc.exe", NULL };
```

# Install Dependencies

To compile the BOF, you need to install the mingw-w64 cross-compiler suite.
```
# Ubuntu/Kali
apt install g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix mingw-w64-tools

# Arch
pacman -Syu mingw-w64-x86_64-gcc mingw-w64-gcc
```
# Clone & Make
```
git clone https://github.com/Svinopesik/Adaptix-inject-auto

cd Adaptix-inject-auto

make
```
Load all modules in AdaptixC2 client: Main menu -> AxScript -> Script manager.

Context menu -> Load new and select the inject_pid.axs file.
# Usage
You can provide the shellcode path directly in the command or set a default one in the `.axs` file.

**Option 1: Direct path (Recommended)**
```
inject-auto /path/to/shellcode.bin
```
**Option 2: Default path**
If no argument is provided, the script will look for the file defined in inject_pid.axs (default: /path/to/shellcode.bin).
```
inject-auto
```
