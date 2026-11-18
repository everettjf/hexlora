//! Capability inference from imports and embedded strings.
//!
//! A capability says a binary *appears able* to do something: the import table
//! and string constants are consistent with it. It never claims the behaviour
//! happens. Every result carries a confidence and the evidence behind it so a
//! reviewer can judge it, and a rule identifier so a policy can allow or forbid
//! it.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use hexlora_core::{
    BinaryAnalysis, BinaryPlatform, Capability, Confidence, Finding, FindingCategory, Severity,
};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Windows,
    /// Mach-O and ELF share the POSIX and libc surface.
    Posix,
    Apple,
    Linux,
    Any,
}

struct Rule {
    id: &'static str,
    group: &'static str,
    name: &'static str,
    description: &'static str,
    severity: Severity,
    /// Confidence when the import requirement alone is met.
    confidence: Confidence,
    target: Target,
    /// Every inner list must be satisfied by at least one imported name.
    /// Empty means the rule is driven by strings only.
    imports: &'static [&'static [&'static str]],
    /// Any one of these, found in the file, corroborates the rule.
    strings: &'static [&'static str],
    /// Whether strings alone (without the imports) are worth reporting.
    strings_alone: bool,
    /// Whether the rule needs both its imports and one of its strings.
    strings_required: bool,
}

// One positional row per rule keeps the table below readable.
#[allow(clippy::too_many_arguments)]
const fn rule(
    id: &'static str,
    group: &'static str,
    name: &'static str,
    description: &'static str,
    severity: Severity,
    confidence: Confidence,
    target: Target,
    imports: &'static [&'static [&'static str]],
) -> Rule {
    Rule {
        id,
        group,
        name,
        description,
        severity,
        confidence,
        target,
        imports,
        strings: &[],
        strings_alone: false,
        strings_required: false,
    }
}

impl Rule {
    /// Strings that corroborate the imports, or stand in for them when `alone`.
    const fn with_strings(mut self, strings: &'static [&'static str], alone: bool) -> Self {
        self.strings = strings;
        self.strings_alone = alone;
        self
    }

    /// Strings that must be present in addition to the imports.
    const fn with_required_strings(mut self, strings: &'static [&'static str]) -> Self {
        self.strings = strings;
        self.strings_required = true;
        self
    }
}

use Confidence::{High as CH, Low as CL, Medium as CM};
use Severity::{Info, Low, Medium};
use Target::{Any, Apple, Linux, Posix, Windows};

/// Windows names are matched without their `A`/`W` suffix and with `Zw`
/// treated as `Nt`, so each alternative below covers those variants.
static RULES: &[Rule] = &[
    // ---- Code injection -------------------------------------------------
    rule(
        "injection.remote-thread",
        "Code injection",
        "Write into and start code in another process",
        "Imports the full sequence used to open another process, allocate and write memory in it, and start a thread or APC there.",
        Medium,
        CH,
        Windows,
        &[
            &["OpenProcess", "NtOpenProcess"],
            &["VirtualAllocEx", "NtAllocateVirtualMemory", "NtMapViewOfSection"],
            &["WriteProcessMemory", "NtWriteVirtualMemory"],
            &[
                "CreateRemoteThread",
                "CreateRemoteThreadEx",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "QueueUserAPC",
                "NtQueueApcThread",
            ],
        ],
    ),
    rule(
        "injection.process-hollowing",
        "Code injection",
        "Replace the image of a suspended process",
        "Imports the calls used to unmap a new process's image, rewrite its thread context, and resume it.",
        Medium,
        CH,
        Windows,
        &[
            &["CreateProcess", "CreateProcessInternal", "NtCreateUserProcess"],
            &["NtUnmapViewOfSection"],
            &["SetThreadContext", "NtSetContextThread"],
            &["ResumeThread", "NtResumeThread"],
        ],
    ),
    rule(
        "injection.foreign-memory-write",
        "Code injection",
        "Write memory of another process",
        "Imports a call that writes into another process's address space. Debuggers and instrumentation tools need this too.",
        Low,
        CM,
        Windows,
        &[&["WriteProcessMemory", "NtWriteVirtualMemory"]],
    ),
    rule(
        "injection.window-hook",
        "Code injection",
        "Install a system-wide hook",
        "Imports SetWindowsHookEx, which loads a module into other processes' message loops.",
        Low,
        CM,
        Windows,
        &[&["SetWindowsHookEx"]],
    ),
    rule(
        "injection.ptrace",
        "Code injection",
        "Trace or modify another process",
        "Imports ptrace, which can read and write another process's memory and registers.",
        Low,
        CL,
        Posix,
        &[&["ptrace"]],
    ),
    rule(
        "injection.mach-task-port",
        "Code injection",
        "Control another process through its task port",
        "Imports the Mach calls used to obtain another task's port and write memory or create threads in it.",
        Medium,
        CH,
        Apple,
        &[
            &["task_for_pid", "processor_set_tasks"],
            &[
                "mach_vm_write",
                "vm_write",
                "thread_create_running",
                "mach_vm_allocate",
            ],
        ],
    ),
    // ---- Anti-analysis --------------------------------------------------
    rule(
        "anti-analysis.debugger-detection",
        "Anti-analysis",
        "Detect an attached debugger",
        "Imports calls commonly used to check for or hide from a debugger. IsDebuggerPresent alone is ignored because the C runtime imports it.",
        Low,
        CM,
        Windows,
        &[&[
            "CheckRemoteDebuggerPresent",
            "NtSetInformationThread",
            "NtQueryInformationProcess",
        ]],
    ),
    rule(
        "anti-analysis.sandbox-artifacts",
        "Anti-analysis",
        "References virtual machine or sandbox artifacts",
        "Contains names of virtualization drivers, guest tools, or sandbox modules that environment checks look for.",
        Low,
        CL,
        Any,
        &[],
    )
    .with_strings(
        &[
            "VBoxGuest",
            "VBoxService",
            "vmtoolsd",
            "vmhgfs",
            "SbieDll",
            "qemu-ga",
            "wine_get_version",
            "cuckoomon",
            "HARDWARE\\ACPI\\DSDT\\VBOX__",
        ],
        true,
    ),
    // ---- Execution ------------------------------------------------------
    rule(
        "execution.process-creation",
        "Execution",
        "Start other programs",
        "Imports calls that launch processes or run shell commands.",
        Info,
        CH,
        Windows,
        &[&[
            "CreateProcess",
            "CreateProcessAsUser",
            "CreateProcessWithLogon",
            "CreateProcessWithToken",
            "ShellExecute",
            "ShellExecuteEx",
            "WinExec",
            "system",
            "_wsystem",
        ]],
    ),
    rule(
        "execution.process-creation",
        "Execution",
        "Start other programs",
        "Imports calls that launch processes or run shell commands.",
        Info,
        CH,
        Posix,
        &[&[
            "execve",
            "execv",
            "execvp",
            "execl",
            "execlp",
            "posix_spawn",
            "posix_spawnp",
            "system",
            "popen",
        ]],
    ),
    rule(
        "execution.runtime-api-resolution",
        "Execution",
        "Resolve APIs by name at run time",
        "Imports the loader calls used to load a library and look up a function by name, so not every function it uses appears in the import table.",
        Info,
        CM,
        Windows,
        &[
            &["LoadLibrary", "LoadLibraryEx", "LdrLoadDll"],
            &["GetProcAddress", "LdrGetProcedureAddress"],
        ],
    ),
    rule(
        "execution.runtime-api-resolution",
        "Execution",
        "Resolve APIs by name at run time",
        "Imports dlopen and dlsym, so not every function it uses appears in the import table.",
        Info,
        CM,
        Posix,
        &[&["dlopen"], &["dlsym"]],
    ),
    rule(
        "execution.runtime-code-memory",
        "Execution",
        "Change memory protection at run time",
        "Imports calls that allocate memory and change its protection, the mechanism behind JIT compilers and in-memory loaders alike.",
        Info,
        CL,
        Windows,
        &[
            &["VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory"],
            &["VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"],
        ],
    ),
    rule(
        "execution.script-host",
        "Execution",
        "Runs a script interpreter",
        "Contains command lines for a script host or command interpreter.",
        Low,
        CL,
        Any,
        &[],
    )
    .with_strings(
        &[
            "powershell -",
            "powershell.exe",
            "cmd.exe /c",
            "cmd /c ",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "/bin/sh -c",
            "/bin/bash -c",
            "osascript -e",
        ],
        true,
    ),
    // ---- Persistence ----------------------------------------------------
    rule(
        "persistence.registry-run-key",
        "Persistence",
        "Register to start at logon",
        "Writes registry values and references an autostart key.",
        Medium,
        CM,
        Windows,
        &[&["RegSetValue", "RegSetValueEx", "RegSetKeyValue", "NtSetValueKey"]],
    )
    .with_required_strings(&[
        "\\CurrentVersion\\Run",
        "\\CurrentVersion\\RunOnce",
        "\\Winlogon\\Shell",
        "\\Winlogon\\Userinit",
        "\\Image File Execution Options",
    ]),
    rule(
        "persistence.windows-service",
        "Persistence",
        "Install or control a Windows service",
        "Imports the service control manager calls used to create and start services, including kernel drivers.",
        Low,
        CH,
        Windows,
        &[&["OpenSCManager"], &["CreateService", "ChangeServiceConfig"]],
    ),
    rule(
        "persistence.scheduled-task",
        "Persistence",
        "Create a scheduled task",
        "References the task scheduler command line.",
        Low,
        CL,
        Windows,
        &[],
    )
    .with_strings(&["schtasks", "\\Microsoft\\Windows\\Task Scheduler"], true),
    rule(
        "persistence.launch-item",
        "Persistence",
        "Install a launch agent or daemon",
        "References the directories launchd loads background items from.",
        Low,
        CL,
        Apple,
        &[],
    )
    .with_strings(&["/LaunchAgents/", "/LaunchDaemons/", "/Library/StartupItems"], true),
    rule(
        "persistence.privileged-helper",
        "Persistence",
        "Install a privileged helper",
        "Imports the ServiceManagement calls that register a helper or login item with launchd.",
        Info,
        CH,
        Apple,
        &[&[
            "SMJobBless",
            "SMLoginItemSetEnabled",
            "OBJC_CLASS_$_SMAppService",
        ]],
    ),
    rule(
        "persistence.unix-autostart",
        "Persistence",
        "References autostart locations",
        "References cron, systemd, or shell start-up files.",
        Low,
        CL,
        Linux,
        &[],
    )
    .with_strings(
        &[
            "/etc/cron",
            "/etc/systemd/system",
            "/.config/autostart",
            "/etc/rc.local",
            "/etc/ld.so.preload",
            "/etc/init.d/",
        ],
        true,
    ),
    // ---- Privilege and credentials --------------------------------------
    rule(
        "privilege.token-adjustment",
        "Privilege",
        "Enable token privileges",
        "Imports the calls used to enable privileges on the process token.",
        Low,
        CM,
        Windows,
        &[&["AdjustTokenPrivileges", "NtAdjustPrivilegesToken", "RtlAdjustPrivilege"]],
    )
    .with_strings(
        &[
            "SeDebugPrivilege",
            "SeLoadDriverPrivilege",
            "SeTcbPrivilege",
            "SeImpersonatePrivilege",
            "SeBackupPrivilege",
        ],
        false,
    ),
    rule(
        "privilege.token-impersonation",
        "Privilege",
        "Impersonate another user's token",
        "Imports the calls used to duplicate a token and run under it.",
        Low,
        CM,
        Windows,
        &[
            &["OpenProcessToken", "NtOpenProcessToken"],
            &[
                "DuplicateTokenEx",
                "ImpersonateLoggedOnUser",
                "SetThreadToken",
                "CreateProcessWithToken",
            ],
        ],
    ),
    rule(
        "privilege.set-user-id",
        "Privilege",
        "Change user or group identity",
        "Imports calls that change the process's user or group ID.",
        Info,
        CM,
        Posix,
        &[&["setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid"]],
    ),
    rule(
        "privilege.authorization-services",
        "Privilege",
        "Run a tool as root through Authorization Services",
        "Imports AuthorizationExecuteWithPrivileges, a deprecated call that runs an arbitrary tool as root after a password prompt.",
        Medium,
        CH,
        Apple,
        &[&["AuthorizationExecuteWithPrivileges"]],
    ),
    rule(
        "credentials.process-memory-dump",
        "Credential access",
        "Dump another process's memory",
        "Imports MiniDumpWriteDump. Crash reporters use it on their own process; credential dumpers use it on LSASS.",
        Low,
        CL,
        Windows,
        &[&["MiniDumpWriteDump"]],
    )
    .with_strings(&["lsass.exe", "lsass.dmp"], false),
    rule(
        "credentials.windows-vault",
        "Credential access",
        "Read stored Windows credentials",
        "Imports credential manager or data-protection calls that return stored secrets.",
        Low,
        CM,
        Windows,
        &[&[
            "CredEnumerate",
            "CredRead",
            "LsaRetrievePrivateData",
            "SamIConnect",
            "VaultEnumerateItems",
        ]],
    ),
    rule(
        "credentials.keychain",
        "Credential access",
        "Read items from the keychain",
        "Imports Keychain Services calls that return stored secrets.",
        Info,
        CM,
        Apple,
        &[&[
            "SecItemCopyMatching",
            "SecKeychainFindGenericPassword",
            "SecKeychainFindInternetPassword",
            "SecKeychainItemCopyContent",
        ]],
    ),
    // ---- Collection -----------------------------------------------------
    rule(
        "collection.keystrokes",
        "Collection",
        "Observe keyboard input",
        "Imports a hook installer together with key-state polling, the combination keyloggers use.",
        Medium,
        CM,
        Windows,
        &[
            &["SetWindowsHookEx", "RegisterRawInputDevices"],
            &["GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "GetRawInputData"],
        ],
    ),
    rule(
        "collection.event-tap",
        "Collection",
        "Observe keyboard and mouse events",
        "Imports CGEventTapCreate, which receives input events destined for other applications.",
        Medium,
        CM,
        Apple,
        &[&["CGEventTapCreate", "CGEventTapCreateForPid"]],
    ),
    rule(
        "collection.screen-capture",
        "Collection",
        "Capture the screen",
        "Imports the calls used to copy the desktop into a bitmap.",
        Low,
        CL,
        Windows,
        &[
            &["BitBlt", "PrintWindow"],
            &["GetDesktopWindow", "GetWindowDC", "CreateDC"],
            &["CreateCompatibleBitmap", "CreateDIBSection"],
        ],
    ),
    rule(
        "collection.screen-capture",
        "Collection",
        "Capture the screen",
        "Imports screen-capture calls.",
        Low,
        CM,
        Apple,
        &[&[
            "CGWindowListCreateImage",
            "CGDisplayCreateImage",
            "CGDisplayStreamCreate",
            "OBJC_CLASS_$_SCStream",
            "OBJC_CLASS_$_SCScreenshotManager",
        ]],
    ),
    rule(
        "collection.clipboard",
        "Collection",
        "Read the clipboard",
        "Imports the calls used to open the clipboard and read its contents.",
        Info,
        CM,
        Windows,
        &[&["OpenClipboard"], &["GetClipboardData"]],
    ),
    // ---- Discovery ------------------------------------------------------
    rule(
        "discovery.process-enumeration",
        "Discovery",
        "Enumerate running processes",
        "Imports the calls used to list running processes.",
        Info,
        CH,
        Windows,
        &[&[
            "CreateToolhelp32Snapshot",
            "EnumProcesses",
            "K32EnumProcesses",
            "WTSEnumerateProcesses",
        ]],
    ),
    // ---- Network --------------------------------------------------------
    rule(
        "network.http-client",
        "Network",
        "Make HTTP requests",
        "Imports an HTTP client API.",
        Info,
        CH,
        Windows,
        &[&[
            "InternetOpen",
            "InternetOpenUrl",
            "HttpSendRequest",
            "HttpSendRequestEx",
            "WinHttpOpen",
            "WinHttpSendRequest",
            "URLDownloadToFile",
            "URLDownloadToCacheFile",
        ]],
    ),
    rule(
        "network.http-client",
        "Network",
        "Make HTTP requests",
        "Imports an HTTP client API.",
        Info,
        CH,
        Posix,
        &[&[
            "curl_easy_perform",
            "curl_multi_perform",
            "OBJC_CLASS_$_NSURLSession",
            "OBJC_CLASS_$_NSURLConnection",
            "CFURLRequestCreate",
            "CFHTTPMessageCreateRequest",
        ]],
    ),
    rule(
        "network.download-and-run",
        "Network",
        "Download a file and start a program",
        "Imports a call that saves a URL to disk together with a call that launches a program.",
        Medium,
        CM,
        Windows,
        &[
            &["URLDownloadToFile", "URLDownloadToCacheFile"],
            &["ShellExecute", "ShellExecuteEx", "CreateProcess", "WinExec"],
        ],
    ),
    rule(
        "network.raw-sockets",
        "Network",
        "Open network connections",
        "Imports socket calls for outbound connections.",
        Info,
        CH,
        Windows,
        &[&["WSAStartup", "socket", "WSASocket"], &["connect", "WSAConnect"]],
    ),
    rule(
        "network.raw-sockets",
        "Network",
        "Open network connections",
        "Imports socket calls for outbound connections.",
        Info,
        CH,
        Posix,
        &[&["socket"], &["connect"]],
    ),
    rule(
        "network.listener",
        "Network",
        "Accept inbound connections",
        "Imports the calls used to bind a port and accept connections.",
        Low,
        CM,
        Any,
        &[&["bind"], &["listen"], &["accept", "accept4", "WSAAccept"]],
    ),
    // ---- Cryptography ---------------------------------------------------
    rule(
        "crypto.symmetric-encryption",
        "Cryptography",
        "Encrypt or decrypt data",
        "Imports a platform encryption API.",
        Info,
        CH,
        Windows,
        &[&[
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "CryptProtectData",
            "CryptUnprotectData",
        ]],
    ),
    rule(
        "crypto.symmetric-encryption",
        "Cryptography",
        "Encrypt or decrypt data",
        "Imports an encryption API.",
        Info,
        CH,
        Posix,
        &[&[
            "CCCrypt",
            "CCCryptorCreate",
            "EVP_EncryptInit_ex",
            "EVP_DecryptInit_ex",
            "EVP_CipherInit_ex",
            "AES_encrypt",
            "AES_set_encrypt_key",
            "SecKeyCreateEncryptedData",
        ]],
    ),
    // ---- Impact ---------------------------------------------------------
    rule(
        "impact.shadow-copy-deletion",
        "Impact",
        "Deletes backups or shadow copies",
        "Contains command lines that delete volume shadow copies or disable recovery, a step ransomware takes before encrypting.",
        Medium,
        CM,
        Windows,
        &[],
    )
    .with_strings(
        &[
            "vssadmin delete shadows",
            "vssadmin.exe delete shadows",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
            "wbadmin delete catalog",
        ],
        true,
    ),
    // ---- Kernel drivers -------------------------------------------------
    rule(
        "driver.user-device-interface",
        "Kernel driver",
        "Expose a device to user mode",
        "Creates a device object and a symbolic link, which lets user-mode programs open the driver and send it I/O control requests.",
        Info,
        CH,
        Windows,
        &[
            &["IoCreateDevice", "IoCreateDeviceSecure", "WdmlibIoCreateDeviceSecure"],
            &["IoCreateSymbolicLink", "IoCreateUnprotectedSymbolicLink"],
        ],
    ),
    rule(
        "driver.physical-memory-mapping",
        "Kernel driver",
        "Map physical memory",
        "Imports calls that map arbitrary physical memory or I/O space. Drivers that expose this to user mode are a common route to kernel compromise.",
        Medium,
        CM,
        Windows,
        &[&[
            "MmMapIoSpace",
            "MmMapIoSpaceEx",
            "MmMapLockedPagesSpecifyCache",
            "MmCopyMemory",
            "HalTranslateBusAddress",
        ]],
    )
    .with_strings(&["\\Device\\PhysicalMemory"], true),
    rule(
        "driver.foreign-process-access",
        "Kernel driver",
        "Open and manipulate arbitrary processes",
        "Imports kernel calls that look up a process and then attach to, copy memory from, or terminate it.",
        Medium,
        CM,
        Windows,
        &[
            &["PsLookupProcessByProcessId", "NtOpenProcess"],
            &[
                "KeStackAttachProcess",
                "KeAttachProcess",
                "MmCopyVirtualMemory",
                "NtTerminateProcess",
                "PsSuspendProcess",
            ],
        ],
    ),
    rule(
        "driver.system-callbacks",
        "Kernel driver",
        "Register system-wide notification callbacks",
        "Registers for process, thread, image-load, object, or registry notifications. Security products and rootkits both do.",
        Info,
        CH,
        Windows,
        &[&[
            "PsSetCreateProcessNotifyRoutine",
            "PsSetCreateProcessNotifyRoutineEx",
            "PsSetCreateProcessNotifyRoutineEx2",
            "PsSetCreateThreadNotifyRoutine",
            "PsSetLoadImageNotifyRoutine",
            "ObRegisterCallbacks",
            "CmRegisterCallback",
            "CmRegisterCallbackEx",
        ]],
    ),
    rule(
        "driver.file-system-filter",
        "Kernel driver",
        "Filter file system I/O",
        "Registers a minifilter that sees file operations system-wide.",
        Info,
        CH,
        Windows,
        &[&["FltRegisterFilter"]],
    ),
    rule(
        "driver.network-filter",
        "Kernel driver",
        "Filter network traffic",
        "Registers a Windows Filtering Platform callout or NDIS filter that sees network traffic system-wide.",
        Info,
        CH,
        Windows,
        &[&[
            "FwpsCalloutRegister0",
            "FwpsCalloutRegister1",
            "FwpsCalloutRegister2",
            "FwpsCalloutRegister3",
            "NdisFRegisterFilterDriver",
            "NdisRegisterProtocolDriver",
        ]],
    ),
    rule(
        "driver.kernel-code-loading",
        "Kernel driver",
        "Load another driver",
        "Imports calls that load additional kernel code.",
        Low,
        CM,
        Windows,
        &[&["NtLoadDriver", "MmLoadSystemImage", "NtSetSystemInformation"]],
    ),
];

impl Rule {
    fn applies_to(&self, platform: Option<BinaryPlatform>) -> bool {
        matches!(
            (self.target, platform),
            (Any, _)
                | (Windows, Some(BinaryPlatform::Windows))
                | (
                    Posix,
                    Some(BinaryPlatform::MacOs | BinaryPlatform::Linux | BinaryPlatform::Unix)
                )
                | (Apple, Some(BinaryPlatform::MacOs))
                | (Linux, Some(BinaryPlatform::Linux | BinaryPlatform::Unix))
        )
    }
}

/// Where each rule string was first seen in a file.
#[derive(Debug, Default, Clone)]
pub struct StringEvidence {
    /// Rule string → file offset of its first occurrence.
    found: BTreeMap<&'static str, u64>,
}

impl StringEvidence {
    pub fn is_empty(&self) -> bool {
        self.found.is_empty()
    }
    pub fn len(&self) -> usize {
        self.found.len()
    }
    fn offset(&self, needle: &str) -> Option<u64> {
        self.found.get(needle).copied()
    }
}

/// Streaming search for every rule string, in ASCII and UTF-16LE, ignoring
/// ASCII case. Feed it the file in order; chunk boundaries are handled.
pub struct StringScanner {
    automaton: AhoCorasick,
    /// Pattern index → rule string.
    needles: Vec<&'static str>,
    /// Bytes carried from the previous chunk so a match can span two chunks.
    carry: Vec<u8>,
    carry_limit: usize,
    /// File offset of the first byte in `carry`.
    carry_offset: u64,
    evidence: StringEvidence,
    distinct: usize,
}

impl Default for StringScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl StringScanner {
    pub fn new() -> Self {
        let mut distinct: Vec<&'static str> = RULES
            .iter()
            .flat_map(|rule| rule.strings)
            .copied()
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(distinct.len() * 2);
        let mut needles = Vec::with_capacity(distinct.len() * 2);
        for needle in &distinct {
            patterns.push(needle.as_bytes().to_vec());
            needles.push(*needle);
            patterns.push(needle.bytes().flat_map(|byte| [byte, 0]).collect());
            needles.push(*needle);
        }
        let carry_limit = patterns.iter().map(Vec::len).max().unwrap_or(1) - 1;
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .expect("rule strings form a valid automaton");
        Self {
            automaton,
            needles,
            carry: Vec::new(),
            carry_limit,
            carry_offset: 0,
            evidence: StringEvidence::default(),
            distinct: distinct.len(),
        }
    }

    /// True once every rule string has been seen; further input changes nothing.
    pub fn is_complete(&self) -> bool {
        self.evidence.found.len() >= self.distinct
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.is_complete() || chunk.is_empty() {
            return;
        }
        let base = self.carry_offset;
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(chunk);
        for found in self.automaton.find_overlapping_iter(&window) {
            let needle = self.needles[found.pattern().as_usize()];
            self.evidence
                .found
                .entry(needle)
                .or_insert(base + found.start() as u64);
        }
        let keep = window.len().min(self.carry_limit);
        self.carry_offset = base + (window.len() - keep) as u64;
        window.drain(..window.len() - keep);
        self.carry = window;
    }

    pub fn finish(self) -> StringEvidence {
        self.evidence
    }

    /// Scans one in-memory buffer.
    pub fn scan(bytes: &[u8]) -> StringEvidence {
        let mut scanner = Self::new();
        scanner.feed(bytes);
        scanner.finish()
    }
}

/// The import names of a binary in the forms rules are written against.
fn import_names(analysis: &BinaryAnalysis) -> HashSet<String> {
    let windows = matches!(analysis.platform, Some(BinaryPlatform::Windows));
    let mut names = HashSet::with_capacity(analysis.imports.len() * 2);
    for import in &analysis.imports {
        let raw = import.name.as_str();
        // Mach-O prefixes C symbols with one underscore.
        let name = if windows {
            raw
        } else {
            raw.strip_prefix('_').unwrap_or(raw)
        };
        names.insert(name.to_string());
        if !windows {
            continue;
        }
        // `Zw` and `Nt` name the same system service.
        let service = name
            .strip_prefix("Zw")
            .map(|rest| format!("Nt{rest}"))
            .unwrap_or_else(|| name.to_string());
        if service != name {
            names.insert(service.clone());
        }
        // ANSI and wide variants share a base name.
        if let Some(base) = service
            .strip_suffix('A')
            .or_else(|| service.strip_suffix('W'))
            && base
                .chars()
                .last()
                .is_some_and(|last| last.is_ascii_lowercase())
        {
            names.insert(base.to_string());
        }
    }
    names
}

fn raise(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::Low => Confidence::Medium,
        Confidence::Medium | Confidence::High => Confidence::High,
    }
}

/// Infers capabilities from an analysis. Pass the result of a string scan to
/// include string-backed rules and corroboration; without it only import
/// evidence is used.
pub fn detect_capabilities(
    analysis: &BinaryAnalysis,
    strings: Option<&StringEvidence>,
) -> Vec<Capability> {
    let names = import_names(analysis);
    let mut capabilities: Vec<Capability> = Vec::new();
    for rule in RULES {
        if !rule.applies_to(analysis.platform) {
            continue;
        }
        let mut evidence = Vec::new();
        let imports_met = !rule.imports.is_empty()
            && rule.imports.iter().all(|alternatives| {
                let matched: Vec<&str> = alternatives
                    .iter()
                    .copied()
                    .filter(|name| names.contains(*name))
                    .collect();
                evidence.extend(matched.iter().map(|name| format!("import {name}")));
                !matched.is_empty()
            });
        if !imports_met {
            evidence.clear();
        }
        let string_hits: Vec<String> = strings
            .map(|found| {
                rule.strings
                    .iter()
                    .filter_map(|needle| {
                        found
                            .offset(needle)
                            .map(|offset| format!("string \"{needle}\" at 0x{offset:x}"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let strings_met = !string_hits.is_empty();
        let confidence = if rule.strings_required {
            if !(imports_met && strings_met) {
                continue;
            }
            rule.confidence
        } else if imports_met {
            if strings_met {
                raise(rule.confidence)
            } else {
                rule.confidence
            }
        } else if strings_met && rule.strings_alone {
            if rule.imports.is_empty() {
                rule.confidence
            } else {
                Confidence::Low
            }
        } else {
            continue;
        };
        evidence.extend(string_hits);
        evidence.dedup();
        // The same capability is described once per platform; keep one.
        if capabilities.iter().any(|known| known.id == rule.id) {
            continue;
        }
        capabilities.push(Capability {
            id: rule.id.into(),
            group: rule.group.into(),
            name: rule.name.into(),
            description: rule.description.into(),
            severity: rule.severity,
            confidence,
            evidence,
        });
    }
    // A capability that is one step of a larger one already reported adds
    // nothing but a second line about the same imports.
    for (part, wholes) in SUBSUMED {
        if capabilities
            .iter()
            .any(|known| wholes.contains(&known.id.as_str()))
        {
            capabilities.retain(|known| known.id != *part);
        }
    }
    capabilities
}

/// Capabilities implied by a more specific one: (part, any of these wholes).
const SUBSUMED: &[(&str, &[&str])] = &[
    (
        "injection.foreign-memory-write",
        &["injection.remote-thread", "injection.process-hollowing"],
    ),
    ("injection.window-hook", &["collection.keystrokes"]),
    ("injection.ptrace", &["injection.mach-task-port"]),
    ("network.raw-sockets", &["network.listener"]),
];

/// Capabilities worth a reviewer's attention become findings; purely
/// informational ones stay in the capability list so they do not drown the
/// findings view.
pub fn capability_findings(capabilities: &[Capability]) -> Vec<Finding> {
    capabilities
        .iter()
        .filter(|capability| capability.severity != Severity::Info)
        .map(|capability| {
            let mut finding = Finding::new(
                capability.severity,
                FindingCategory::Capability,
                format!("Capability: {}", capability.name),
                format!(
                    "{} This is inferred from static evidence and does not show the behaviour occurs.",
                    capability.description
                ),
            )
            .with_rule(format!("capability.{}", capability.id))
            .with_confidence(capability.confidence);
            for item in &capability.evidence {
                let (label, value) = item.split_once(' ').unwrap_or(("evidence", item));
                finding = finding.with_evidence(
                    match label {
                        "import" => "Import",
                        "string" => "String",
                        _ => "Evidence",
                    },
                    value,
                );
            }
            finding
        })
        .collect()
}

/// Recomputes the capabilities and capability findings of an analysis and of
/// its architecture slices.
pub fn apply_capabilities(analysis: &mut BinaryAnalysis, strings: Option<&StringEvidence>) {
    analysis.capabilities = detect_capabilities(analysis, strings);
    analysis
        .findings
        .retain(|finding| finding.category != FindingCategory::Capability);
    analysis
        .findings
        .extend(capability_findings(&analysis.capabilities));
    for slice in &mut analysis.slice_analyses {
        apply_capabilities(slice, strings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlora_core::SymbolInfo;

    fn binary(platform: BinaryPlatform, imports: &[&str]) -> BinaryAnalysis {
        BinaryAnalysis {
            platform: Some(platform),
            imports: imports
                .iter()
                .map(|name| SymbolInfo {
                    name: (*name).into(),
                    address: None,
                    library: None,
                    demangled: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn ids(capabilities: &[Capability]) -> Vec<&str> {
        capabilities.iter().map(|c| c.id.as_str()).collect()
    }

    #[test]
    fn rule_identifiers_are_well_formed_and_strings_are_searchable() {
        for rule in RULES {
            assert!(
                rule.id.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'-'),
                "{}",
                rule.id
            );
            assert!(
                !rule.imports.is_empty() || !rule.strings.is_empty(),
                "{} can never fire",
                rule.id
            );
            assert!(
                rule.imports.iter().all(|group| !group.is_empty()),
                "{}",
                rule.id
            );
            assert!(
                rule.strings.iter().all(|s| s.len() >= 6 && s.is_ascii()),
                "{}",
                rule.id
            );
            if rule.strings_required {
                assert!(!rule.strings.is_empty() && !rule.imports.is_empty());
            }
        }
    }

    #[test]
    fn injection_needs_the_whole_sequence() {
        let partial = binary(BinaryPlatform::Windows, &["OpenProcess", "VirtualAllocEx"]);
        assert!(!ids(&detect_capabilities(&partial, None)).contains(&"injection.remote-thread"));

        let full = binary(
            BinaryPlatform::Windows,
            &[
                "OpenProcess",
                "VirtualAllocEx",
                "ZwWriteVirtualMemory",
                "CreateRemoteThread",
            ],
        );
        let capabilities = detect_capabilities(&full, None);
        let injection = capabilities
            .iter()
            .find(|c| c.id == "injection.remote-thread")
            .expect("full injection sequence is reported");
        assert_eq!(injection.confidence, Confidence::High);
        assert!(
            injection
                .evidence
                .contains(&"import NtWriteVirtualMemory".to_string())
        );
    }

    #[test]
    fn ansi_and_wide_variants_match_but_unrelated_suffixes_do_not() {
        let wide = binary(BinaryPlatform::Windows, &["CreateProcessW"]);
        assert!(ids(&detect_capabilities(&wide, None)).contains(&"execution.process-creation"));
        // `VirtualAllocExNUMA` is not `VirtualAllocEx` + suffix, and the C
        // runtime's IsDebuggerPresent must stay quiet.
        let quiet = binary(BinaryPlatform::Windows, &["IsDebuggerPresent", "GetDataA1"]);
        assert!(detect_capabilities(&quiet, None).is_empty());
    }

    #[test]
    fn platform_rules_do_not_cross_over() {
        let mach = binary(
            BinaryPlatform::MacOs,
            &["_task_for_pid", "_mach_vm_write", "_ptrace"],
        );
        let found = detect_capabilities(&mach, None);
        assert!(ids(&found).contains(&"injection.mach-task-port"));
        // Task-port control already says everything `ptrace` would.
        assert!(!ids(&found).contains(&"injection.ptrace"));
        let tracer = binary(BinaryPlatform::MacOs, &["_ptrace"]);
        assert_eq!(
            ids(&detect_capabilities(&tracer, None)),
            ["injection.ptrace"]
        );

        let elf = binary(
            BinaryPlatform::Linux,
            &["task_for_pid", "mach_vm_write", "socket", "connect"],
        );
        let found = detect_capabilities(&elf, None);
        assert!(!ids(&found).contains(&"injection.mach-task-port"));
        assert!(ids(&found).contains(&"network.raw-sockets"));

        let windows = binary(BinaryPlatform::Windows, &["ptrace", "execve"]);
        assert!(detect_capabilities(&windows, None).is_empty());
    }

    #[test]
    fn strings_corroborate_gate_and_stand_alone() {
        // Required strings: imports alone are not enough.
        let registry = binary(BinaryPlatform::Windows, &["RegSetValueExW"]);
        assert!(detect_capabilities(&registry, None).is_empty());
        let evidence =
            StringScanner::scan(b"..Software\\Microsoft\\Windows\\CurrentVersion\\Run\0..");
        let found = detect_capabilities(&registry, Some(&evidence));
        assert_eq!(ids(&found), ["persistence.registry-run-key"]);
        assert!(found[0].evidence.iter().any(|e| e.starts_with("string ")));

        // Corroborating strings raise confidence.
        let token = binary(BinaryPlatform::Windows, &["AdjustTokenPrivileges"]);
        let plain = detect_capabilities(&token, None);
        assert_eq!(plain[0].confidence, Confidence::Medium);
        let evidence = StringScanner::scan(b"SeDebugPrivilege");
        assert_eq!(
            detect_capabilities(&token, Some(&evidence))[0].confidence,
            Confidence::High
        );
        // ...but do not report that rule on their own.
        let none = binary(BinaryPlatform::Windows, &[]);
        assert!(detect_capabilities(&none, Some(&evidence)).is_empty());

        // String-only rules report at their own confidence.
        let evidence = StringScanner::scan(b"cmd.exe /c vssadmin delete shadows /all");
        let found = detect_capabilities(&none, Some(&evidence));
        assert!(ids(&found).contains(&"impact.shadow-copy-deletion"));
        assert!(ids(&found).contains(&"execution.script-host"));
    }

    #[test]
    fn scanner_finds_utf16_mixed_case_and_matches_split_across_chunks() {
        let wide: Vec<u8> = "sedebugprivilege".bytes().flat_map(|b| [b, 0]).collect();
        let evidence = StringScanner::scan(&wide);
        assert_eq!(evidence.offset("SeDebugPrivilege"), Some(0));

        let haystack = b"....................VBoxGuest....";
        for split in 0..haystack.len() {
            let mut scanner = StringScanner::new();
            scanner.feed(&haystack[..split]);
            scanner.feed(&haystack[split..]);
            assert_eq!(
                scanner.finish().offset("VBoxGuest"),
                Some(20),
                "split at {split}"
            );
        }
        let mut scanner = StringScanner::new();
        for byte in haystack {
            scanner.feed(std::slice::from_ref(byte));
        }
        assert_eq!(scanner.finish().offset("VBoxGuest"), Some(20));
        assert!(StringScanner::scan(&[]).is_empty());
    }

    #[test]
    fn only_non_informational_capabilities_become_findings() {
        let mut analysis = binary(
            BinaryPlatform::Windows,
            &["CreateProcessW", "WriteProcessMemory"],
        );
        analysis
            .slice_analyses
            .push(binary(BinaryPlatform::Windows, &["SetWindowsHookExW"]));
        apply_capabilities(&mut analysis, None);
        assert_eq!(analysis.capabilities.len(), 2);
        assert_eq!(analysis.findings.len(), 1);
        let finding = &analysis.findings[0];
        assert_eq!(
            finding.rule_id.as_deref(),
            Some("capability.injection.foreign-memory-write")
        );
        assert_eq!(finding.category, FindingCategory::Capability);
        assert!(finding.confidence.is_some());
        assert_eq!(finding.evidence[0].label, "Import");
        assert_eq!(analysis.slice_analyses[0].findings.len(), 1);

        // Re-applying replaces rather than duplicates.
        apply_capabilities(&mut analysis, None);
        assert_eq!(analysis.findings.len(), 1);
    }
}
