use hexlora_core::{ArtifactNode, FileFormat, HexloraError, Result};
use std::{
    collections::BTreeMap,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub enum ToolAvailability {
    Available(PathBuf),
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolBehavior {
    Launch,
    Capture,
}
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}
pub trait ExternalTool: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self) -> ToolAvailability;
    fn behavior(&self) -> ToolBehavior {
        ToolBehavior::Launch
    }
    fn supports(&self, artifact: &ArtifactNode) -> bool {
        artifact.path.is_file()
    }
    /// Launches only after an explicit UI action.
    fn launch(&self, artifact: &ArtifactNode) -> Result<()>;
    fn capture(&self, _artifact: &ArtifactNode) -> Result<Option<ToolOutput>> {
        Ok(None)
    }
    fn capture_controlled(
        &self,
        artifact: &ArtifactNode,
        _timeout: Duration,
        _is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        self.capture(artifact)
    }
    /// Whether the tool can be started at, or limited to, a code address.
    fn accepts_address(&self) -> bool {
        false
    }
    /// Launches the tool positioned at `address` when it accepts one; tools
    /// that do not are launched as usual.
    fn launch_at(&self, artifact: &ArtifactNode, _address: Option<u64>) -> Result<()> {
        self.launch(artifact)
    }
    /// Captures the tool's output for the code at `address` when it accepts
    /// one, and its usual output otherwise.
    fn capture_at(
        &self,
        artifact: &ArtifactNode,
        _address: Option<u64>,
        timeout: Duration,
        is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        self.capture_controlled(artifact, timeout, is_cancelled)
    }
}

/// Builds the command-line arguments that position a tool at a virtual address.
pub type AddressArguments = fn(u64) -> Result<Vec<String>>;

pub struct CommandTool {
    id: &'static str,
    name: &'static str,
    candidates: &'static [&'static str],
    args: &'static [&'static str],
    formats: Option<&'static [FileFormat]>,
    capture: bool,
    /// Builds the arguments that position the tool at a virtual address.
    address_args: Option<AddressArguments>,
}
impl CommandTool {
    pub const fn new(
        id: &'static str,
        name: &'static str,
        candidates: &'static [&'static str],
        args: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            name,
            candidates,
            args,
            formats: None,
            capture: false,
            address_args: None,
        }
    }
    /// Arguments used instead of the default ones when a handoff carries a
    /// code address.
    pub const fn with_address_args(mut self, build: AddressArguments) -> Self {
        self.address_args = Some(build);
        self
    }
    fn arguments(&self, address: Option<u64>) -> Result<Vec<String>> {
        match (address, self.address_args) {
            (Some(address), Some(build)) => build(address),
            _ => Ok(self
                .args
                .iter()
                .map(|argument| (*argument).to_string())
                .collect()),
        }
    }
    pub const fn with_formats(mut self, formats: &'static [FileFormat]) -> Self {
        self.formats = Some(formats);
        self
    }
    pub const fn with_capture(mut self) -> Self {
        self.capture = true;
        self
    }
}
impl ExternalTool for CommandTool {
    fn id(&self) -> &'static str {
        self.id
    }
    fn display_name(&self) -> &'static str {
        self.name
    }
    fn detect(&self) -> ToolAvailability {
        self.candidates
            .iter()
            .find_map(|candidate| find_command(candidate))
            .map(ToolAvailability::Available)
            .unwrap_or(ToolAvailability::Unavailable)
    }
    fn behavior(&self) -> ToolBehavior {
        if self.capture {
            ToolBehavior::Capture
        } else {
            ToolBehavior::Launch
        }
    }
    fn supports(&self, artifact: &ArtifactNode) -> bool {
        artifact.path.is_file()
            && self
                .formats
                .is_none_or(|formats| artifact.format.is_some_and(|f| formats.contains(&f)))
    }
    fn launch(&self, artifact: &ArtifactNode) -> Result<()> {
        self.launch_at(artifact, None)
    }
    fn accepts_address(&self) -> bool {
        self.address_args.is_some()
    }
    fn launch_at(&self, artifact: &ArtifactNode, address: Option<u64>) -> Result<()> {
        let ToolAvailability::Available(exe) = self.detect() else {
            return Err(HexloraError::Malformed(format!(
                "{} is not installed",
                self.name
            )));
        };
        Command::new(exe)
            .args(self.arguments(address)?)
            .arg(&artifact.path)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|source| HexloraError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        Ok(())
    }
    fn capture(&self, artifact: &ArtifactNode) -> Result<Option<ToolOutput>> {
        self.capture_controlled(artifact, DEFAULT_CAPTURE_TIMEOUT, &|| false)
    }
    fn capture_controlled(
        &self,
        artifact: &ArtifactNode,
        timeout: Duration,
        is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        self.capture_at(artifact, None, timeout, is_cancelled)
    }
    fn capture_at(
        &self,
        artifact: &ArtifactNode,
        address: Option<u64>,
        timeout: Duration,
        is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        if !self.capture {
            return Ok(None);
        }
        let ToolAvailability::Available(exe) = self.detect() else {
            return Err(HexloraError::Malformed(format!(
                "{} is not installed",
                self.name
            )));
        };
        let mut child = Command::new(exe)
            .args(self.arguments(address)?)
            .arg(&artifact.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| HexloraError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            HexloraError::Malformed(format!("{} stdout pipe unavailable", self.name))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            HexloraError::Malformed(format!("{} stderr pipe unavailable", self.name))
        })?;
        let stdout_thread = thread::spawn(move || read_capped(stdout));
        let stderr_thread = thread::spawn(move || read_capped(stderr));
        let started = Instant::now();
        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            if is_cancelled() {
                cancelled = true;
                terminate_child(&mut child, &artifact.path)?;
                break child.wait().map_err(|source| HexloraError::Io {
                    path: artifact.path.clone(),
                    source,
                })?;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                timed_out = true;
                terminate_child(&mut child, &artifact.path)?;
                break child.wait().map_err(|source| HexloraError::Io {
                    path: artifact.path.clone(),
                    source,
                })?;
            }
            let interval = remaining.min(Duration::from_millis(100));
            if let Some(status) =
                child
                    .wait_timeout(interval)
                    .map_err(|source| HexloraError::Io {
                        path: artifact.path.clone(),
                        source,
                    })?
            {
                break status;
            }
        };
        let (stdout, stdout_truncated) = stdout_thread
            .join()
            .map_err(|_| HexloraError::Malformed("stdout reader panicked".into()))?
            .map_err(|source| HexloraError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        let (stderr, stderr_truncated) = stderr_thread
            .join()
            .map_err(|_| HexloraError::Malformed("stderr reader panicked".into()))?
            .map_err(|source| HexloraError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        Ok(Some(ToolOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            truncated: stdout_truncated || stderr_truncated,
            timed_out,
            cancelled,
        }))
    }
}

fn terminate_child(child: &mut std::process::Child, path: &std::path::Path) -> Result<()> {
    child
        .kill()
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|source| HexloraError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn read_capped(reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > MAX_CAPTURE_BYTES;
    bytes.truncate(MAX_CAPTURE_BYTES as usize);
    Ok((bytes, truncated))
}
fn find_command(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(name))
            .find(|p| p.is_file())
    })
}

/// How much code a capture tool is asked to show from a handoff address.
const HANDOFF_WINDOW_BYTES: u64 = 0x200;

/// IDA takes no address on its command line, but `-S` runs a script once the
/// database is open. The script waits for analysis and jumps to the address.
fn ida_address_arguments(address: u64) -> Result<Vec<String>> {
    let directory = std::env::temp_dir().join("hexlora-handoff");
    let io = |path: &std::path::Path, source| HexloraError::Io {
        path: path.to_path_buf(),
        source,
    };
    std::fs::create_dir_all(&directory).map_err(|source| io(&directory, source))?;
    // One script per address; rewriting it is harmless and nothing accumulates.
    let script = directory.join(format!("jump-{address:x}.idc"));
    std::fs::write(
        &script,
        format!("static main() {{\n    auto_wait();\n    jumpto(0x{address:x});\n}}\n"),
    )
    .map_err(|source| io(&script, source))?;
    Ok(vec![format!("-S{}", script.display())])
}

/// Hopper's launcher jumps to an address with `-j`, and takes the file after
/// `-e` like every launch of it.
fn hopper_address_arguments(address: u64) -> Result<Vec<String>> {
    Ok(vec!["-j".into(), format!("0x{address:x}"), "-e".into()])
}
fn objdump_address_arguments(address: u64) -> Result<Vec<String>> {
    Ok(vec![
        "-d".into(),
        format!("--start-address=0x{address:x}"),
        format!(
            "--stop-address=0x{:x}",
            address.saturating_add(HANDOFF_WINDOW_BYTES)
        ),
    ])
}

#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn ExternalTool>>,
}
impl ToolRegistry {
    pub fn standard() -> Self {
        let mut r = Self::default();
        r.register(
            CommandTool::new("otool", "otool", &["/usr/bin/otool", "otool"], &["-L"])
                .with_formats(&[FileFormat::MachO, FileFormat::FatMachO])
                .with_capture(),
        );
        r.register(
            CommandTool::new(
                "codesign",
                "codesign",
                &["/usr/bin/codesign", "codesign"],
                &["-dvvv"],
            )
            .with_formats(&[FileFormat::MachO, FileFormat::FatMachO])
            .with_capture(),
        );
        r.register(CommandTool::new("ghidra", "Ghidra", &["ghidraRun"], &[]));
        r.register(
            CommandTool::new(
                "ida",
                "IDA",
                &[
                    "/Applications/IDA Professional 9.2.app/Contents/MacOS/ida64",
                    "/Applications/IDA Professional 9.2.app/Contents/MacOS/ida",
                    "/Applications/IDA Professional 9.1.app/Contents/MacOS/ida64",
                    "/Applications/IDA Professional 9.1.app/Contents/MacOS/ida",
                    "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida64",
                    "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida",
                    "ida64",
                    "ida",
                ],
                &[],
            )
            .with_address_args(ida_address_arguments),
        );
        r.register(CommandTool::new(
            "binary-ninja",
            "Binary Ninja",
            &[
                "/Applications/Binary Ninja.app/Contents/MacOS/binaryninja",
                "binaryninja",
            ],
            &[],
        ));
        r.register(
            CommandTool::new(
                "hopper",
                "Hopper",
                &[
                    "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper",
                    "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
                    "hopper",
                ],
                // The launcher opens nothing without `-e`; given a bare path it
                // only prints its usage.
                &["-e"],
            )
            .with_address_args(hopper_address_arguments),
        );
        r.register(
            CommandTool::new("radare2", "radare2", &["r2", "radare2"], &[])
                .with_address_args(|address| Ok(vec!["-s".into(), format!("0x{address:x}")])),
        );
        r.register(CommandTool::new("cutter", "Cutter", &["cutter"], &[]));
        r.register(
            CommandTool::new("readelf", "readelf", &["readelf", "eu-readelf"], &["-a"])
                .with_formats(&[FileFormat::Elf])
                .with_capture(),
        );
        r.register(
            CommandTool::new("objdump", "objdump", &["objdump", "llvm-objdump"], &["-x"])
                .with_formats(&[FileFormat::Pe, FileFormat::Elf, FileFormat::MachO])
                .with_capture()
                .with_address_args(objdump_address_arguments),
        );
        r.register(
            CommandTool::new("dumpbin", "dumpbin", &["dumpbin.exe", "dumpbin"], &["/all"])
                .with_formats(&[FileFormat::Pe])
                .with_capture(),
        );
        r.register(
            CommandTool::new(
                "sigcheck",
                "Sigcheck",
                &["sigcheck64.exe", "sigcheck.exe", "sigcheck"],
                &["-a", "-h", "-i", "-nobanner"],
            )
            .with_formats(&[FileFormat::Pe])
            .with_capture(),
        );
        r.register(
            CommandTool::new("nm", "nm", &["nm", "llvm-nm"], &[])
                .with_formats(&[
                    FileFormat::Pe,
                    FileFormat::Elf,
                    FileFormat::MachO,
                    FileFormat::FatMachO,
                    FileFormat::Archive,
                ])
                .with_capture(),
        );
        r.register(CommandTool::new("strings", "strings", &["strings"], &[]).with_capture());
        r
    }
    pub fn register(&mut self, tool: impl ExternalTool + 'static) {
        self.tools.insert(tool.id(), Box::new(tool));
    }
    pub fn iter(&self) -> impl Iterator<Item = &dyn ExternalTool> {
        self.tools.values().map(Box::as_ref)
    }
    pub fn get(&self, id: &str) -> Option<&dyn ExternalTool> {
        self.tools.get(id).map(Box::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_is_extensible() {
        let r = ToolRegistry::standard();
        assert!(r.get("otool").is_some());
        assert_eq!(r.get("otool").unwrap().behavior(), ToolBehavior::Capture);
        assert_eq!(r.get("ghidra").unwrap().behavior(), ToolBehavior::Launch);
        for id in [
            "ghidra",
            "ida",
            "binary-ninja",
            "hopper",
            "dumpbin",
            "sigcheck",
        ] {
            assert!(r.get(id).is_some(), "missing standard tool {id}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_tool_is_terminated_at_time_limit() {
        let artifact = ArtifactNode::new(
            "artifact",
            std::env::current_exe().expect("current executable"),
            hexlora_core::ArtifactKind::Executable,
        );
        let tool = CommandTool::new(
            "slow-test",
            "slow test",
            &["/bin/sh"],
            &["-c", "exec sleep 10"],
        )
        .with_capture();
        let started = Instant::now();
        let output = tool
            .capture_controlled(&artifact, Duration::from_millis(30), &|| false)
            .expect("capture")
            .expect("output");
        assert!(output.timed_out);
        assert!(!output.cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn handoff_addresses_reach_the_tools_that_accept_them() {
        let registry = ToolRegistry::standard();
        for (id, accepts) in [
            ("radare2", true),
            ("ida", true),
            ("objdump", true),
            ("ghidra", false),
            ("binary-ninja", false),
            ("hopper", true),
            ("cutter", false),
            ("strings", false),
        ] {
            assert_eq!(
                registry.get(id).expect("registered tool").accepts_address(),
                accepts,
                "{id}"
            );
        }
        let radare = CommandTool::new("r", "r", &["r2"], &["-A"])
            .with_address_args(|address| Ok(vec!["-s".into(), format!("0x{address:x}")]));
        assert_eq!(radare.arguments(None).unwrap(), ["-A"]);
        assert_eq!(
            hopper_address_arguments(0x1000).unwrap(),
            ["-j", "0x1000", "-e"]
        );
        assert_eq!(
            radare.arguments(Some(0x1_4000_1060)).unwrap(),
            ["-s", "0x140001060"]
        );
        assert_eq!(
            objdump_address_arguments(0x1000).unwrap(),
            ["-d", "--start-address=0x1000", "--stop-address=0x1200"]
        );
        // A tool without address support ignores the address.
        let plain = CommandTool::new("p", "p", &["p"], &["-x"]);
        assert_eq!(plain.arguments(Some(0x1000)).unwrap(), ["-x"]);

        let ida = ida_address_arguments(0x401000).unwrap();
        let script = ida[0].strip_prefix("-S").expect("script argument");
        let text = std::fs::read_to_string(script).expect("handoff script exists");
        assert!(text.contains("auto_wait();") && text.contains("jumpto(0x401000);"));
        let _ = std::fs::remove_file(script);
    }

    #[test]
    fn objdump_captures_only_the_code_at_a_handoff_address() {
        let registry = ToolRegistry::standard();
        let objdump = registry.get("objdump").expect("objdump is registered");
        if matches!(objdump.detect(), ToolAvailability::Unavailable) {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/binaries/fixture-x86_64.elf");
        let mut node = ArtifactNode::new(
            "fixture-x86_64.elf",
            path.clone(),
            hexlora_core::ArtifactKind::Executable,
        );
        node.format = Some(FileFormat::Elf);
        // The entry point of the fixture, read from its ELF header.
        let bytes = std::fs::read(&path).expect("read fixture");
        let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let output = objdump
            .capture_at(&node, Some(entry), DEFAULT_CAPTURE_TIMEOUT, &|| false)
            .expect("objdump runs")
            .expect("objdump captures");
        assert!(output.success, "{}", output.stderr);
        assert!(
            output.stdout.contains(&format!("{entry:x}")),
            "{}",
            output.stdout
        );
        // The usual header dump is replaced by a disassembly of that window.
        assert!(output.stdout.contains("Disassembly"), "{}", output.stdout);
        assert!(
            !output.stdout.contains("Program Header"),
            "{}",
            output.stdout
        );
    }
}
