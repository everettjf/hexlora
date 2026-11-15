//! Hostile, damaged and oversized inputs must degrade to a partial but usable
//! artifact. None of them may abort discovery, hang, or overflow a worker stack.

use super::*;
use std::io::Write;

fn open(path: &Path) -> ArtifactNode {
    open_artifact(path, &CancellationToken::default()).expect("artifact should open")
}

fn find<'a>(root: &'a ArtifactNode, name: &str) -> Option<&'a ArtifactNode> {
    if root.name == name {
        return Some(root);
    }
    root.children.iter().find_map(|child| find(child, name))
}

/// Background tasks in the desktop application run on 512 KiB worker stacks.
fn on_worker_stack<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(work)
        .expect("spawn worker")
        .join()
        .expect("worker must not overflow its stack")
}

#[test]
fn damaged_zip_opens_as_a_plain_file_with_a_reason() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("damaged.zip");
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.extend(std::iter::repeat_n(0xa5u8, 4096));
    std::fs::write(&path, bytes).unwrap();

    let root = open(&path);
    assert!(root.children.is_empty());
    assert_eq!(root.size, 4100);
    assert!(
        root.properties
            .get("Archive Members Unavailable")
            .is_some_and(|reason| reason.contains("ZIP"))
    );
    // The file itself stays readable for Hex, strings and hashing.
    let reader = ArtifactReader::open(&root).unwrap();
    assert_eq!(reader.read_prefix(4).unwrap(), b"PK\x03\x04");
}

#[test]
fn hostile_zip_members_are_counted_instead_of_failing_the_archive() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hostile.zip");
    let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    archive.start_file("../escape.txt", options).unwrap();
    archive.write_all(b"x").unwrap();
    archive
        .start_file(format!("{}leaf.txt", "d/".repeat(MAX_DEPTH + 8)), options)
        .unwrap();
    archive.write_all(b"x").unwrap();
    archive.start_file("kept/readme.txt", options).unwrap();
    archive.write_all(b"hello").unwrap();
    archive.finish().unwrap();

    let root = open(&path);
    let kept = find(&root, "readme.txt").expect("ordinary member stays listed");
    assert_eq!(
        ArtifactReader::open(kept).unwrap().read_all(16).unwrap(),
        b"hello"
    );
    assert!(find(&root, "escape.txt").is_none());
    assert!(find(&root, "leaf.txt").is_none());
    assert!(
        root.properties
            .get("Unsafe Member Paths")
            .is_some_and(|note| note.starts_with("1 "))
    );
    assert!(
        root.properties
            .get("Deeply Nested Members")
            .is_some_and(|note| note.starts_with("1 "))
    );
}

#[test]
fn zip_bomb_member_is_listed_but_never_decompressed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bomb.zip");
    let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
    archive
        .start_file(
            "zeros.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    let block = vec![0u8; 1024 * 1024];
    for _ in 0..128 {
        archive.write_all(&block).unwrap();
    }
    archive
        .start_file("note.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(b"fine").unwrap();
    archive.finish().unwrap();

    let root = open(&path);
    let bomb = find(&root, "zeros.bin").expect("the member stays visible");
    assert_eq!(bomb.size, 128 * 1024 * 1024);
    assert!(bomb.properties.contains_key("Read Blocked"));
    assert!(matches!(
        ArtifactReader::open(bomb),
        Err(HexloraError::Limit(_))
    ));
    assert!(root.properties.contains_key("Read-Blocked Members"));
    let note = find(&root, "note.txt").unwrap();
    assert_eq!(
        ArtifactReader::open(note).unwrap().read_all(16).unwrap(),
        b"fine"
    );
}

#[test]
fn archives_with_many_members_are_read_without_reparsing_the_directory() {
    const MEMBERS: usize = 20_000;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("many.zip");
    let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for index in 0..MEMBERS {
        // One flat directory also exercises the per-parent child index.
        archive
            .start_file(format!("flat/f{index}.txt"), options)
            .unwrap();
        archive.write_all(b"x").unwrap();
    }
    archive.finish().unwrap();

    let started = std::time::Instant::now();
    let root = open(&path);
    let files = root.files().collect::<Vec<_>>();
    assert_eq!(files.len(), MEMBERS);
    for node in &files {
        assert_eq!(
            ArtifactReader::open(node).unwrap().read_all(8).unwrap(),
            b"x"
        );
    }
    // Reparsing a 20,000-entry central directory per member took minutes.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "reading every member took {:?}",
        started.elapsed()
    );
}

#[test]
fn replaced_zip_is_not_served_from_the_directory_cache() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replaced.zip");
    let write = |name: &str, contents: &[u8]| {
        let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(contents).unwrap();
        archive.finish().unwrap();
    };
    write("first.txt", b"one");
    let first = open(&path);
    assert!(find(&first, "first.txt").is_some());

    write("second-member.txt", b"two two");
    let second = open(&path);
    assert!(find(&second, "first.txt").is_none());
    let member = find(&second, "second-member.txt").unwrap();
    assert_eq!(
        ArtifactReader::open(member).unwrap().read_all(16).unwrap(),
        b"two two"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_and_special_entries_do_not_hide_the_rest_of_a_directory() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let root_path = directory.path().join("tree");
    std::fs::create_dir(&root_path).unwrap();
    std::fs::write(root_path.join("readable.txt"), b"hello").unwrap();
    let locked = root_path.join("locked.bin");
    std::fs::write(&locked, b"secret").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::os::unix::fs::symlink(".", root_path.join("loop")).unwrap();
    let fifo = root_path.join("pipe");
    let made_fifo = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|status| status.success());

    let root = open(&root_path);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(find(&root, "readable.txt").is_some());
    assert!(find(&root, "loop").is_none());
    // Root ignores file modes, so the placeholder only appears for other users.
    if File::open(&locked).is_ok() && std::fs::metadata("/").is_ok() {
        let placeholder = find(&root, "locked.bin").expect("unreadable file stays listed");
        if placeholder.properties.contains_key("Read Error") {
            assert_eq!(placeholder.size, 6);
            assert!(root.properties.contains_key("Unreadable Entries"));
        }
    }
    if made_fifo {
        assert!(find(&root, "pipe").is_none());
        assert!(root.properties.contains_key("Special Files Skipped"));
        // Opening a FIFO directly would block forever waiting for a writer.
        assert!(matches!(
            open_artifact(&fifo, &CancellationToken::default()),
            Err(HexloraError::Malformed(_))
        ));
    }
}

#[test]
fn deeply_nested_plist_is_rejected_on_a_worker_stack() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("Deep.plist");
    let depth = 50_000;
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">{}{}</plist>",
        "<array>".repeat(depth),
        "</array>".repeat(depth)
    );
    std::fs::write(&path, &document).unwrap();

    let result = on_worker_stack(move || {
        let parsed = parse_plist(document.as_bytes()).map(|_| ());
        let node = build_file_node(&path).unwrap();
        (parsed, inspect_metadata(&node).map(|_| ()))
    });
    assert!(matches!(result.0, Err(HexloraError::Limit(_))));
    assert!(matches!(result.1, Err(HexloraError::Limit(_))));
}

#[test]
fn ordinary_nested_plist_still_parses() {
    let document = format!(
        "<?xml version=\"1.0\"?><plist version=\"1.0\">{}<string>leaf</string>{}</plist>",
        "<array>".repeat(MAX_PLIST_DEPTH),
        "</array>".repeat(MAX_PLIST_DEPTH)
    );
    assert!(parse_plist(document.as_bytes()).is_ok());
}

#[test]
fn wide_json_is_flattened_up_to_the_entry_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wide.json");
    let body = (0..MAX_FLATTENED_ENTRIES * 3)
        .map(|index| format!("\"k{index}\":{index}"))
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(&path, format!("{{{body}}}")).unwrap();
    let node = build_file_node(&path).unwrap();
    let metadata = inspect_metadata(&node).unwrap();
    assert_eq!(metadata.len(), MAX_FLATTENED_ENTRIES);
}
