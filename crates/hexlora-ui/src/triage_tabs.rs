//! The Capabilities, Disassembly, and YARA inspector tabs.

use super::*;
use hexlora_analysis::{
    CodeListing, CodeView, EndReason, FlowKind, Limits, MAX_LISTING_INSTRUCTIONS,
    apply_capability_strings, scan_capability_strings,
};

pub(super) const FUNCTIONS_TABLE: &str = "Functions";
pub(super) const LISTING_TABLE: &str = "Disassembly";
pub(super) const YARA_TABLE: &str = "YARA Matches";

const INITIAL_LISTING_INSTRUCTIONS: usize = 2_000;
/// Most rule matches kept from one scan of an artifact.
const MAX_YARA_HITS: usize = 100_000;
/// Disassembly history kept for the Back button.
const MAX_CODE_HISTORY: usize = 256;

/// Where to start listing once a code view has loaded.
#[derive(Clone, Copy)]
pub(super) enum CodeTarget {
    /// An address as the listing shows it.
    Address(u64),
    /// An address from one of the file's own tables: an RVA for PE.
    TableAddress(u64),
}

#[derive(Default)]
pub(super) struct CodeState {
    view: Option<Arc<CodeView>>,
    /// A load was attempted for the selected file and slice.
    pub(super) loaded: bool,
    error: Option<SharedString>,
    listing: Option<Arc<CodeListing>>,
    history: Vec<u64>,
    show_functions: bool,
    symbol_file: Option<PathBuf>,
    pending: Option<CodeTarget>,
    limit: usize,
    /// Function indices matching the search text, cached per query.
    filtered: std::cell::RefCell<Option<(String, Arc<Vec<usize>>)>>,
}

pub(super) struct YaraHit {
    path: PathBuf,
    rule: String,
    tags: String,
    severity: String,
    occurrences: String,
    description: String,
}

#[derive(Default)]
pub(super) struct YaraState {
    rules_path: Option<PathBuf>,
    hits: Arc<Vec<YaraHit>>,
    /// A scan of the open artifact has finished.
    pub(super) scanned: bool,
    /// The task generation the scan runs under, to tell a running scan from
    /// one that another task replaced.
    generation: u64,
    summary: SharedString,
    /// Rules to scan with as soon as the artifact being opened is ready.
    queued: Option<PathBuf>,
}

impl YaraState {
    pub(super) fn take_queued(&mut self) -> Option<PathBuf> {
        self.queued.take()
    }
}

/// Something a selected table row can open.
#[derive(Clone)]
pub(super) enum RowAction {
    /// List code at an address from a symbol table.
    Disassemble(u64),
    /// List code at a branch or call destination.
    Follow(u64),
    ShowInHex {
        offset: u64,
        length: u64,
    },
    /// Select the file a match was found in.
    OpenFile(PathBuf),
}

impl RowAction {
    pub(super) fn button(self, cx: &mut Context<HexloraApp>) -> AnyElement {
        match self {
            Self::Disassemble(address) => toolbar_button("row-disassemble", "Disassemble")
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.open_disassembly(CodeTarget::TableAddress(address), cx);
                })),
            Self::Follow(target) => toolbar_button("row-follow", "Follow Target").on_click(
                cx.listener(move |this, _, _, cx| {
                    this.open_disassembly(CodeTarget::Address(target), cx);
                }),
            ),
            Self::ShowInHex { offset, length } => toolbar_button("row-hex", "Show in Hex")
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.hex_offset = offset;
                    this.hex_selection = Some((offset, offset + length));
                    this.tab = InspectorTab::Hex;
                    this.row_selection = None;
                    this.status = format!("Instruction bytes at file offset 0x{offset:x}").into();
                    cx.notify();
                })),
            Self::OpenFile(path) => toolbar_button("row-open-file", "Open File")
                .on_click(cx.listener(move |this, _, _, cx| this.open_matched_file(&path, cx))),
        }
        .into_any_element()
    }
}

fn toolbar_button(id: &'static str, label: impl Into<SharedString>) -> Button {
    Button::new(id).label(label).xsmall().compact()
}

fn note(text: impl Into<SharedString>, color: u32) -> impl IntoElement {
    div().text_xs().text_color(rgb(color)).child(text.into())
}

impl HexloraApp {
    // ---- Capabilities ----------------------------------------------------

    /// Searches the selected file for the strings capability rules look for
    /// and recomputes its capabilities with them.
    pub(super) fn load_capability_strings(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node().filter(|node| node.is_file()).cloned() else {
            return;
        };
        let Some(analysis) = self.analysis.clone() else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.status = format!("Searching {} for capability evidence…", node.name).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let strings = scan_capability_strings(&node, &cancellation)?;
                    let mut analysis = (*analysis).clone();
                    apply_capability_strings(&mut analysis, &strings);
                    Ok::<_, hexlora_core::HexloraError>(analysis)
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(analysis) => {
                        let count = analysis.capabilities.len();
                        this.analysis = Some(Arc::new(analysis));
                        this.capability_strings_loaded = true;
                        this.status = format!("{count} capabilities inferred").into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "Capability evidence search incomplete".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }

    pub(super) fn render_capabilities(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let capabilities = self
            .current_analysis()
            .map(|analysis| analysis.capabilities.clone())
            .unwrap_or_default();
        let basis = if self.capability_strings_loaded {
            "Inferred from the import table and strings embedded in the file."
        } else if self.loading {
            "Inferred from the import table. Embedded strings are being searched…"
        } else {
            "Inferred from the import table only; embedded strings were not searched."
        };
        div()
            .flex_1()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Capabilities"))
            .child(note(
                format!(
                    "{basis} A capability means the binary appears able to do something; it does not show that it does."
                ),
                MUTED,
            ))
            .when(capabilities.is_empty(), |panel| {
                panel.child(info_panel(
                    "No capabilities inferred",
                    "None of Hexlora's capability rules matched this binary's imports or strings. Functions resolved at run time or called by ordinal are not visible to these rules.",
                ))
            })
            .when(!capabilities.is_empty(), |panel| {
                panel.child(table_panel(
                    "Capabilities",
                    &[
                        "Capability",
                        "Group",
                        "Severity",
                        "Confidence",
                        "Evidence",
                        "Rule ID",
                    ],
                    capabilities
                        .iter()
                        .map(|capability| {
                            vec![
                                capability.name.clone(),
                                capability.group.clone(),
                                format!("{:?}", capability.severity),
                                capability.confidence.label().to_string(),
                                capability.evidence.join(" · "),
                                format!("capability.{}", capability.id),
                            ]
                        })
                        .collect(),
                    cx,
                ))
            })
    }

    /// Report sections for the selected binary's capabilities and for the
    /// most recent YARA scan.
    pub(super) fn triage_report_sections(&self) -> Vec<ReportSection> {
        let mut sections = Vec::new();
        if let Some(analysis) = self.current_analysis()
            && !analysis.capabilities.is_empty()
        {
            sections.push(ReportSection {
                title: "Selected Object Capabilities".into(),
                blocks: vec![
                    ReportBlock::Paragraph(
                        if self.capability_strings_loaded {
                            "Inferred from the import table and embedded strings. A capability means the binary appears able to do something; it does not show that it does."
                        } else {
                            "Inferred from the import table only; embedded strings were not searched. A capability means the binary appears able to do something; it does not show that it does."
                        }
                        .into(),
                    ),
                    ReportBlock::Table {
                        headers: vec![
                            "Capability".into(),
                            "Group".into(),
                            "Severity".into(),
                            "Confidence".into(),
                            "Evidence".into(),
                            "Rule ID".into(),
                        ],
                        rows: analysis
                            .capabilities
                            .iter()
                            .map(|capability| {
                                vec![
                                    capability.name.clone(),
                                    capability.group.clone(),
                                    format!("{:?}", capability.severity),
                                    capability.confidence.label().to_string(),
                                    capability.evidence.join("; "),
                                    format!("capability.{}", capability.id),
                                ]
                            })
                            .collect(),
                    },
                ],
            });
        }
        if self.yara.scanned {
            sections.push(ReportSection {
                title: "YARA Rule Matches".into(),
                blocks: vec![
                    ReportBlock::KeyValues(vec![
                        (
                            "Rules".into(),
                            self.yara
                                .rules_path
                                .as_ref()
                                .map(|path| path.display().to_string())
                                .unwrap_or_default(),
                        ),
                        ("Scan".into(), self.yara.summary.to_string()),
                    ]),
                    ReportBlock::Table {
                        headers: vec![
                            "File".into(),
                            "Rule".into(),
                            "Severity".into(),
                            "Tags".into(),
                            "Matched".into(),
                            "Description".into(),
                        ],
                        rows: self
                            .yara
                            .hits
                            .iter()
                            .map(|hit| {
                                vec![
                                    hit.path.display().to_string(),
                                    hit.rule.clone(),
                                    hit.severity.clone(),
                                    hit.tags.clone(),
                                    hit.occurrences.clone(),
                                    hit.description.clone(),
                                ]
                            })
                            .collect(),
                    },
                ],
            });
        }
        sections
    }

    // ---- Disassembly -----------------------------------------------------

    pub(super) fn reset_code(&mut self) {
        // The chosen symbol file belongs to the binary it was chosen for.
        self.code = CodeState::default();
    }

    /// The architecture slice the code view is for, when the file has slices.
    fn code_slice(&self) -> Option<usize> {
        self.analysis
            .as_ref()
            .filter(|analysis| !analysis.slice_analyses.is_empty())
            .map(|_| self.active_slice.unwrap_or(0))
    }

    /// Loads the code view for a plain visit to the tab, starting at the
    /// entry point rather than wherever an abandoned request pointed.
    pub(super) fn load_code_view(&mut self, cx: &mut Context<Self>) {
        self.code.pending = None;
        self.load_code_view_at_pending(cx);
    }

    fn load_code_view_at_pending(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node().filter(|node| node.is_file()).cloned() else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        let slice = self.code_slice();
        let symbol_file = self.code.symbol_file.clone();
        self.code.loaded = false;
        self.code.error = None;
        self.loading = true;
        self.status = format!("Finding functions in {}…", node.name).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    CodeView::open(&node, slice, symbol_file.as_deref(), &cancellation)
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                this.code.loaded = true;
                match result {
                    Ok(view) => {
                        let functions = view.functions().len();
                        this.status = match view.symbol_summary() {
                            Some(symbols) => format!(
                                "{functions} functions · {} symbols loaded",
                                symbols.format.label()
                            ),
                            None => format!("{functions} functions found"),
                        }
                        .into();
                        let target = this
                            .code
                            .pending
                            .take()
                            .map(|target| match target {
                                CodeTarget::Address(address) => address,
                                CodeTarget::TableAddress(address) => view
                                    .program
                                    .code_address_from_table(address)
                                    .unwrap_or_else(|| view.program.table_address(address)),
                            })
                            .or(view.program.entry);
                        this.code.view = Some(Arc::new(view));
                        this.code.limit = INITIAL_LISTING_INSTRUCTIONS;
                        match target {
                            Some(address) => this.show_code_at(address, false, cx),
                            None => this.code.show_functions = true,
                        }
                    }
                    Err(error) => {
                        this.code.error = Some(error.to_string().into());
                        this.status = "Disassembly unavailable".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }

    /// Lists code at `address`. Listings are small and bounded, so this runs
    /// directly rather than as a background task.
    pub(super) fn show_code_at(&mut self, address: u64, remember: bool, cx: &mut Context<Self>) {
        let Some(view) = self.code.view.clone() else {
            return;
        };
        let limit = self.code.limit.clamp(1, MAX_LISTING_INSTRUCTIONS);
        match view.listing(
            address,
            Limits {
                max_instructions: limit,
            },
        ) {
            Ok(listing) => {
                if remember
                    && let Some(current) = &self.code.listing
                    && current.start != address
                {
                    self.code.history.push(current.start);
                    if self.code.history.len() > MAX_CODE_HISTORY {
                        self.code.history.remove(0);
                    }
                }
                self.status = format!(
                    "{} · {} instructions",
                    listing
                        .function
                        .clone()
                        .unwrap_or_else(|| format!("0x{address:x}")),
                    listing.lines.len()
                )
                .into();
                self.code.listing = Some(Arc::new(listing));
                self.code.show_functions = false;
                self.row_selection = None;
            }
            Err(error) => self.error = Some(error.to_string().into()),
        }
        cx.notify();
    }

    /// Opens the Disassembly tab at an address taken from another view.
    pub(super) fn open_disassembly(&mut self, target: CodeTarget, cx: &mut Context<Self>) {
        self.tab = InspectorTab::Disassembly;
        self.row_selection = None;
        match self.code.view.clone() {
            Some(view) => {
                let address = match target {
                    CodeTarget::Address(address) => address,
                    CodeTarget::TableAddress(address) => view
                        .program
                        .code_address_from_table(address)
                        .unwrap_or_else(|| view.program.table_address(address)),
                };
                self.code.limit = INITIAL_LISTING_INSTRUCTIONS;
                self.show_code_at(address, true, cx);
            }
            None => {
                self.code.pending = Some(target);
                self.load_code_view_at_pending(cx);
            }
        }
    }

    fn choose_debug_symbols(&mut self, cx: &mut Context<Self>) {
        // The dialog is asynchronous; the symbols are for the file selected
        // when it was opened, not whatever is selected when it closes.
        let selected = self.selected;
        self.prompt_path(
            rfd::AsyncFileDialog::new().set_title("Choose a PDB, dSYM, or debug file"),
            DialogKind::File,
            cx,
            move |this, path, cx| {
                if this.selected != selected || this.loading {
                    this.status =
                        "Symbols not loaded: the selection changed or a task is running".into();
                    cx.notify();
                    return;
                }
                let pending = this
                    .code
                    .listing
                    .as_ref()
                    .map(|listing| CodeTarget::Address(listing.start));
                this.code = CodeState {
                    symbol_file: Some(path),
                    pending,
                    ..CodeState::default()
                };
                this.load_code_view_at_pending(cx);
            },
        );
    }

    /// The address an external tool should open at: the selected line of the
    /// listing, or its start, while the Disassembly tab is showing one.
    pub(super) fn handoff_address(&self) -> Option<u64> {
        if self.tab != InspectorTab::Disassembly || self.code.show_functions {
            return None;
        }
        let listing = self.code.listing.as_ref()?;
        self.row_selection
            .as_deref()
            .and_then(|selection| self.selected_code_line(selection))
            .map(|line| line.address)
            .or(Some(listing.start))
    }

    /// The listing line a selected Disassembly row stands for.
    fn selected_code_line(&self, selection: &RowSelection) -> Option<&hexlora_analysis::CodeLine> {
        (selection.table == LISTING_TABLE)
            .then(|| self.code.listing.as_ref()?.lines.get(selection.index))
            .flatten()
    }

    /// Runs when a table row is clicked, for tables whose rows open something.
    pub(super) fn row_activated(&mut self, cx: &mut Context<Self>) {
        let Some(selection) = self.row_selection.clone() else {
            return;
        };
        if selection.table == FUNCTIONS_TABLE
            && let Some(address) = selection
                .values
                .first()
                .and_then(|value| parse_hex_offset(value))
        {
            self.code.limit = INITIAL_LISTING_INSTRUCTIONS;
            self.show_code_at(address, true, cx);
        }
    }

    /// What the selected row can open, beyond being copied.
    pub(super) fn row_actions(&self) -> Vec<RowAction> {
        let Some(selection) = self.row_selection.as_deref() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        // Symbol tables put the address in their second column.
        // Address zero is an undefined symbol. Once the image layout is known,
        // the action is offered only for addresses that are code.
        if matches!(selection.table, "Symbols" | "Exports")
            && self.tabs().contains(&InspectorTab::Disassembly)
            && let Some(address) = selection
                .values
                .get(1)
                .and_then(|value| parse_hex_offset(value))
                .filter(|address| *address != 0)
            && self
                .code
                .view
                .as_ref()
                .is_none_or(|view| view.program.code_address_from_table(address).is_some())
        {
            actions.push(RowAction::Disassemble(address));
        }
        if let Some(line) = self.selected_code_line(selection)
            && let Some(view) = &self.code.view
        {
            if let Some(target) = line.target.filter(|target| view.program.is_code(*target)) {
                actions.push(RowAction::Follow(target));
            }
            if let Some(offset) = view.file_offset(line.address) {
                actions.push(RowAction::ShowInHex {
                    offset,
                    length: (line.bytes.len() / 2).max(1) as u64,
                });
            }
        }
        if selection.table == YARA_TABLE
            && let Some(hit) = self.yara.hits.get(selection.index)
        {
            actions.push(RowAction::OpenFile(hit.path.clone()));
        }
        actions
    }

    /// Indices of the functions matching the search text.
    fn filtered_functions(&self, view: &CodeView) -> Arc<Vec<usize>> {
        let query = self.query.trim().to_lowercase();
        let mut cache = self.code.filtered.borrow_mut();
        if let Some((cached, indices)) = cache.as_ref()
            && *cached == query
        {
            return indices.clone();
        }
        let indices: Vec<usize> = view
            .functions()
            .iter()
            .enumerate()
            .filter(|(_, function)| {
                query.is_empty()
                    || function.display_name().to_lowercase().contains(&query)
                    || function
                        .name
                        .as_ref()
                        .is_some_and(|name| name.to_lowercase().contains(&query))
                    || format!("0x{:x}", function.address).contains(&query)
                    // The table prints addresses zero-padded.
                    || fmt_addr(function.address).contains(&query)
            })
            .map(|(index, _)| index)
            .collect();
        let indices = Arc::new(indices);
        *cache = Some((query, indices.clone()));
        indices
    }

    pub(super) fn render_disassembly(&self, cx: &mut Context<Self>) -> AnyElement {
        if let Some(error) = &self.code.error {
            return info_panel("Disassembly unavailable", error.clone()).into_any_element();
        }
        let Some(view) = self.code.view.clone() else {
            return info_panel(
                "Disassembly",
                if self.loading {
                    "Reading the image layout, function starts, and debug symbols…"
                } else {
                    "Open this tab again to read the image's functions."
                },
            )
            .into_any_element();
        };
        let program = &view.program;
        let listing = self.code.listing.clone();
        let show_functions = self.code.show_functions || listing.is_none();
        let query = self.query.trim().to_string();
        let go_target = (!query.is_empty())
            .then(|| program.resolve(&query))
            .flatten();
        let can_load_more = listing.as_ref().is_some_and(|listing| {
            listing.end == EndReason::InstructionLimit && self.code.limit < MAX_LISTING_INSTRUCTIONS
        });

        let mut summary = format!(
            "{} · {} functions known{}",
            program.architecture.label(),
            program.functions.len(),
            if program.functions_truncated {
                " (list truncated)"
            } else {
                ""
            }
        );
        if program.relative_tables {
            summary.push_str(&format!(" · image base 0x{:x}", program.image_base));
        }
        let symbols = match (view.symbol_summary(), &view.symbol_error) {
            (Some(symbols), _) => format!(
                "{} symbols from {} · {} functions · {} source lines",
                symbols.format.label(),
                symbols.path.display(),
                symbols.functions,
                symbols.line_records
            ),
            (None, Some(error)) => format!("Debug symbols not used: {error}"),
            (None, None) => "No debug symbols found in or beside this file.".into(),
        };
        let symbols_failed = view.symbol_summary().is_none() && view.symbol_error.is_some();

        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .child(panel_title(match (&listing, show_functions) {
                (Some(listing), false) => format!(
                    "Disassembly · {}",
                    listing
                        .function
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", listing.start))
                ),
                _ => "Disassembly · functions".to_string(),
            }))
            .child(div().flex_1())
            .child(
                toolbar_button(
                    "code-toggle",
                    if show_functions {
                        "Listing"
                    } else {
                        "Functions"
                    },
                )
                .disabled(listing.is_none())
                .on_click(cx.listener(|this, _, _, cx| {
                    this.code.show_functions = !this.code.show_functions;
                    this.row_selection = None;
                    cx.notify();
                })),
            )
            .when_some(program.entry, |toolbar, entry| {
                toolbar.child(
                    toolbar_button("code-entry", "Entry Point").on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.code.limit = INITIAL_LISTING_INSTRUCTIONS;
                            this.show_code_at(entry, true, cx);
                        },
                    )),
                )
            })
            .child(
                toolbar_button("code-back", "Back")
                    .disabled(self.code.history.is_empty())
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(previous) = this.code.history.pop() {
                            this.code.limit = INITIAL_LISTING_INSTRUCTIONS;
                            this.show_code_at(previous, false, cx);
                        }
                    })),
            )
            .child(
                toolbar_button("code-go", "Go to Search Text")
                    .disabled(go_target.is_none())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(address) = go_target {
                            this.code.limit = INITIAL_LISTING_INSTRUCTIONS;
                            this.show_code_at(address, true, cx);
                        }
                    })),
            )
            .when(can_load_more, |toolbar| {
                toolbar.child(
                    toolbar_button("code-more", "Load More").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.code.limit = (this.code.limit * 4).min(MAX_LISTING_INSTRUCTIONS);
                            if let Some(start) = this.code.listing.as_ref().map(|l| l.start) {
                                this.show_code_at(start, false, cx);
                            }
                        },
                    )),
                )
            })
            .when_some(
                listing.clone().filter(|_| !show_functions),
                |toolbar, listing| {
                    toolbar.child(toolbar_button("code-copy", "Copy Listing").on_click(
                        cx.listener(move |this, _, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(listing.to_text()));
                            this.status = "Listing copied to the clipboard".into();
                            cx.notify();
                        }),
                    ))
                },
            )
            .child(
                toolbar_button("code-symbols", "Load Symbols…")
                    .on_click(cx.listener(|this, _, _, cx| this.choose_debug_symbols(cx))),
            );

        let body = if show_functions {
            let indices = self.filtered_functions(&view);
            let total = indices.len();
            let functions = view.clone();
            lazy_table_panel(
                FUNCTIONS_TABLE,
                &["Address", "Size", "Name", "Found by"],
                total,
                move |row| {
                    let function = &functions.functions()[indices[row]];
                    vec![
                        fmt_addr(function.address),
                        function
                            .size
                            .map(|size| size.to_string())
                            .unwrap_or_default(),
                        function.display_name(),
                        function.source.label().to_string(),
                    ]
                },
                cx,
            )
        } else {
            let listing = listing.clone().expect("a listing is shown");
            let total = listing.lines.len();
            let start = listing.start;
            keyed_table_panel(
                LISTING_TABLE,
                start,
                &["Address", "Bytes", "Instruction", "Refers to", "Source"],
                total,
                move |row| {
                    let line = &listing.lines[row];
                    // Name the source line only where it changes.
                    let source = line.source_file.as_deref().zip(line.source_line);
                    let previous = row
                        .checked_sub(1)
                        .and_then(|index| listing.lines.get(index))
                        .and_then(|line| line.source_file.as_deref().zip(line.source_line));
                    let source = source
                        .filter(|source| Some(*source) != previous)
                        .map(|(file, number)| {
                            let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
                            format!("{name}:{number}")
                        })
                        .unwrap_or_default();
                    vec![
                        fmt_addr(line.address),
                        line.bytes.clone(),
                        match line.flow {
                            FlowKind::Invalid => format!("{} (not an instruction)", line.text),
                            _ => line.text.clone(),
                        },
                        line.comment.clone().unwrap_or_default(),
                        source,
                    ]
                },
                cx,
            )
        };
        let end_note =
            listing
                .as_ref()
                .filter(|_| !show_functions)
                .map(|listing| match listing.end {
                    EndReason::FunctionEnd => {
                        "The listing ends where the function does.".to_string()
                    }
                    EndReason::NextFunction => {
                        "The listing ends where the next known function begins.".to_string()
                    }
                    EndReason::InstructionLimit => format!(
                        "Only the first {} instructions are listed.",
                        listing.lines.len()
                    ),
                    EndReason::EndOfData => "The listing ends with the mapped code.".to_string(),
                });

        div()
            .flex_1()
            .flex()
            .flex_col()
            .gap_3()
            .child(toolbar)
            .child(note(summary, MUTED))
            .child(note(symbols, if symbols_failed { WARNING } else { MUTED }))
            .child(note(
                if show_functions {
                    "Click a function to list it. The search box filters by name or address."
                } else {
                    "Linear listing: indirect jumps are not followed and control flow is not reconstructed. Click a line to follow its target or see its bytes."
                },
                MUTED,
            ))
            .when_some(end_note, |panel, text| panel.child(note(text, MUTED)))
            .child(body)
            .into_any_element()
    }

    // ---- YARA ------------------------------------------------------------

    pub(super) fn choose_yara_rules(&mut self, folder: bool, cx: &mut Context<Self>) {
        if self.artifact.is_none() {
            self.error = Some("Open a file or folder before scanning with YARA rules.".into());
            cx.notify();
            return;
        }
        if self.loading {
            // Starting a scan now would replace the task that is running.
            self.error =
                Some("Wait for the current task to finish before starting a YARA scan.".into());
            cx.notify();
            return;
        }
        let dialog = rfd::AsyncFileDialog::new().set_title("Choose YARA rules");
        let (dialog, kind) = if folder {
            (dialog, DialogKind::Folder)
        } else {
            (
                dialog.add_filter("YARA rules", &["yar", "yara"]),
                DialogKind::File,
            )
        };
        self.prompt_path(dialog, kind, cx, |this, path, cx| this.scan_yara(path, cx));
    }

    #[cfg(not(feature = "yara"))]
    fn scan_yara(&mut self, _rules: PathBuf, cx: &mut Context<Self>) {
        self.error = Some("This build of Hexlora does not include YARA scanning.".into());
        cx.notify();
    }

    /// Compiles the rules and scans every file of the open artifact.
    #[cfg(feature = "yara")]
    fn scan_yara(&mut self, rules_path: PathBuf, cx: &mut Context<Self>) {
        use hexlora_analysis::{YaraRules, yara_scan_node};
        let Some(artifact) = self.artifact.clone() else {
            return;
        };
        if self.loading {
            // A task started while the file dialog was open.
            self.error =
                Some("Wait for the current task to finish before starting a YARA scan.".into());
            cx.notify();
            return;
        }
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.yara = YaraState {
            rules_path: Some(rules_path.clone()),
            generation,
            ..YaraState::default()
        };
        self.tab = InspectorTab::Yara;
        self.row_selection = None;
        self.status = format!("Scanning with YARA rules from {}…", rules_path.display()).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let rules = YaraRules::load(&rules_path)?;
                    let mut hits = Vec::new();
                    let (mut scanned, mut skipped, mut dropped) = (0usize, 0usize, 0usize);
                    for node in artifact.files() {
                        cancellation.check()?;
                        let matches = match yara_scan_node(node, &rules, &cancellation) {
                            Ok(matches) => matches,
                            Err(hexlora_core::HexloraError::Cancelled) => {
                                return Err(hexlora_core::HexloraError::Cancelled);
                            }
                            // An unreadable or oversized member does not end the scan.
                            Err(_) => {
                                skipped += 1;
                                continue;
                            }
                        };
                        scanned += 1;
                        for found in matches {
                            if hits.len() >= MAX_YARA_HITS {
                                dropped += 1;
                                continue;
                            }
                            let first = found
                                .occurrences
                                .first()
                                .map(|occurrence| {
                                    format!(
                                        "{} at 0x{:x}",
                                        occurrence.identifier, occurrence.offset
                                    )
                                })
                                .unwrap_or_default();
                            let count = found.occurrences.len() as u64 + found.more_occurrences;
                            hits.push(YaraHit {
                                path: node.path.clone(),
                                rule: found.rule_id(),
                                tags: found.tags.join(", "),
                                severity: found
                                    .severity
                                    .map(|severity| format!("{severity:?}"))
                                    .unwrap_or_default(),
                                occurrences: match count {
                                    0 => String::new(),
                                    1 => first,
                                    _ => format!("{first} (+{} more)", count - 1),
                                },
                                description: found.description.unwrap_or_default(),
                            });
                        }
                    }
                    let mut summary = format!(
                        "{} rules · {scanned} files scanned · {} matches",
                        rules.rule_count(),
                        hits.len()
                    );
                    if skipped > 0 {
                        summary.push_str(&format!(
                            " · {skipped} files could not be read or exceed the scan limit"
                        ));
                    }
                    if dropped > 0 {
                        summary.push_str(&format!(" · {dropped} further matches not listed"));
                    }
                    if !rules.warnings().is_empty() {
                        summary.push_str(&format!(" · {} rule warnings", rules.warnings().len()));
                    }
                    Ok::<_, hexlora_core::HexloraError>((hits, summary))
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok((hits, summary)) => {
                        this.status = format!("YARA scan complete: {} matches", hits.len()).into();
                        this.yara.hits = Arc::new(hits);
                        this.yara.summary = summary.into();
                        this.yara.scanned = true;
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "YARA scan incomplete".into();
                        this.yara = YaraState::default();
                        if this.tab == InspectorTab::Yara {
                            this.tab = InspectorTab::Overview;
                        }
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }

    /// Remembers rules to scan with once the artifact being opened is ready.
    pub(super) fn queue_yara_scan(&mut self, rules: Option<PathBuf>) {
        self.yara.queued = rules;
    }

    /// Starts the queued scan, if there is one and nothing else is running.
    pub(super) fn start_queued_yara_scan(&mut self, cx: &mut Context<Self>) {
        if !self.loading
            && let Some(rules) = self.yara.queued.take()
        {
            self.scan_yara(rules, cx);
        }
    }

    /// Selects the file a match was found in, expanding the tree down to it.
    fn open_matched_file(&mut self, path: &std::path::Path, cx: &mut Context<Self>) {
        fn locate(
            node: &ArtifactNode,
            path: &std::path::Path,
            ancestors: &mut Vec<uuid::Uuid>,
        ) -> Option<uuid::Uuid> {
            if node.path == path && node.is_file() {
                return Some(node.id);
            }
            let found = node
                .children
                .iter()
                .find_map(|child| locate(child, path, ancestors))?;
            ancestors.push(node.id);
            Some(found)
        }
        let mut ancestors = Vec::new();
        let found = self
            .artifact
            .as_deref()
            .and_then(|root| locate(root, path, &mut ancestors));
        match found {
            Some(id) => {
                self.expanded_nodes.extend(ancestors);
                self.select(id, cx);
            }
            None => {
                self.error = Some(format!("{} is no longer in the tree", path.display()).into());
                cx.notify();
            }
        }
    }

    /// Whether the YARA tab has anything to show.
    pub(super) fn yara_active(&self) -> bool {
        self.yara.rules_path.is_some()
    }

    pub(super) fn render_yara(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let base = self.artifact.as_ref().map(|artifact| artifact.path.clone());
        let hits = self.yara.hits.clone();
        let query = self.query.to_lowercase();
        let visible: Arc<Vec<usize>> = Arc::new(
            hits.iter()
                .enumerate()
                .filter(|(_, hit)| {
                    query.is_empty()
                        || hit.rule.to_lowercase().contains(&query)
                        || hit.path.to_string_lossy().to_lowercase().contains(&query)
                        || hit.tags.to_lowercase().contains(&query)
                })
                .map(|(index, _)| index)
                .collect(),
        );
        let rules = self
            .yara
            .rules_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        div()
            .flex_1()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("YARA Rule Matches"))
            .child(note(format!("Rules: {rules}"), MUTED))
            .child(note(
                if self.yara.scanned {
                    self.yara.summary.clone()
                } else if self.loading && self.yara.generation == self.task_generation {
                    "Scanning…".into()
                } else {
                    "The scan was interrupted before it finished. Start it again from the File menu.".into()
                },
                MUTED,
            ))
            .child(note(
                "A match means a pattern from your rules occurs in the file. What that implies depends on the rule.",
                MUTED,
            ))
            .when(self.yara.scanned && hits.is_empty(), |panel| {
                panel.child(info_panel(
                    "No matches",
                    "None of the rules matched any file in this artifact.",
                ))
            })
            .when(!hits.is_empty(), |panel| {
                // A filtered table cannot map its rows back to hits, so row
                // actions are offered only for the unfiltered list.
                let title = if visible.len() == hits.len() {
                    YARA_TABLE
                } else {
                    "YARA Matches (filtered)"
                };
                let total = visible.len();
                panel.child(lazy_table_panel(
                    title,
                    &["File", "Rule", "Severity", "Tags", "Matched", "Description"],
                    total,
                    move |row| {
                        let hit = &hits[visible[row]];
                        let file = base
                            .as_ref()
                            .and_then(|base| hit.path.strip_prefix(base).ok())
                            .filter(|relative| !relative.as_os_str().is_empty())
                            .unwrap_or(&hit.path);
                        vec![
                            file.display().to_string(),
                            hit.rule.clone(),
                            hit.severity.clone(),
                            hit.tags.clone(),
                            hit.occurrences.clone(),
                            hit.description.clone(),
                        ]
                    },
                    cx,
                ))
            })
    }
}
