//! Hexlora's semantic color tokens.
//!
//! The dark palette is a neutral graphite scale (no hue tint in the surfaces) with a single
//! blue interactive accent, following the conventions of professional developer tools.
//! Status colors carry meaning only: green = good, amber = caution, orange = high,
//! red = critical. Keeping these as semantic tokens prevents individual inspectors from
//! inventing their own colors and leaves room for additional appearance modes.

// Surfaces, from the window background up to raised controls.
pub const BACKGROUND: u32 = 0x161616;
pub const PANEL: u32 = 0x1e1e1e;
pub const PANEL_RAISED: u32 = 0x2a2a2a;
pub const BORDER: u32 = 0x363636;
pub const SELECTION: u32 = 0x1d3557;

// Text.
pub const TEXT: u32 = 0xe6e6e6;
pub const TEXT_MUTED: u32 = 0x9b9b9b;

// Interactive accent. `PRIMARY` is for text, icons, and chart marks on dark surfaces;
// `PRIMARY_SOLID` is the filled-button background that carries `ON_PRIMARY` text.
pub const PRIMARY: u32 = 0x58a6ff;
pub const PRIMARY_SOLID: u32 = 0x1f6feb;
pub const PRIMARY_SOLID_HOVER: u32 = 0x388bfd;
pub const PRIMARY_SOLID_ACTIVE: u32 = 0x1158c7;
pub const ON_PRIMARY: u32 = 0xffffff;

// Status.
pub const SUCCESS: u32 = 0x3fb950;
pub const ACCENT: u32 = 0xd29922;
pub const WARNING: u32 = 0xd29922;
pub const HIGH: u32 = 0xdb6d28;
pub const DESTRUCTIVE: u32 = 0xf85149;
pub const DESTRUCTIVE_HOVER: u32 = 0xff7b72;
pub const DESTRUCTIVE_ACTIVE: u32 = 0xda3633;

// Additional categorical hues for charts and treemaps.
pub const SKY: u32 = 0x79c0ff;
pub const PURPLE: u32 = 0xa371f7;
pub const PINK: u32 = 0xdb61a2;
pub const SLATE: u32 = 0x8b949e;
