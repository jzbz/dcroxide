// SPDX-License-Identifier: ISC
//! A port of the subset of Go's `text/tabwriter` used by dcrjson's
//! help generation: space padding, no flags, and cell widths counted
//! in characters.
//!
//! dcrjson initializes its writers with `Init(w, 0, 4, 1, ' ', 0)`.
//! Column widths are computed per column block — maximal runs of
//! consecutive lines that all have a cell in the column — exactly as
//! Go's recursive `format` does, and the last cell of each line is
//! never padded because tab-terminated cells define columns while the
//! newline-terminated remainder does not.

// Bounded index arithmetic over line/cell vectors mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

struct Cell {
    text: String,
    width: usize,
}

/// The tab-alignment writer.
pub struct TabWriter {
    minwidth: usize,
    padding: usize,
    lines: Vec<Vec<Cell>>,
    cur: String,
}

impl TabWriter {
    /// A writer configured the way dcrjson configures Go's:
    /// `tabwriter.Writer.Init(w, 0, 4, 1, ' ', 0)`.
    pub fn new() -> TabWriter {
        TabWriter {
            minwidth: 0,
            padding: 1,
            lines: vec![Vec::new()],
            cur: String::new(),
        }
    }

    /// Append text, splitting cells on tabs and lines on newlines.
    pub fn write(&mut self, text: &str) {
        for c in text.chars() {
            match c {
                '\t' => self.terminate_cell(),
                '\n' => {
                    self.terminate_cell();
                    self.lines.push(Vec::new());
                }
                c => self.cur.push(c),
            }
        }
    }

    fn terminate_cell(&mut self) {
        let text = core::mem::take(&mut self.cur);
        let width = text.chars().count();
        self.lines
            .last_mut()
            .expect("line")
            .push(Cell { text, width });
    }

    /// Format the buffered content (Go `Flush`).
    pub fn flush(mut self) -> String {
        if !self.cur.is_empty() {
            self.terminate_cell();
        }
        let mut out = String::new();
        let mut widths = Vec::new();
        format(
            &self.lines,
            &mut widths,
            self.minwidth,
            self.padding,
            0,
            self.lines.len(),
            &mut out,
        );
        out
    }
}

impl Default for TabWriter {
    fn default() -> Self {
        TabWriter::new()
    }
}

fn format(
    lines: &[Vec<Cell>],
    widths: &mut Vec<usize>,
    minwidth: usize,
    padding: usize,
    line0: usize,
    line1: usize,
    out: &mut String,
) {
    let column = widths.len();
    let mut line0 = line0;
    let mut this = line0;
    while this < line1 {
        let line = &lines[this];
        if column + 1 < line.len() {
            // A cell exists in this column: this line has more cells
            // than the previous line.  Print unprinted lines until the
            // beginning of the block, then compute the column width
            // over the block.
            write_lines(lines, widths, line0, this, out);
            line0 = this;
            let mut width = minwidth;
            while this < line1 {
                let line = &lines[this];
                if column + 1 >= line.len() {
                    break;
                }
                let w = line[column].width + padding;
                if w > width {
                    width = w;
                }
                this += 1;
            }
            widths.push(width);
            format(lines, widths, minwidth, padding, line0, this, out);
            widths.pop();
            line0 = this;
            // The outer loop increment applies to the terminating
            // line, mirroring Go's for-loop structure.
        }
        this += 1;
    }
    write_lines(lines, widths, line0, line1, out);
}

fn write_lines(
    lines: &[Vec<Cell>],
    widths: &[usize],
    line0: usize,
    line1: usize,
    out: &mut String,
) {
    for i in line0..line1 {
        let line = &lines[i];
        for (j, c) in line.iter().enumerate() {
            out.push_str(&c.text);
            if j < widths.len() {
                for _ in 0..widths[j].saturating_sub(c.width) {
                    out.push(' ');
                }
            }
        }
        if i + 1 != lines.len() {
            out.push('\n');
        }
    }
}
