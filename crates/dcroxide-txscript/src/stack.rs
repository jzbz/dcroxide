// SPDX-License-Identifier: ISC
//! The engine's data/alternate stack (dcrd `stack.go`) with dcrd's exact
//! boolean and numeric interpretation rules and error identities.

use alloc::format;
use alloc::vec::Vec;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::scriptnum::{ScriptNum, make_script_num};

/// The boolean value of a stack byte array (dcrd `asBool`): any non-zero
/// byte makes it true, except a trailing 0x80 alone (negative zero).
pub(crate) fn as_bool(t: &[u8]) -> bool {
    for (i, b) in t.iter().enumerate() {
        if *b != 0 {
            // Negative 0 is also considered false.
            if i == t.len() - 1 && *b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// The byte array for a boolean (dcrd `fromBool`): `[1]` or empty.
pub(crate) fn from_bool(v: bool) -> Vec<u8> {
    if v { alloc::vec![1] } else { Vec::new() }
}

/// A stack of byte arrays (dcrd `stack`).
#[derive(Default)]
pub(crate) struct Stack {
    pub stk: Vec<Vec<u8>>,
}

impl Stack {
    /// The number of items on the stack (dcrd `Depth`).
    pub fn depth(&self) -> i32 {
        self.stk.len() as i32
    }

    /// Push a byte array onto the top of the stack.
    pub fn push_byte_array(&mut self, so: Vec<u8>) {
        self.stk.push(so);
    }

    /// Push a script number onto the top of the stack.
    pub fn push_int(&mut self, val: ScriptNum) {
        self.push_byte_array(val.bytes());
    }

    /// Push a boolean onto the top of the stack.
    pub fn push_bool(&mut self, val: bool) {
        self.push_byte_array(from_bool(val));
    }

    /// Pop the top value off the stack (dcrd `PopByteArray`).
    pub fn pop_byte_array(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.nip_n_internal(0)
    }

    /// Pop the top value as a script number, enforcing the consensus rules
    /// imposed on data interpreted as numbers (dcrd `PopInt`).
    pub fn pop_int(&mut self, max_script_num_len: usize) -> Result<ScriptNum, ScriptError> {
        let so = self.pop_byte_array()?;
        make_script_num(&so, max_script_num_len)
    }

    /// Pop the top value as a boolean (dcrd `PopBool`).
    pub fn pop_bool(&mut self) -> Result<bool, ScriptError> {
        let so = self.pop_byte_array()?;
        Ok(as_bool(&so))
    }

    /// The Nth item on the stack without removing it (dcrd
    /// `PeekByteArray`).
    pub fn peek_byte_array(&self, idx: i32) -> Result<&[u8], ScriptError> {
        let sz = self.stk.len() as i32;
        if idx < 0 || idx >= sz {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("index {idx} is invalid for stack size {sz}"),
            ));
        }
        Ok(&self.stk[(sz - idx - 1) as usize])
    }

    /// The Nth item on the stack as a script number (dcrd `PeekInt`).
    pub fn peek_int(&self, idx: i32, max_script_num_len: usize) -> Result<ScriptNum, ScriptError> {
        let so = self.peek_byte_array(idx)?;
        make_script_num(so, max_script_num_len)
    }

    /// Remove the Nth item on the stack and return it (dcrd `nipN`).
    fn nip_n_internal(&mut self, idx: i32) -> Result<Vec<u8>, ScriptError> {
        let sz = self.stk.len() as i32;
        if idx < 0 || idx > sz - 1 {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("index {idx} is invalid for stack size {sz}"),
            ));
        }
        Ok(self.stk.remove((sz - idx - 1) as usize))
    }

    /// Remove the Nth item on the stack (dcrd `NipN`).
    pub fn nip_n(&mut self, idx: i32) -> Result<(), ScriptError> {
        self.nip_n_internal(idx).map(|_| ())
    }

    /// Copy the top item and insert it before the 2nd-to-top item (dcrd
    /// `Tuck`): `[... x1 x2] -> [... x2 x1 x2]`.
    pub fn tuck(&mut self) -> Result<(), ScriptError> {
        let so2 = self.pop_byte_array()?;
        let so1 = self.pop_byte_array()?;
        self.push_byte_array(so2.clone());
        self.push_byte_array(so1);
        self.push_byte_array(so2);
        Ok(())
    }

    /// Remove the top N items (dcrd `DropN`).
    pub fn drop_n(&mut self, n: i32) -> Result<(), ScriptError> {
        let mut n = n;
        while n > 0 {
            self.pop_byte_array()?;
            n -= 1;
        }
        Ok(())
    }

    /// Duplicate the top N items (dcrd `DupN`).
    pub fn dup_n(&mut self, n: i32) -> Result<(), ScriptError> {
        if n < 1 {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("attempt to dup {n} stack items"),
            ));
        }
        for _ in 0..n {
            let so = self.peek_byte_array(n - 1)?.to_vec();
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Rotate the top 3N items to the left N times (dcrd `RotN`).
    pub fn rot_n(&mut self, n: i32) -> Result<(), ScriptError> {
        if n < 1 {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("attempt to rotate {n} stack items"),
            ));
        }
        let entry = 3 * n - 1;
        for _ in 0..n {
            let so = self.nip_n_internal(entry)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Swap the top N items with those below them (dcrd `SwapN`).
    pub fn swap_n(&mut self, n: i32) -> Result<(), ScriptError> {
        if n < 1 {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("attempt to swap {n} stack items"),
            ));
        }
        let entry = 2 * n - 1;
        for _ in 0..n {
            let so = self.nip_n_internal(entry)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Copy N items N items back to the top (dcrd `OverN`).
    pub fn over_n(&mut self, n: i32) -> Result<(), ScriptError> {
        if n < 1 {
            return Err(script_error(
                ErrorKind::InvalidStackOperation,
                format!("attempt to perform over on {n} stack items"),
            ));
        }
        let entry = 2 * n - 1;
        let mut n = n;
        while n > 0 {
            let so = self.peek_byte_array(entry)?.to_vec();
            self.push_byte_array(so);
            n -= 1;
        }
        Ok(())
    }

    /// Copy the item N items back to the top (dcrd `PickN`).
    pub fn pick_n(&mut self, n: i32) -> Result<(), ScriptError> {
        let so = self.peek_byte_array(n)?.to_vec();
        self.push_byte_array(so);
        Ok(())
    }

    /// Move the item N items back to the top (dcrd `RollN`).
    pub fn roll_n(&mut self, n: i32) -> Result<(), ScriptError> {
        let so = self.nip_n_internal(n)?;
        self.push_byte_array(so);
        Ok(())
    }
}
