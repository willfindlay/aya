use core::{hint::unreachable_unchecked, mem};

use aya_bpf_cty::c_long;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY},
    helpers::bpf_tail_call,
    maps::PinningType,
    BpfContext,
};

/// A BPF map that stores an array of program indices for tail calling.
///
/// # Examples
///
/// ```no_run
/// # #![allow(dead_code)]
/// use aya_bpf::{macros::map, maps::ProgramArray, cty::c_long};
/// # use aya_bpf::{programs::LsmContext};
///
/// #[map]
/// static mut JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(16, 0);
///
/// # unsafe fn try_test(ctx: &LsmContext) -> Result<(), c_long> {
/// let index: u32 = 13;
///
/// let res = JUMP_TABLE.tail_call(ctx, index);
///
/// # res
/// }
/// ```
#[repr(transparent)]
pub struct ProgramArray {
    def: bpf_map_def,
}

impl ProgramArray {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> ProgramArray {
        ProgramArray {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_PROG_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> ProgramArray {
        ProgramArray {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_PROG_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
        }
    }

    /// Perform a tail call into a program indexed by this map.
    ///
    /// # Return Value
    ///
    /// On success, this function **does not return** into the original program.
    /// On failure, a negative error is returned, wrapped in `Err()`.
    pub fn tail_call<C: BpfContext>(&mut self, ctx: &C, index: u32) -> Result<(), c_long> {
        let res = unsafe { bpf_tail_call(ctx.as_ptr(), &mut self.def as *mut _ as *mut _, index) };
        if res != 0 {
            Err(res)
        } else {
            unsafe { unreachable_unchecked() }
        }
    }
}
