//! Library half of `freenet-git`. Holds the bits that are easier to test
//! when not wrapped in `clap`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod ids;
pub mod state_init;
pub mod url;
