extern crate cryptoki;
extern crate packed_struct;
extern crate serde_cbor;

#[macro_use]
mod macros;

mod binio;
pub mod crypto;
mod ctaphid;
mod error;
//mod eventloop;
mod hid;
//mod panic;
pub mod prompt;
mod usb;
pub mod usbip;

pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
