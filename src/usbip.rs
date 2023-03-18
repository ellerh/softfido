// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use crate::crypto;
use crate::ctaphid;
use crate::eventloop;
use crate::hid;
use bindings::*;
use packed_struct::prelude::*;
use packed_struct::PackedStruct;
use packed_struct::PrimitiveEnum;
use std::cmp::min;
use std::convert::TryFrom;
use std::io::{Error, Read, Write};
use std::mem::size_of;

type R<T> = Result<T, Box<dyn std::error::Error>>;

pub const USBIP_VERSION: u16 = 0x0111u16;
const LANG_ID_EN_US: u16 = 0x0409;

// const URB_SHORT_NOT_OK        = 0x00000001;
// const URB_ISO_ASAP            = 0x00000002;
// const URB_NO_TRANSFER_DMA_MAP = 0x00000004;
// const URB_ZERO_PACKET         = 0x00000040;
// const URB_NO_INTERRUPT        = 0x00000080;
// const URB_FREE_BUFFER         = 0x00000100;
pub const URB_DIR_MASK: u32 = 0x00000200;

#[derive(PackedStruct, Clone, Copy, Debug)]
#[packed_struct(endian = "lsb")]
pub struct SetupPacket {
    #[packed_field(size_bytes = "1")]
    bm_request_type: BmRequestType,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
}

#[derive(PackedStruct, Clone, Copy, Debug)]
#[packed_struct(endian = "lsb", size_bytes = "1", bit_numbering = "lsb0")]
pub struct BmRequestType {
    #[packed_field(bits = "7", ty = "enum")]
    direction: DataTransferDirection,
    #[packed_field(bits = "5..=6", ty = "enum")]
    type_: RequestType,
    #[packed_field(bits = "0..=4", ty = "enum")]
    recipient: RequestRecipient,
}

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
pub enum DataTransferDirection {
    HostToDevice = 0,
    DeviceToHost = 1,
}

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
pub enum RequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
    Reserved = 3,
}

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
pub enum RequestRecipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
}

#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum StandardRequest {
    GetStatus = 0,
    ClearFeature = 1,
    SetFeature = 3,
    SetAddress = 5,
    GetDescriptor = 6,
    SetDescriptor = 7,
    GetConfiguration = 8,
    SetConfiguration = 9,
    GetInterface = 10,
    SetInterface = 11,
    SynchFrame = 12,
}

#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum HIDRequest {
    GetReport = 1,
    GetIdle = 2,
    GetProtocol = 3,
    SetReport = 9,
    SetIdle = 0xa,
    SetProtocol = 0xb,
}

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    Endpoint = 5,
    DeviceQualifier = 6,
    OtherSpeedConfiguration = 7,
    InterfacePower = 8,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
struct usb_hid_descriptor {
    bLength: __u8,
    bDescriptorType: __u8,
    bcdHID: __le16,
    bCountryCode: __u8,
    bNumDescriptors: __u8,
    bReportDescriptorType: __u8,
    wReportDescriptorLength: __le16,
    // ... optional other descriptors type/length pairs
}

#[derive(Debug, Clone)]
struct RequestError {
    msg: String,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct Device<'a> {
    device_descriptor: usb_device_descriptor,
    config_descriptor: usb_config_descriptor,
    interface_descriptor: usb_interface_descriptor,
    hid_descriptor: usb_hid_descriptor,
    hid_report_descriptor: Vec<u8>,
    endpoint_descriptors: Vec<usb_endpoint_descriptor>,
    strings: Vec<&'static str>,
    parser: ctaphid::Parser<'a>,
}

impl<'a> Device<'a> {
    pub fn new(token: &'a crypto::KeyStore) -> Self {
        let hid_report_descriptor: Vec<u8> = {
            use hid::*;
            [
                usage_page(FIDO),
                usage(CTAPHID),
                collection(APPLICATION),
                usage(FIDO_USAGE_DATA_IN),
                logical_minimum(0),
                logical_maximum(0xff),
                report_size(8),
                report_count(64),
                input(DATA | VARIABLE | ABSOLUTE),
                usage(FIDO_USAGE_DATA_OUT),
                logical_minimum(0),
                logical_maximum(0xff),
                report_size(8),
                report_count(64),
                output(DATA | VARIABLE | ABSOLUTE),
                end_collection(),
            ]
            .iter()
            .flatten()
            .map(|&u8| u8)
            .collect()
        };

        Self {
            device_descriptor: usb_device_descriptor {
                bLength: u8::try_from(size_of::<usb_device_descriptor>())
                    .unwrap(),
                bDescriptorType: DescriptorType::Device.to_primitive(),
                bcdUSB: 0x0110u16.to_le(),
                bDeviceClass: USB_CLASS_PER_INTERFACE as u8,
                bDeviceSubClass: 0,
                bDeviceProtocol: 0,
                bMaxPacketSize0: 64,
                idVendor: 0,
                idProduct: 0,
                bcdDevice: 0x001u16.to_le(),
                iManufacturer: 1,
                iProduct: 2,
                iSerialNumber: 3,
                bNumConfigurations: 1,
            },
            config_descriptor: usb_config_descriptor {
                bLength: u8::try_from(size_of::<usb_config_descriptor>())
                    .unwrap(),
                bDescriptorType: DescriptorType::Configuration
                    .to_primitive(),
                wTotalLength: u16::try_from(
                    size_of::<usb_config_descriptor>()
                        + size_of::<usb_interface_descriptor>()
                        + size_of::<usb_hid_descriptor>()
                        //+ hid_report_descriptor.len()
                        + 2 * USB_DT_ENDPOINT_SIZE as usize,
                )
                .unwrap()
                .to_le(),
                bNumInterfaces: 1,
                bConfigurationValue: 0,
                iConfiguration: 4,
                bmAttributes: (USB_CONFIG_ATT_ONE
                    | USB_CONFIG_ATT_SELFPOWER)
                    as u8,
                bMaxPower: 0,
            },
            interface_descriptor: usb_interface_descriptor {
                bLength: u8::try_from(
                    size_of::<usb_interface_descriptor>(),
                )
                .unwrap(),
                bDescriptorType: DescriptorType::Interface.to_primitive(),
                bInterfaceNumber: 0,
                bAlternateSetting: 0,
                bNumEndpoints: 2,
                bInterfaceClass: USB_CLASS_HID as u8,
                bInterfaceSubClass: 0,
                bInterfaceProtocol: 0,
                iInterface: 5,
            },
            hid_descriptor: usb_hid_descriptor {
                bLength: size_of::<usb_hid_descriptor>() as u8,
                bDescriptorType: HID_DT_HID as u8,
                bcdHID: 0x101u16.to_le(),
                bCountryCode: 0,
                bNumDescriptors: 1,
                bReportDescriptorType: HID_DT_REPORT as u8,
                wReportDescriptorLength: (hid_report_descriptor.len()
                    as u16)
                    .to_le(),
            },
            hid_report_descriptor: hid_report_descriptor,
            endpoint_descriptors: vec![
                usb_endpoint_descriptor {
                    bLength: USB_DT_ENDPOINT_SIZE as u8,
                    bDescriptorType: DescriptorType::Endpoint
                        .to_primitive(),
                    bEndpointAddress: ((1 & USB_ENDPOINT_NUMBER_MASK)
                        | (USB_DIR_IN & USB_ENDPOINT_DIR_MASK))
                        as u8,
                    bmAttributes: USB_ENDPOINT_XFER_INT as u8,
                    wMaxPacketSize: (((64 & USB_ENDPOINT_MAXP_MASK)
                        as u16)
                        .to_le()),
                    bInterval: 255,
                    bRefresh: 0,
                    bSynchAddress: 0,
                },
                usb_endpoint_descriptor {
                    bLength: USB_DT_ENDPOINT_SIZE as u8,
                    bDescriptorType: DescriptorType::Endpoint
                        .to_primitive(),
                    bEndpointAddress: ((2 & USB_ENDPOINT_NUMBER_MASK)
                        | (USB_DIR_OUT & USB_ENDPOINT_DIR_MASK))
                        as u8,
                    bmAttributes: USB_ENDPOINT_XFER_INT as u8,
                    wMaxPacketSize: ((64 & USB_ENDPOINT_MAXP_MASK) as u16)
                        .to_le(),
                    bInterval: 255,
                    bRefresh: 0,
                    bSynchAddress: 0,
                },
            ],
            strings: vec![
                "string0",
                "Fakecompany",
                "Softproduct",
                "v0",
                "Default Config",
                "The Interface",
            ],
            parser: ctaphid::Parser::new(token),
        }
    }

    pub fn init_callbacks(el: &mut eventloop::EventLoop<Device>) {
        let d2h = eventloop::Handler::Dev2Host(
            0,
            |el: &mut eventloop::EventLoop<Device>,
             setup: &[u8; 8],
             data: &mut [u8]|
             -> R<bool> {
                el.state.ep0_dev2host(setup, data)?;
                Ok(true)
            },
        );
        el.schedule(d2h).unwrap();
        let h2d = eventloop::Handler::Host2Dev(
            0,
            |el: &mut eventloop::EventLoop<Device>,
             setup: &[u8; 8],
             data: &[u8]|
             -> R<bool> {
                el.state.ep0_host2dev(setup, data)?;
                Ok(true)
            },
        );
        el.schedule(h2d).unwrap();
        let d2h1 = eventloop::Handler::Dev2Host(
            1,
            |el: &mut eventloop::EventLoop<Device>,
             _setup: &[u8; 8],
             data: &mut [u8]|
             -> R<bool> { el.state.ep1_dev2host(data) },
        );
        el.schedule(d2h1).unwrap();
        let h2d2 = eventloop::Handler::Host2Dev(
            2,
            |el: &mut eventloop::EventLoop<Device>,
             _setup: &[u8; 8],
             data: &[u8]|
             -> R<bool> {
                el.state.ep2_host2dev(data)?;
                if !el.state.parser.recv_queue.is_empty()
                    || !el.state.parser.send_queue.is_empty()
                {
                    el.unblock_handler(1, true);
                };
                Ok(true)
            },
        );
        el.schedule(h2d2).unwrap();
    }

    fn get_lang_descriptor(
        &self,
        sink: &mut dyn Write,
    ) -> Result<(), Error> {
        let d = usb_string_descriptor {
            bLength: size_of::<usb_string_descriptor>() as u8,
            bDescriptorType: DescriptorType::String.to_primitive(),
            wData: [LANG_ID_EN_US.to_le()],
        };
        write_struct(sink, &d)
    }

    fn get_string_descriptor(
        &self,
        index: u8,
        sink: &mut dyn Write,
    ) -> Result<(), Error> {
        assert!(index > 0);
        let text = self.strings[index as usize];
        let utf16_len = text.encode_utf16().count();
        let mut v = Vec::<u8>::with_capacity(utf16_len);
        text.encode_utf16().for_each(|u| {
            let bs = u.to_le_bytes();
            v.push(bs[0]);
            v.push(bs[1])
        });
        sink.write_all(&[
            2 + (utf16_len * 2) as u8,
            DescriptorType::String.to_primitive(),
        ])?;
        sink.write_all(&v)
    }

    fn get_descriptor(
        &self,
        r#type: DescriptorType,
        index: u8,
        lang: u16,
        length: u16,
        sink: &mut dyn Write,
    ) -> Result<(), Error> {
        println!(
            "GET_DESCRIPTOR: type: {:?} index: {} lang: {} length: {} ",
            r#type, index, lang, length
        );
        use DescriptorType::*;

        match (r#type, index, lang) {
            (Device, 0, 0) => write_struct(sink, &self.device_descriptor),
            (Configuration, 0, 0) => {
                write_struct(sink, &self.config_descriptor)?;
                write_struct(sink, &self.interface_descriptor)?;
                write_struct(sink, &self.hid_descriptor)?;
                self.endpoint_descriptors
                    .iter()
                    .map(|epd| {
                        sink.write_all(
                            &(unsafe { any_as_u8_slice(epd) }
                                [..epd.bLength as usize]),
                        )
                    })
                    .find(|e| e.is_err())
                    .unwrap_or(Ok(()))
            }
            (String, 0, 0) => self.get_lang_descriptor(sink),
            (String, i, LANG_ID_EN_US) => {
                self.get_string_descriptor(i, sink)
            }
            x => panic!("Unsupported descriptor: {:?}", x),
        }
    }

    fn get_interface_descriptor(
        &self,
        type_: u8,
        index: u8,
        lang: u16,
        length: u16,
        sink: &mut dyn Write,
    ) -> Result<(), Error> {
        println!(
            "GET_DESCRIPTOR/i: type: {:?} index: {} lang: {} length: {} ",
            type_, index, lang, length
        );
        match type_ as u32 {
            HID_DT_REPORT => sink.write_all(&self.hid_report_descriptor),
            x => panic!("Unsupported descriptor type: {}", x),
        }
    }

    fn ep0_dev2host(&self, setup: &[u8; 8], sink: &mut [u8]) -> R<()> {
        let req = SetupPacket::unpack(setup).unwrap();
        let value = u16::from_le(req.w_value);
        let index = u16::from_le(req.w_index);
        let length = u16::from_le(req.w_length);
        match req.bm_request_type {
            BmRequestType {
                direction: DataTransferDirection::DeviceToHost,
                type_: RequestType::Standard,
                recipient: RequestRecipient::Device,
            } => match (
                StandardRequest::from_primitive(req.b_request).unwrap(),
                value,
                index,
                length,
            ) {
                (StandardRequest::GetDescriptor, value, lang, length) => {
                    let [idx, ty] = value.to_le_bytes();
                    call_with_write(sink, |sink| -> R<()> {
                        match DescriptorType::from_primitive(ty) {
                            Some(ty) => {
                                self.get_descriptor(
                                    ty, idx, lang, length, sink,
                                )?;
                                Ok(())
                            }
                            None => Err(RequestError {
                                msg: format!(
                                    "unknown descriptor type: {}",
                                    ty
                                ),
                            })?,
                        }
                    })?
                }
                (StandardRequest::GetStatus, 0, 0, 2) => {
                    sink.copy_from_slice(&[1u8, 0])
                }
                x => panic!(
                    "Unsupported device-to-host/standard/device \
                     request: {:?}",
                    x
                ),
            },
            BmRequestType {
                direction: DataTransferDirection::HostToDevice,
                type_: RequestType::Class,
                recipient: RequestRecipient::Interface,
            } => match (
                HIDRequest::from_primitive(req.b_request).unwrap(),
                value,
                index,
                length,
            ) {
                (HIDRequest::SetIdle, 0, 0, 0) => (),
                x => panic!("Unsupported hid request index: {:?}", x),
            },
            BmRequestType {
                direction: DataTransferDirection::DeviceToHost,
                type_: RequestType::Standard,
                recipient: RequestRecipient::Interface,
            } => match (
                StandardRequest::from_primitive(req.b_request).unwrap(),
                value,
                index,
                length,
            ) {
                (StandardRequest::GetDescriptor, value, index, length) => {
                    let [idx, ty] = value.to_le_bytes();
                    call_with_write(sink, |sink| {
                        self.get_interface_descriptor(
                            ty, idx, index, length, sink,
                        )
                    })?
                }
                x => panic!("Unsupported interface request: {:?}", x),
            },
            x => panic!("Unsupported dev2host b_requestType: {:?}", x),
        }
        Ok(())
    }

    fn ep0_host2dev(&self, setup: &[u8; 8], _data: &[u8]) -> R<()> {
        let req = SetupPacket::unpack(setup).unwrap();
        let value = u16::from_le(req.w_value);
        let index = u16::from_le(req.w_index);
        let length = u16::from_le(req.w_length);
        match req.bm_request_type {
            BmRequestType {
                direction: DataTransferDirection::HostToDevice,
                type_: RequestType::Standard,
                recipient: RequestRecipient::Device,
            } => match (
                StandardRequest::from_primitive(req.b_request).unwrap(),
                value,
                index,
                length,
            ) {
                (StandardRequest::SetConfiguration, 0, 0, 0) => Ok(()),
                x => panic!(
                    "Unsupported hos2dev/standard/device \
                     request: {:?}",
                    x
                ),
            },
            BmRequestType {
                direction: DataTransferDirection::HostToDevice,
                type_: RequestType::Class,
                recipient: RequestRecipient::Interface,
            } => match (
                HIDRequest::from_primitive(req.b_request).unwrap(),
                value,
                index,
                length,
            ) {
                (HIDRequest::SetIdle, 0, 0, 0) => Ok(()),
                x => panic!("Unsupported hid request index: {:?}", x),
            },
            x => panic!("Unsupported host2dev b_requestType: {:?}", x),
        }
    }

    fn ep1_dev2host(&mut self, buf: &mut [u8]) -> R<bool> {
        log!("ep1 dev->host");
        while !self.parser.recv_queue.is_empty() {
            self.parser.parse()?
        }
        if !self.parser.send_queue.is_empty() {
            self.parser.unparse(buf)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn ep2_host2dev(&mut self, data: &[u8]) -> R<bool> {
        log!("ep2 host->dev");
        self.parser.recv_queue.push_back(data.to_vec());
        Ok(true)
    }
}

fn read_struct<T>(stream: &mut dyn Read) -> Result<T, Error> {
    unsafe {
        let s = std::mem::MaybeUninit::<T>::uninit();
        stream.read_exact(any_as_u8_slice(&s))?;
        Ok(s.assume_init())
    }
}

fn write_struct<T>(stream: &mut dyn Write, s: &T) -> Result<(), Error> {
    stream.write_all(unsafe { any_as_u8_slice(s) })
}

pub fn read_op_common(
    stream: &mut dyn Read,
) -> Result<(u16, u16, u32), Error> {
    let header = read_struct::<op_common>(stream)?;
    Ok((
        u16::from_be(header.version),
        u16::from_be(header.code),
        u32::from_be(header.status),
    ))
}

fn op_common(code: u32) -> op_common {
    op_common {
        version: USBIP_VERSION.to_be(),
        code: u16::try_from(code).unwrap().to_be(),
        status: 0u32.to_be(),
    }
}

fn usb_device() -> usbip_usb_device {
    let mut dev = usbip_usb_device {
        path: [0; 256],
        busid: [0; 32],
        busnum: 33u32.to_be(),
        devnum: 22u32.to_be(),
        speed: 2u32.to_be(),
        idVendor: 0u16.to_be(),
        idProduct: 0u16.to_be(),
        bcdDevice: 0u16.to_be(),
        bDeviceClass: 0u8.to_be(),
        bDeviceSubClass: 0u8.to_be(),
        bDeviceProtocol: 0u8.to_be(),
        bConfigurationValue: 0u8.to_be(),
        bNumConfigurations: 1u8.to_be(),
        bNumInterfaces: 1u8.to_be(),
    };
    b"/frob/bar"
        .iter()
        .enumerate()
        .for_each(|(i, &v)| dev.path[i] = v as i8);
    b"1-1"
        .iter()
        .enumerate()
        .for_each(|(i, &v)| dev.busid[i] = v as i8);
    dev
}

fn usb_interface() -> usbip_usb_interface {
    usbip_usb_interface {
        bInterfaceClass: 3u8.to_be(),
        bInterfaceSubClass: 0u8.to_be(),
        bInterfaceProtocol: 0u8.to_be(),
        padding: 0u8.to_be(),
    }
}

pub fn write_op_rep_devlist(stream: &mut dyn Write) -> Result<(), Error> {
    write_struct(stream, &op_common(OP_REP_DEVLIST))?;
    write_struct(stream, &op_devlist_reply { ndev: 1u32.to_be() })?;
    write_struct(stream, &usb_device())?;
    write_struct(stream, &usb_interface())?;
    Ok(())
}

pub fn write_op_rep_import(stream: &mut dyn Write) -> Result<(), Error> {
    write_struct(stream, &op_common(OP_REP_IMPORT))?;
    write_struct(stream, &usb_device())
}

pub fn write_submit_reply(
    stream: &mut dyn Write,
    header: &usbip_header,
    data: &[u8],
    actual_len: Option<i32>,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_SUBMIT.to_be(),
                seqnum: header.base.seqnum,
                devid: header.base.devid,
                direction: USBIP_DIR_OUT.to_be(),
                ep: header.base.ep,
            },
            u: usbip_header__bindgen_ty_1 {
                ret_submit: usbip_header_ret_submit {
                    status: 0,
                    actual_length: match actual_len {
                        None => i32::try_from(data.len()).unwrap().to_be(),
                        Some(l) => l.to_be(),
                    },
                    start_frame: 0,
                    number_of_packets: 0,
                    error_count: 0,
                },
            },
        },
    )?;
    stream.write(data)?;
    Ok(())
}

pub fn write_submit_reply_error(
    stream: &mut dyn Write,
    header: &usbip_header,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_SUBMIT.to_be(),
                seqnum: header.base.seqnum,
                devid: header.base.devid,
                direction: USBIP_DIR_OUT.to_be(),
                ep: header.base.ep,
            },
            u: usbip_header__bindgen_ty_1 {
                ret_submit: usbip_header_ret_submit {
                    status: 1,
                    actual_length: 0,
                    start_frame: 0,
                    number_of_packets: 0,
                    error_count: 0,
                },
            },
        },
    )
}

pub fn write_unlink_reply(
    stream: &mut dyn Write,
    header: &usbip_header,
    status: i32,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_UNLINK.to_be(),
                seqnum: header.base.seqnum,
                devid: header.base.devid,
                direction: USBIP_DIR_OUT.to_be(),
                ep: header.base.ep,
            },
            u: usbip_header__bindgen_ty_1 {
                ret_unlink: usbip_header_ret_unlink {
                    status: status.to_be(),
                },
            },
        },
    )
}

pub fn read_busid(stream: &mut dyn Read) -> Result<String, Error> {
    let req: op_import_request = read_struct(stream)?;
    Ok(String::from_utf8(
        req.busid
            .iter()
            .take_while(|&&x| x != 0)
            .map(|&x| x as u8)
            .collect(),
    )
    .unwrap())
}

pub fn read_cmd_header(
    stream: &mut dyn Read,
) -> Result<usbip_header, Error> {
    read_struct(stream)
}

pub unsafe fn any_as_u8_slice<T>(p: &T) -> &mut [u8] {
    std::slice::from_raw_parts_mut(
        (p as *const T) as *mut u8,
        size_of::<T>(),
    )
}

fn call_with_write<F, T>(buf: &mut [u8], f: F) -> T
where
    F: Fn(&mut dyn Write) -> T,
{
    let mut c = std::io::Cursor::new(Vec::with_capacity(buf.len()));
    let v = f(&mut c);
    let r = c.into_inner();
    let min = min(buf.len(), r.len());
    buf[..min].copy_from_slice(&r[..min]);
    v
}
