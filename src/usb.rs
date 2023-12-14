use crate::bindings::*;
use crate::binio::{write_struct, write_struct_limited};
use crate::error::R;
use crate::hid;
use packed_struct::prelude::PackedStruct;
use packed_struct::prelude::{PrimitiveEnum, PrimitiveEnum_u8};
use std::convert::TryFrom;
use std::mem::size_of;
use std::sync::mpsc::Sender;

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

impl SetupPacket {
    fn request_type(self) -> (DataTransferDirection, RT, RR) {
        (
            self.bm_request_type.direction,
            self.bm_request_type.type_,
            self.bm_request_type.recipient,
        )
    }
    fn direction(self) -> DataTransferDirection {
        self.bm_request_type.direction
    }
    fn args(self) -> (u16, u16, u16) {
        (self.w_value, self.w_index, self.w_length)
    }
    fn std(self) -> StandardRequest {
        StandardRequest::from_primitive(self.b_request).unwrap()
    }
    fn hid_request(self) -> (HIDRequest, (u16, u16, u16)) {
        (
            HIDRequest::from_primitive(self.b_request).unwrap(),
            self.args(),
        )
    }
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

use DataTransferDirection::DeviceToHost as D2H;
use DataTransferDirection::HostToDevice as H2D;

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
pub enum RequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
    Reserved = 3,
}

use RequestType as RT;

#[derive(PrimitiveEnum, Clone, Copy, Debug)]
pub enum RequestRecipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
}

use RequestRecipient as RR;

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

use StandardRequest as SR;

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
    OTG = 9,
    Debug = 10,
    InterfaceAssociation = 11,
    BOS = 15,
    DeviceCapability = 16,
    SuperspeedUsbEndpointCompanion = 48,
    SuperspeedplusIsochronousEndpointCompanion = 49,
}

use DescriptorType as DT;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
struct usb_hid_descriptor {
    bLength: u8,
    bDescriptorType: u8,
    bcdHID: u16,
    bCountryCode: u8,
    bNumDescriptors: u8,
    bReportDescriptorType: u8,
    wReportDescriptorLength: u16,
    // ... optional other descriptors type/length pairs
}

pub struct Device {
    pub device_descriptor: usb_device_descriptor,
    pub config_descriptor: usb_config_descriptor,
    pub interface_descriptor: usb_interface_descriptor,
    hid_descriptor: usb_hid_descriptor,
    hid_report_descriptor: Vec<u8>,
    endpoint_descriptors: Vec<usb_endpoint_descriptor>,
    strings: Vec<&'static str>,
    endpoints: Vec<Sender<Box<URB>>>,
}

// USB Request Block
pub struct URB {
    pub endpoint: u8,
    pub setup: [u8; 8],
    pub transfer_buffer: Option<Vec<u8>>,
    pub transfer_buffer_length: usize,
    pub complete: Option<CompletionFn>,
}
type CompletionResult = Result<Option<Vec<u8>>, CompletionError>;
type CompletionFn =
    Box<dyn FnOnce(Box<URB>, Option<Vec<u8>>) -> CompletionResult + Send>;
#[derive(Debug)]
pub enum CompletionError {
    Unlinked(Option<Vec<u8>>), // the URB was unlinked and should be ignored
}

impl URB {
    pub fn complete(
        mut self: Box<Self>,
        transfer_buffer: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, CompletionError> {
        let f = self.complete.take().unwrap();
        f(self, transfer_buffer)
    }
}

impl Device {
    pub fn new(endpoints: Vec<Sender<Box<URB>>>) -> Self {
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
            .into_iter()
            .flatten()
            .collect()
        };

        Self {
            device_descriptor: usb_device_descriptor {
                bLength: size_of::<usb_device_descriptor>() as u8,
                bDescriptorType: DT::Device.to_primitive(),
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
                bLength: size_of::<usb_config_descriptor>() as u8,
                bDescriptorType: DT::Configuration.to_primitive(),
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
                bLength: size_of::<usb_interface_descriptor>() as u8,
                bDescriptorType: DT::Interface.to_primitive(),
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
            hid_report_descriptor,
            endpoint_descriptors: vec![
                usb_endpoint_descriptor {
                    bLength: USB_DT_ENDPOINT_SIZE as u8,
                    bDescriptorType: DT::Endpoint.to_primitive(),
                    bEndpointAddress: ((1 & USB_ENDPOINT_NUMBER_MASK)
                        | (USB_DIR_IN & USB_ENDPOINT_DIR_MASK))
                        as u8,
                    bmAttributes: USB_ENDPOINT_XFER_INT as u8,
                    wMaxPacketSize: (((64 & USB_ENDPOINT_MAXP_MASK)
                        as u16)
                        .to_le()),
                    bInterval: 5, //255,
                    bRefresh: 0,
                    bSynchAddress: 0,
                },
                usb_endpoint_descriptor {
                    bLength: USB_DT_ENDPOINT_SIZE as u8,
                    bDescriptorType: DT::Endpoint.to_primitive(),
                    bEndpointAddress: ((2 & USB_ENDPOINT_NUMBER_MASK)
                        | (USB_DIR_OUT & USB_ENDPOINT_DIR_MASK))
                        as u8,
                    bmAttributes: USB_ENDPOINT_XFER_INT as u8,
                    wMaxPacketSize: ((64 & USB_ENDPOINT_MAXP_MASK) as u16)
                        .to_le(),
                    bInterval: 5, //255,
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
            endpoints,
        }
    }

    pub fn submit(&self, urb: Box<URB>) -> R<()> {
        let setup = SetupPacket::unpack(&urb.setup).unwrap();
        match (urb.endpoint, setup.direction()) {
            (0, D2H) => {
                let buf = self.ep0_dev2host(setup);
                urb.complete(Some(buf)).unwrap();
            }
            (0, H2D) => {
                self.ep0_host2dev(setup);
                urb.complete(None).unwrap();
            }
            (n, _) => self.endpoints[n as usize - 1].send(urb).unwrap(),
        };
        Ok(())
    }

    fn get_lang_descriptor(&self) -> Vec<u8> {
        let d = usb_string_descriptor {
            bLength: size_of::<usb_string_descriptor>() as u8,
            bDescriptorType: DT::String.to_primitive(),
            wData: [LANG_ID_EN_US.to_le()],
        };
        let mut vec =
            Vec::with_capacity(size_of::<usb_string_descriptor>());
        write_struct(&mut vec, &d).unwrap();
        vec
    }

    fn get_string_descriptor(&self, index: u8) -> Vec<u8> {
        assert!(index > 0);
        let text = self.strings[index as usize];
        let utf16_len = text.encode_utf16().count();
        let mut v =
            vec![2 + (utf16_len * 2) as u8, DT::String.to_primitive()];
        text.encode_utf16().for_each(|u| {
            let bs = u.to_le_bytes();
            v.push(bs[0]);
            v.push(bs[1])
        });
        v
    }

    fn get_descriptor(&self, req: SetupPacket) -> Vec<u8> {
        let (value, lang, length) = req.args();
        let [index, ty] = value.to_le_bytes();
        let r#type = DT::from_primitive(ty).unwrap();
        log!(
            USB,
            "GET_DESCRIPTOR: type: {:?} index: {} lang: {} length: {} ",
            r#type,
            index,
            lang,
            length
        );
        let mut out = vec![0u8; length as usize];
        use std::io::Cursor;
        let sink = &mut Cursor::<&mut [u8]>::new(&mut out);
        fn has_room(c: &std::io::Cursor<&mut [u8]>) -> bool {
            (c.position() as usize) < (c.get_ref().len() as usize)
        }
        use DescriptorType::*;
        match (r#type, index, lang) {
            (Device, 0, 0) => {
                write_struct(sink, &self.device_descriptor).unwrap();
                out
            }
            (Configuration, 0, 0) => {
                write_struct(sink, &self.config_descriptor).unwrap();
                if has_room(sink) {
                    write_struct(sink, &self.interface_descriptor)
                        .unwrap();
                    write_struct(sink, &self.hid_descriptor).unwrap();
                    for epd in self.endpoint_descriptors.iter() {
                        let len = epd.bLength as usize;
                        write_struct_limited(sink, epd, len).unwrap()
                    }
                }
                out
            }
            (String, 0, 0) => self.get_lang_descriptor(),
            (String, i, LANG_ID_EN_US) => self.get_string_descriptor(i),
            (Debug, 0, 0) => vec![], // Hmm. not sure what to do here
            _ => todo!("GET_DESCRIPTOR: type={type:?} index={index}"),
        }
    }

    fn get_interface_descriptor(&self, req: SetupPacket) -> Vec<u8> {
        let (value, _, _) = req.args();
        let [_, desctype] = value.to_le_bytes();
        match desctype as u32 {
            HID_DT_REPORT => self.hid_report_descriptor.clone(),
            _ => todo!(),
        }
    }

    fn ep0_dev2host(&self, req: SetupPacket) -> Vec<u8> {
        match req.request_type() {
            (D2H, RT::Standard, RR::Device) => match req.std() {
                SR::GetDescriptor => self.get_descriptor(req),
                SR::GetStatus if req.args() == (0, 0, 2) => vec![1u8, 0],
                _ => todo!(),
            },
            (D2H, RT::Standard, RR::Interface) => match req.std() {
                SR::GetDescriptor => self.get_interface_descriptor(req),
                _ => todo!(),
            },
            _ => todo!(),
        }
    }

    fn ep0_host2dev(&self, req: SetupPacket) {
        match req.request_type() {
            (H2D, RT::Standard, RR::Device) => match req.std() {
                SR::SetConfiguration if req.args() == (0, 0, 0) => (),
                _ => todo!(),
            },
            (H2D, RT::Class, RR::Interface) => match req.hid_request() {
                (HIDRequest::SetIdle, (0, 0, 0)) => (),
                _ => todo!(),
            },
            _ => todo!(),
        }
    }
}

#[test]
fn test_get_device_descriptor() {
    let dev = Device::new(vec![]);
    const GET_DEVICE_DESCRIPTOR: &[u8; 8] =
        include_bytes!("../poke/get-device-descriptor.dat");
    let setup = SetupPacket::unpack(GET_DEVICE_DESCRIPTOR).unwrap();
    let mut vec = dev.ep0_dev2host(setup);
    vec.resize(size_of::<usb_device_descriptor>(), 0);
    let d = crate::binio::test::view_as::<usb_device_descriptor>(&vec);
    assert_eq!(d.bLength, size_of::<usb_device_descriptor>() as u8);
    assert_eq!(d.bDescriptorType, DT::Device.to_primitive());
    assert_eq!(d.bDeviceClass, USB_CLASS_PER_INTERFACE as u8);
    assert_eq!(d.bNumConfigurations, 1);
    ()
}

#[test]
fn test_get_interface_descriptor() {
    let dev = Device::new(vec![]);
    let setup = SetupPacket {
        bm_request_type: BmRequestType {
            direction: D2H,
            recipient: RR::Interface,
            type_: RT::Standard,
        },
        b_request: (SR::GetDescriptor).to_primitive(),
        w_index: 0,
        w_length: 64,
        w_value: u16::from_le_bytes([0, HID_DT_REPORT as u8]),
    };
    let v = dev.ep0_dev2host(setup);
    use hid::*;
    assert_eq!(v[..3], usage_page(FIDO));
    assert_eq!(v[3..5], usage(CTAPHID));
    ()
}
