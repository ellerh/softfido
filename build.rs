extern crate bindgen;

fn main() {
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/bindings.h")
        .allowlist_type("op_common")
        .allowlist_type("op_devlist_reply")
        .allowlist_type("op_devlist_reply_extra")
        .allowlist_type("op_import_request")
        .allowlist_type("usbip_header")
        .allowlist_var("OP_REQ_DEVLIST")
        .allowlist_var("OP_REP_DEVLIST")
        .allowlist_var("OP_REQ_IMPORT")
        .allowlist_var("OP_REP_IMPORT")
        .allowlist_var("USBIP_CMD_SUBMIT")
        .allowlist_var("USBIP_RET_SUBMIT")
        .allowlist_var("USBIP_CMD_UNLINK")
        .allowlist_var("USBIP_RET_UNLINK")
        .allowlist_var("USBIP_DIR_IN")
        .allowlist_var("USBIP_DIR_OUT")
        .allowlist_var("USBIP_DIR_OUT")
        .allowlist_type("usb_ctrlrequest")
        .allowlist_type("usb_device_descriptor")
        .allowlist_type("usb_config_descriptor")
        .allowlist_type("usb_interface_descriptor")
        .allowlist_type("usb_endpoint_descriptor")
        .allowlist_type("usb_string_descriptor")
        .allowlist_var("USB_CONFIG_ATT_ONE")
        .allowlist_var("USB_CONFIG_ATT_SELFPOWER")
        .allowlist_var("USB_CLASS_PER_INTERFACE")
        .allowlist_var("USB_CLASS_HID")
        .allowlist_var("USB_DT_ENDPOINT_SIZE")
        .allowlist_var("USB_ENDPOINT_NUMBER_MASK")
        .allowlist_var("USB_DIR_IN")
        .allowlist_var("USB_DIR_OUT")
        .allowlist_var("USB_ENDPOINT_DIR_MASK")
        .allowlist_var("USB_ENDPOINT_XFER_INT")
        .allowlist_var("USB_ENDPOINT_MAXP_MASK")
        .allowlist_var("EINPROGRESS")
        .allowlist_var("ENOENT")
        .allowlist_var("HID_DT_HID")
        .allowlist_var("HID_DT_REPORT")
        // .allowlist_var("USB_TYPE_STANDARD")
        // .allowlist_var("USB_TYPE_CLASS")
        // .allowlist_var("USB_TYPE_VENDOR")
        // .allowlist_var("USB_RECIP_DEVICE")
        // .allowlist_var("USB_RECIP_INTERFACE")
        // .allowlist_var("USB_RECIP_ENDPOINT")
        // .allowlist_var("USB_RECIP_OTHER")
        // .allowlist_var("USB_DIR_IN")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
