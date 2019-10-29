extern crate bindgen;

fn main() {
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/x.h")
        .whitelist_type("op_common")
        .whitelist_type("op_devlist_reply")
        .whitelist_type("op_devlist_reply_extra")
        .whitelist_type("op_import_request")
        .whitelist_type("usbip_header")
        .whitelist_var("OP_REQ_DEVLIST")
        .whitelist_var("OP_REP_DEVLIST")
        .whitelist_var("OP_REQ_IMPORT")
        .whitelist_var("OP_REP_IMPORT")
        .whitelist_var("USBIP_CMD_SUBMIT")
        .whitelist_var("USBIP_RET_SUBMIT")
        .whitelist_var("USBIP_CMD_UNLINK")
        .whitelist_var("USBIP_RET_UNLINK")
        .whitelist_var("USBIP_DIR_IN")
        .whitelist_var("USBIP_DIR_OUT")
        .whitelist_var("USBIP_DIR_OUT")
        .whitelist_type("usb_ctrlrequest")
        .whitelist_type("usb_device_descriptor")
        .whitelist_type("usb_config_descriptor")
        .whitelist_type("usb_interface_descriptor")
        .whitelist_type("usb_endpoint_descriptor")
        .whitelist_type("usb_string_descriptor")
        .whitelist_var("USB_CONFIG_ATT_ONE")
        .whitelist_var("USB_CONFIG_ATT_SELFPOWER")
        .whitelist_var("USB_CLASS_PER_INTERFACE")
        .whitelist_var("USB_CLASS_HID")
        .whitelist_var("USB_DT_ENDPOINT_SIZE")
        .whitelist_var("USB_ENDPOINT_NUMBER_MASK")
        .whitelist_var("USB_DIR_IN")
        .whitelist_var("USB_DIR_OUT")
        .whitelist_var("USB_ENDPOINT_DIR_MASK")
        .whitelist_var("USB_ENDPOINT_XFER_INT")
        .whitelist_var("USB_ENDPOINT_MAXP_MASK")
        .whitelist_var("EINPROGRESS")
        .whitelist_var("ENOENT")
        .whitelist_var("HID_DT_HID")
        .whitelist_var("HID_DT_REPORT")
        // .whitelist_var("USB_TYPE_STANDARD")
        // .whitelist_var("USB_TYPE_CLASS")
        // .whitelist_var("USB_TYPE_VENDOR")
        // .whitelist_var("USB_RECIP_DEVICE")
        // .whitelist_var("USB_RECIP_INTERFACE")
        // .whitelist_var("USB_RECIP_ENDPOINT")
        // .whitelist_var("USB_RECIP_OTHER")
        // .whitelist_var("USB_DIR_IN")

        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
