# Softfido

Softfido is a software implementation of a
[FIDO2/U2F](https://fidoalliance.org/fido2/) authenticator.  Most
FIDO2 authenticators are based on hardware like USB sticks or TPM-like
chips in smartphones.  Softfido instead implements a virtual USB
device (via [USBIP](https://wiki.archlinux.org/index.php/USB/IP)) so
that webbrowsers can talk to it.

The cryptographic operations are delegated to
[SoftHSM](https://www.opendnssec.org/softhsm/). In theory other PKCS11
modules could be used, but I only tested with SoftHSM.

# Build

```
cargo build
```

Some USBIP related kernel headers must be installed during the build.

# Use

## Set up SoftHSM

Create a SoftHSM token with the following command:

```
softhsm2-util --init-token --free --label softfido
```

## Start Softfido

```softfido --token-label softfido```

This should print something like
```
softfido::crypto: Generating secret key...
softfido::crypto: Generating token counter...
Softfido server running.
```

You may need to specify the --pkcs11-module argument if libsofthsm2.so
is not installed in /usr/lib/softhsm/libsofthsm2.so.

## Kernel module

Insert the vhci-hcd module with:
```modprobe vhci-hcd```

Connet the kernel module to the server:
```usbip attach -r 127.0.0.1 -d 1-1```

After that `lsusb -d 0:0 -v` should describe the virtual USB device.
`ls -l /sys/class/hidraw/` should also list a link to a vhci_hcd
device.

## Device mermissions

To allow non-root users to open the virtual hidraw device, its
permissions must be setup accordingly.  This can be done manually with
`chmod` or with an udev rule like so:

```
SUBSYSTEM=="hidraw", ATTRS{manufacturer}=="Fakecompany", \
,ATTRS{product}=="Softproduct", TAG+="uaccess", GROUP="plugdev", MODE="0660"
```

## Testing

The `python/` directory contains some (interactive) tests. You can run
them with ```python3 softfido_tests.py```.  The tests require the
[`fido2`](https://pypi.org/project/fido2/) Python module.

## Test in browser

You can test the authenticator on [Yubico's test
page](https://demo.yubico.com/webauthn-technical/registration) or
[webauthn.io](https://webauthn.io/).

At the time of writing, Firefox only supports U2F but not FIDO2.
Chromium supports both.  In my experience, the only website that uses
FIDO2 when available is github.com; all others use U2F even if the
device and the browser would support FIDO2.

# Webauthn with a TPM

Some time after I had started Softfido, I found [James Bottomley's
Webauthn on TPM
project](https://blog.hansenpartnership.com/webauthn-in-linux-with-a-tpm-via-the-hid-gadget/).
He describes the technical issues pretty well.  He uses the [HID
Gadget](https://www.kernel.org/doc/html/latest/usb/gadget_hid.html)
machinery, which would probably have been a bit easier than USBIP.
OTOH, with USBIP the authenticator can run on a different machine than
the kernel module which is useful to sidestep kernel bugs.  During
development I had a few kernel crashes. After debugging my code, the
only kernel related issue that I'm aware off is that the kernel cannot
properly hibernate as long as the virtual device is connected.
Removing the kernel module `rmmod vhci-hcd` before hibernating is
advisable.

# Caution

Softfido is just a hobby project of mine to learn a bit about Rust,
USB, FIDO2, and cryptography.  The code is potentially insecure.  Use
it at your own risk.
