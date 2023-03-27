
# The check target assumens that a properly configured VM is running.
# The VM should expose an SSH server on 127.0.0.1:2222 and the host
# directory should be mounted inside the VM under ~user/softfido.

SSH=ssh -p 2222 user@127.0.0.1
HOSTIP=$(word 1,$(shell hostname -I))

check: ensure-vm-running build-test-server
	cargo run --bin test-server \
	2>/tmp/test-server.stderr >/tmp/test-server.stdout & \
        trap "kill $$!" EXIT && \
	until grep -q listening /tmp/test-server.stdout ; do \
	   sleep 0.2 ; \
        done && \
	$(SSH) "sudo usbip attach -r $(HOSTIP) -d 1-1 && \
	cd softfido/python && make test"

ensure-vm-running:
	$(SSH) 'sudo modprobe vhci-hcd'

build-test-server:
	cargo build --bin test-server

test:
	 PYTHONPATH=/scratch/usb-fido/python-fido2/ \
         python3 softfido_tests.py
