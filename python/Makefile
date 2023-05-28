
test:
	PYTHONPATH=/scratch/usb-fido/python-fido2/ \
	python3 softfido_tests.py

# The check target assumes that a properly configured VM is running.
# The VM should expose an SSH server on 127.0.0.1:2222 and the softido
# directory should be mounted inside the VM under ~user/softfido.

SSH=ssh -p 2222 user@127.0.0.1
HOSTIP=$(word 1,$(shell hostname -I))

check: ensure-vm-running build-test-server
	set -e ; \
	rm -f /tmp/test-server.stdout ; \
	cargo run --bin test-server \
	2>/tmp/test-server.stderr >/tmp/test-server.stdout & \
        trap "kill $$!" EXIT 15 2 ; \
	until grep -q listening /tmp/test-server.stdout ; do \
	   sleep 0.2 ; \
        done && \
	$(SSH) "sudo usbip attach -r $(HOSTIP) -d 1-1 && \
	cd softfido/python && \
	for i in 1 2 ; do \
          make test; \
        done"

ensure-vm-running:
	$(SSH) 'sudo modprobe vhci-hcd'

build-test-server:
	cargo build --bin test-server
