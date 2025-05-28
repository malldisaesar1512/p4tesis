import sys
import logging
import time

import p4runtime_sh.shell as sh
import p4runtime_shell_utils as shu

logger = logging.getLogger(None)
logger.setLevel(logging.INFO)

grpc_addrp4 = 'localhost:9559'
p4info_path = './forwarding.p4info.txtpb'
json_path = './finalospf.json'
# you can omit the config argument if the switch is already configured with the
# correct P4 dataplane.
sh.setup(
    device_id=1,
    grpc_addr=grpc_addrp4,
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig(p4info_path, json_path)
)

logger.info('P4Runtime shell setup complete.')

# see p4runtime_sh/test.py for more examples
te = sh.TableEntry('MyIngress.ipv4_lpm')(action='MyIngress.ipv4_forward',)
te.match['hdr.ipv4.dstAddr'] = '10.10.2.0/24'
te.action['dstAddr'] = '50:00:00:00:30:00'
te.action['port'] = 1
te.insert()

# ...

sh.teardown()