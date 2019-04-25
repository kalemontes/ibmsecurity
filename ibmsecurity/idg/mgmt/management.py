import json
import logging
import time
import ibmsecurity.isam.base.lmi

logger = logging.getLogger(__name__)


def available(idgAppliance, check_mode=False, force=False):
    """
    """
    if check_mode is True:
        return idgAppliance.create_return_object(changed=True)
    else:
        return idgAppliance.invoke_get("Rebooting appliance",
                                         "/diagnostics/restart_shutdown/reboot",
                                         {})