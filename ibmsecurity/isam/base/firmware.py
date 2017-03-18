import logging
import ibmsecurity.utilities.tools

logger = logging.getLogger(__name__)


def get(isamAppliance, check_mode=False, force=False):
    """
    Retrieve existing firmware.
    """
    return isamAppliance.invoke_get("Retrieving firmware",
                                    "/firmware_settings")


def backup(isamAppliance, check_mode=False, force=False):
    """
    Kickoff Backup of active partition
    """
    if check_mode is True:
        return isamAppliance.create_return_object(changed=True)
    else:
        return isamAppliance.invoke_put("Kickoff Backup of Active Partition",
                                        "/firmware_settings/kickoff_backup", {})


def swap(isamAppliance, check_mode=False, force=False):
    """
    Kickoff swap of active partition
    """
    if check_mode is True:
        return isamAppliance.create_return_object(changed=True)
    else:
        ret_obj_old = get(isamAppliance)

        ret_obj = isamAppliance.invoke_put("Kickoff swap of Active Partition",
                                           "/firmware_settings/kickoff_swap", {})
        # Process previous query after a successful call to swap the partition
        for partition in ret_obj_old['data']:
            if partition['active'] is False:  # Get version of inactive partition (active now!)
                ver = partition['firmware_version'].split(' ')
                isamAppliance.facts['version'] = ver[-1]

        return ret_obj


def set(isamAppliance, id, comment, check_mode=False, force=False):
    """
    Update comment on partition
    """
    if force is True or _check_comment(isamAppliance, comment) is False:
        if check_mode is True:
            return isamAppliance.create_return_object(changed=True)
        else:
            return isamAppliance.invoke_put("Update comment on Partition",
                                            "/firmware_settings/{0}".format(id),
                                            {'comment': comment})

    return isamAppliance.create_return_object()


def _check_comment(isamAppliance, comment):
    ret_obj = get(isamAppliance)

    # Loop through firmware partitions looking for active one
    for partition in ret_obj['data']:
        if partition['active'] is True:
            return (partition['comment'] == comment)

    return False


def compare(isamAppliance1, isamAppliance2):
    """
    Compare firmware between two appliances
    """
    ret_obj1 = get(isamAppliance1)
    ret_obj2 = get(isamAppliance2)

    for obj in ret_obj1['data']:
        del obj['install_date']
        del obj['backup_date']
        del obj['last_boot']
    for obj in ret_obj2['data']:
        del obj['install_date']
        del obj['backup_date']
        del obj['last_boot']

    return ibmsecurity.utilities.tools.json_compare(ret_obj1, ret_obj2,
                                                    deleted_keys=['install_date', 'backup_date', 'last_boot'])
