import logging
from ibmsecurity.utilities import tools
from ibmsecurity.appliance.ibmappliance import IBMError

logger = logging.getLogger(__name__)

# URI for this module
uri = "/mgmt/filestore/{0}/local"

def get_all(idgAppliance, dir_path='', check_mode=False, force=False):
    """
    Retrieving the contents of a directory from the application domain local files area
    """
    domain_uri = uri.format(idgAppliance.domain)
    return idgAppliance.invoke_get("Retrieving the contents of a directory from the application domain local files area",
                                    _dpPathJoin(domain_uri, dir_path))

def get(idgAppliance, file_path, save_to, check_mode=False, force=False):
    """
    Downloading a file from the application domain local files area
    """
    domain_uri = uri.format(idgAppliance.domain)
    return idgAppliance.invoke_get_file("Downloading a file from the application domain local files area",
                                    _dpPathJoin(domain_uri, file_path), 
                                    save_to)

def add(idgAppliance, dir_path, file_name, file_path=None, check_mode=False, force=False):
    """
    Add a file to the application domain local files area. If file_name and file_path are empty it will create the directory instead.
    """
    domain_uri = uri.format(idgAppliance.domain)
    domain_dir = _dpPathJoin(domain_uri, dir_path)

    if file_path is None:
        if _check(idgAppliance, dir_path, file_name) is False:
            if check_mode is True:
                return idgAppliance.create_return_object(changed=True)
            else:
                return idgAppliance.invoke_post_file(
                    "Add directory {0} to the local files area".format(domain_dir),
                    domain_dir,
                    file_name)
    else:
        if force is True or _check(idgAppliance, dir_path, file_name) is False:
            if check_mode is True:
                return idgAppliance.create_return_object(changed=True)
            else:
                return idgAppliance.invoke_post_file(
                    "Add file {0} to {1}".format(file_name, domain_dir),
                    domain_dir,
                    file_name,
                    file_path)

    return idgAppliance.create_return_object()

def update(idgAppliance, dir_path, filename, file_path, check_mode=False, force=False):
    """
    Update a specified file from the application domain local files area
    """
    update_required = False
    add_required = False
    domain_uri = uri.format(idgAppliance.domain)
    domain_dir = _dpPathJoin(domain_uri, dir_path)

    compare_to_path = "{0}/{1}".format(tools.get_random_temp_dir(), filename) #TODO: this should be path.join with os lib
    try:
       get(idgAppliance, _dpPathJoin(dir_path, filename), compare_to_path)
       if not tools.files_same(file_path, compare_to_path):
           update_required = True
    except IBMError:
        update_required = True
        add_required = True

    if force is True or update_required is True:
        if check_mode is True:
            return idgAppliance.create_return_object(changed=True)
        else:
            if force is True and add_required is True:
                return idgAppliance.invoke_post_file(
                    "Add file {0} to {1}".format(filename, domain_dir),
                    domain_dir,
                    filename,
                    file_path)
            else:
                return idgAppliance.invoke_put_file(
                    "Update {0} from the application domain local at {1}".format(filename, dir_path),
                    domain_dir,
                    filename,
                    file_path
                    )
    return idgAppliance.create_return_object()

def delete(idgAppliance, dir_path, filename, check_mode=False, force=False):
    """
    Delete a mapping rule
    """
    domain_uri = uri.format(idgAppliance.domain)
    domain_dir = _dpPathJoin(domain_uri, dir_path)

    if force is True or _check(idgAppliance, dir_path, filename) is True:
        if check_mode is True:
            return idgAppliance.create_return_object(changed=True)
        else:
            return idgAppliance.invoke_delete(
                "Delete file {0} to {1}".format(filename, domain_dir),
                _dpPathJoin(domain_dir, filename))
    return idgAppliance.create_return_object()

def _check(isamAppliance, file_path, file_name):
    """
    Check if file already exists.
    """
    ret_obj = get_all(isamAppliance, file_path)

    if 'file' in ret_obj['data']['filestore']['location']:
        if isinstance(ret_obj['data']['filestore']['location']['file'], list) :
            for obj in ret_obj['data']['filestore']['location']['file']:
                if obj['name'] == file_name:
                    return True
        else:
            if ret_obj['data']['filestore']['location']['file']['name'] == file_name:
                return True
    elif 'directory' in ret_obj['data']['filestore']['location']:
        if isinstance(ret_obj['data']['filestore']['location']['directory'], list) :
            for obj in ret_obj['data']['filestore']['location']['directory']:
                if obj['name'].split('/')[-1]  == file_name:
                    return True
        else:
            if ret_obj['data']['filestore']['location']['directory']['name'].split('/')[-1] == file_name:
                return True
    return False

def _dpPathJoin(dir_path, file_name):
    return "{0}/{1}".format(dir_path, file_name).replace('//','/').rstrip('/')