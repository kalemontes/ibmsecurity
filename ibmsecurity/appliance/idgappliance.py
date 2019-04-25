import json
import requests
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from .ibmappliance import IBMAppliance
from .ibmappliance import IBMError
from .ibmappliance import IBMFatal
from ibmsecurity.utilities import tools


class IDGAppliance(IBMAppliance):
    def __init__(self, hostname, user, domain='default', rest_port=5554):
        self.logger = logging.getLogger(__name__)
        self.logger.debug('Creating an IDGAppliance')
        try:
            basestring
        except NameError:
            basestring = str
        if isinstance(rest_port, basestring):
            self.rest_port = int(rest_port)
        else:
            self.rest_port = rest_port
        self.session = requests.session()
        self.session.auth = (user.username, user.password)
        self.domain = domain
        IBMAppliance.__init__(self, hostname, user)

    def _url(self, uri):
        # Build up the URL
        url = "https://" + self.hostname + ":" + str(self.rest_port) + uri
        self.logger.debug("Issuing request to: " + url)
        return url

    def _file_url(self, uri, filename):
        # Build up the URL
        url = "https://" + self.hostname + ":" + str(self.rest_port) + uri + "/" + filename
        self.logger.debug("Issuing request to: " + url)
        return url

    def _log_desc(self, description):
        if description != "":
            self.logger.info('*** ' + description + ' ***')

    def _suppress_ssl_warning(self):
        # Disable https warning because of non-standard certs on appliance
        try:
            self.logger.debug("Suppressing SSL Warnings.")
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except AttributeError:
            self.logger.warning("load requests.packages.urllib3.disable_warnings() failed")

    def _process_response(self, return_obj, http_response, ignore_error):

        return_obj['rc'] = http_response.status_code

        # Examine the response.
        if (http_response.status_code == 403):
            self.logger.error("  Request failed: ")
            self.logger.error("     status code: {0}".format(http_response.status_code))
            if http_response.text != "":
                self.logger.error("     text: " + http_response.text)
            # Unconditionally raise exception to abort execution
            raise IBMFatal("HTTP Return code: {0}".format(http_response.status_code), http_response.text)
        elif (
                http_response.status_code != 200 and http_response.status_code != 204 and http_response.status_code != 201):
            self.logger.error("  Request failed: ")
            self.logger.error("     status code: {0}".format(http_response.status_code))
            if http_response.text != "":
                self.logger.error("     text: " + http_response.text)
            if not ignore_error:
                raise IBMError("HTTP Return code: {0}".format(http_response.status_code), http_response.text)
            return_obj['changed'] = False  # force changed to be False as there is an error
        else:
            return_obj['rc'] = 0

            # Handle if there was json on input but response was not in json format
        try:
            json_data = json.loads(http_response.text)
        except ValueError:
            return_obj['data'] = http_response.content
            return

        self.logger.debug("Status Code: {0}".format(http_response.status_code))
        if http_response.text != "":
            self.logger.debug("Text: " + http_response.content.decode("utf-8"))

        for key in http_response.headers:
            if key == 'g-type':
                if http_response.headers[key] == 'application/octet-stream; charset=UTF-8':
                    json_data = {}
                    return_obj.data = http_response.content
                    return

        if http_response.text == "":
            json_data = {}
        else:
            json_data = json.loads(http_response.text)

        if 'result' in json_data:
            return_obj['data'] = json_data['result']
        else:
            return_obj['data'] = json_data

    def _process_connection_error(self, ignore_error, return_obj):
        if not ignore_error:
            self.logger.critical("Failed to connect to server.")
            raise IBMError("HTTP Return code: 502", "Failed to connect to server")
        else:
            self.logger.debug("Failed to connect to server.")
            return_obj['rc'] = 502


    def invoke_post_file(self, description, uri, filename, filedata=None, ignore_error=False, warnings=[], json_response=True):
        """
        Send multipart/form-data upload file request to the appliance.
        """
        self._log_desc(description=description)

        return_obj = self.create_return_object(warnings=warnings)
        
        file2post = dict()
        if filedata is None:
            file2post['directory'] = dict()
            file2post['directory']['name'] = filename
        else :    
            file2post['file'] = dict()
            file2post['file']['name'] = filename

            with open(filedata, "rb") as data_file:
                file2post['file']['content'] = base64.b64encode(data_file.read()).decode("utf-8")
        json_data = json.dumps(file2post)

        self._suppress_ssl_warning()

        try:
            r = self.session.post(url=self._url(uri=uri), data=json_data, verify=False)
            return_obj['changed'] = True  # POST of file would be a change
            self._process_response(return_obj=return_obj, http_response=r, ignore_error=ignore_error)

        except requests.exceptions.ConnectionError:
            if not ignore_error:
                self.logger.critical("Failed to connect to server.")
                raise IBMError("HTTP Return code: 502", "Failed to connect to server")
            else:
                self.logger.debug("Failed to connect to server.")
                return_obj.rc = 502

        return return_obj

    def invoke_put_file(self, description, uri, filename, filedata, ignore_error=False, warnings=[]):
        """
        Send multipart/form-data upload file request to the appliance.
        """
        self._log_desc(description=description)

        return_obj = self.create_return_object(warnings=warnings)

        file2post = dict()
        file2post['file'] = dict()
        file2post['file']['name'] = filename
        with open(filedata, "rb") as data_file:
             file2post['file']['content'] = base64.b64encode(data_file.read()).decode("utf-8")
        json_data = json.dumps(file2post)

        self._suppress_ssl_warning()

        try:
            r = self.session.put(url=self._file_url(uri=uri, filename=filename), data=json_data, verify=False)
            return_obj['changed'] = True  # POST of file would be a change
            self._process_response(return_obj=return_obj, http_response=r, ignore_error=ignore_error)

        except requests.exceptions.ConnectionError:
            if not ignore_error:
                self.logger.critical("Failed to connect to server.")
                raise IBMError("HTTP Return code: 502", "Failed to connect to server")
            else:
                self.logger.debug("Failed to connect to server.")
                return_obj.rc = 502

        return return_obj

    def invoke_get_file(self, description, uri, filename, ignore_error=False, warnings=[]):
        """
        Invoke a GET request and download the response data to a file
        """
        self._log_desc(description=description)

        return_obj = self.create_return_object(warnings=warnings)

        self._suppress_ssl_warning()

        try:
            r = self.session.get(url=self._url(uri=uri), verify=False)

            if (r.status_code != 200 and r.status_code != 204 and r.status_code != 201):
                self.logger.error("  Request failed: ")
                self.logger.error("     status code: {0}".format(r.status_code))
                if r.text != "":
                    self.logger.error("     text: " + r.text)
                if not ignore_error:
                    raise IBMError("HTTP Return code: {0}".format(r.status_code), r.text)
                else:
                    return_obj['rc'] = r.status_code
                    return_obj['data'] = {'msg': 'Unable to extract contents to file!'}
            else:
                with open(filename, 'wb') as f:
                    if r.content :
                        json_data = json.loads(r.content)
                        f_data = base64.b64decode(json_data['file'])
                        f.write(f_data)
                        return_obj['rc'] = 0
                        return_obj['data'] = {'msg': 'Contents extracted to file: ' + filename}
        except requests.exceptions.ConnectionError:
            self._process_connection_error(ignore_error=ignore_error, return_obj=return_obj)

        except IOError:
            if not ignore_error:
                self.logger.critical("Failed to write to file: " + filename)
                raise IBMError("HTTP Return code: 999", "Failed to write to file: " + filename)
            else:
                self.logger.debug("Failed to write to file: " + filename)
                return_obj['rc'] = 999

        return return_obj

    def _invoke_request(self, func, description, uri, ignore_error, data={}, requires_modules=None,
                        requires_version=None, warnings=[]):
        """
        Send a request to the Rest API.  This function is private and should not be
        used directly.  The invoke_get/invoke_put/etc functions should be used instead.
        """
        self._log_desc(description=description)
        return_obj = self.create_return_object()

        # There maybe some cases when header should be blank (not json)
        headers = {
            'Accept': 'application/json',
            'Content-type': 'application/json'
        }
        self.logger.debug("Headers are: {0}".format(headers))

        # Process the input data into JSON
        json_data = json.dumps(data)

        self.logger.debug("Input Data: " + json_data)

        self._suppress_ssl_warning()

        try:
            if func == self.session.get or func == self.session.delete:
                if data != {}:
                    r = func(url=self._url(uri), data=json_data, verify=False, headers=headers)
                else:
                    r = func(url=self._url(uri), verify=False, headers=headers)
            else:
                r = func(url=self._url(uri), data=json_data,
                         verify=False, headers=headers)

            if func != self.session.get:
                return_obj['changed'] = True  # Anything but GET should result in change

            self._process_response(return_obj=return_obj, http_response=r, ignore_error=ignore_error)

        except requests.exceptions.ConnectionError:
            self._process_connection_error(ignore_error=ignore_error, return_obj=return_obj)

        return return_obj


    def invoke_get(self, description, uri, ignore_error=False, requires_modules=None, requires_version=None,
                   warnings=[]):
        """
        Send a GET request to the LMI.
        """
        self._log_request("GET", uri, description)

        response = self._invoke_request(self.session.get, description, uri,
                                        ignore_error, requires_modules=requires_modules,
                                        requires_version=requires_version, warnings=warnings)
        self._log_response(response)
        return response

    def invoke_delete(self, description, uri, ignore_error=False, requires_modules=None, requires_version=None,
                      warnings=[]):
        """
        Send a DELETE request to the LMI.
        """
        self._log_request("DELETE", uri, description)
        response = self._invoke_request(self.session.delete, description, uri,
                                        ignore_error, requires_modules=requires_modules,
                                        requires_version=requires_version, warnings=warnings)
        self._log_response(response)
        return response
    
    def _log_request(self, method, url, desc):
        self.logger.debug("Request: %s %s desc=%s", method, url, desc)

    def _log_response(self, response):
        if response:
            self.logger.debug("Response: %d", response.get('rc'))
            # self.logger.debug("Response: %i %i warnings:%s",
            #                     response.get('rc'),
            #                     response.get('status_code'),
            #                     response.get('warnings'))
        else:
            self.logger.debug("Response: None")
