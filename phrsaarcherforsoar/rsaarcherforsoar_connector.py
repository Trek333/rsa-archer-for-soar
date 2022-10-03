#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from rsaarcherforsoar_consts import *
import requests
import json
from bs4 import BeautifulSoup
import sys

# Imports local to this App
import rsaarcherforsoar_consts as consts
from archer_soap import ArcherSOAP
import archer_utils


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RsaArcherForSoarConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RsaArcherForSoarConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self.base_url = None
        self.userName = None
        self.password = None
        self.instanceName = None
        self.verifySSL = None
        self.usersDomain = None
        self.asoap = None
        self.python_version = None
        self.proxy = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self.base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make get_token call
        ret_val, session = self.get_token()

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            action_result.set_status(ret_val, session)
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed - " + str(session)[:4] + '...' + str(session)[-4:])
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_token(self):
        try:
            if not self.asoap:
                self.asoap = ArcherSOAP(self.base_url, self.userName, self.password, self.instanceName, verify_cert=self.verifySSL,
                             usersDomain=self.usersDomain, pythonVersion=self.python_version)
        except Exception as e:
            return RetVal(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e)))

        return RetVal(phantom.APP_SUCCESS, self.asoap.session)

    def _handle_get_session_token(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make get_token call
        ret_val, session = self.get_token()

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            action_result.set_status(ret_val, session)
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(dict(token=str(session)))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['ret_val'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def terminate_token(self, token):
        try:
            if not self.asoap:
                self.asoap = ArcherSOAP(self.base_url, self.userName, self.password, self.instanceName, session='do not authenticate',
                    verify_cert=self.verifySSL, usersDomain=self.usersDomain, pythonVersion=self.python_version)

            result = self.asoap.terminate_session(token)

        except Exception as e:
            return RetVal(phantom.APP_ERROR, "Error terminating token. Details: {0}".format(str(e)))

        return RetVal(phantom.APP_SUCCESS, result)

    def _handle_terminate_session(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        token = param['token']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make terminate token call
        ret_val, result = self.terminate_token(token)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            action_result.set_status(ret_val, result)
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(dict(result=result))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['ret_val'] = ret_val

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        if result == '1':
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Result not equal to 1; result = " + str(result))

    def _get_proxy_args(self):
        """Returns the args to instantiate archer_utils.ArcherAPISession"""
        return (self.get_config().get('base_url'),
                self.get_config().get('userName'),
                self.get_config().get('password'),
                self.get_config().get('instanceName'),
                self.get_config().get('usersDomain'))

    def _get_proxy(self):
        """Returns an archer_utils.ArcherAPISession object."""
        if not self.proxy:
            ep, user, pwd, instance, users_domain = self._get_proxy_args()
            verify = self.get_config().get('verifySSL')
            self.debug_print('New Archer API session at ep:{}, user:{}, '
                             'verify:{}'.format(ep, user, verify))
            self.proxy = archer_utils.ArcherAPISession(ep, user, pwd, instance, self.python_version, users_domain)
            self.proxy.verifySSL = verify
            archer_utils.W = self.debug_print
        return self.proxy

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """Handles non integer values and set appropriate status"""
        if parameter is not None:
            try:
                if not float(parameter).is_integer() or isinstance(parameter, float):
                    return action_result.set_status(phantom.APP_ERROR, consts.ARCHER_ERR_VALID_INTEGER.format(key)), None
                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, consts.ARCHER_ERR_VALID_INTEGER.format(key)), None
            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, consts.ARCHER_ERR_NON_NEGATIVE.format(key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, consts.ARCHER_ERR_VALID_INTEGER.format(key)), None
        return phantom.APP_SUCCESS, parameter

    def _handle_list_tickets(self, param):
        """Handles 'list_tickets' actions"""
        self.save_progress('Get Archer record...')
        action_result = self.add_action_result(ActionResult(dict(param)))
        app = param.get('application')
        max_count = param.get('max_results', 100)
        search_field_name = param.get('name_field')
        search_value = param.get('search_value')
        query_filter_json = param.get('query_filter_json')
        results_filter_json = param.get('results_filter_json')
        if results_filter_json:
            results_filter_dict = json.loads(results_filter_json)
        else:
            results_filter_dict = None

        results_filter_operator = param.get('results_filter_operator')
        results_filter_equality = param.get('results_filter_equality')
        try:
            results_filter_operator = results_filter_operator.lower()
        except:
            pass
        try:
            results_filter_equality = results_filter_equality.lower()
        except:
            pass

        status, max_count = self._validate_integer(action_result, max_count, "max_result", False)
        if (phantom.is_fail(status)):
            return action_result.get_status()

        if (results_filter_dict or results_filter_operator or results_filter_equality) \
          and not (results_filter_dict and results_filter_operator and results_filter_equality):
            action_result.set_status(phantom.APP_ERROR,
              'Need results filter json, results filter operator and results filter equality to filter the results')
            return action_result.get_status()

        proxy = self._get_proxy()

        proxy.excluded_fields = [ x.lower().strip() for x in self.get_config().get('exclude_fields', '').split(',') ]

        if query_filter_json:
            filter_dict = json.loads(query_filter_json)
            records = proxy.find_records_dict(app, filter_dict, max_count)
        else:
            if (search_field_name or search_value) and not (search_field_name and search_value):
                action_result.set_status(phantom.APP_ERROR, 'Need both the field name and the search value to search')
                return action_result.get_status()
            filter_dict = {}
            filter_dict[search_field_name] = search_value
            records = proxy.find_records(app, search_field_name, search_value, max_count)

        term_msg = proxy.terminate_session()

        if results_filter_dict:
            filtered_records = self.filter_records(results_filter_dict, results_filter_operator, results_filter_equality, records)
        else:
            filtered_records = records

        if filtered_records:
            for r in filtered_records:
                action_result.add_data(r)
            action_result.set_status(phantom.APP_SUCCESS, 'Tickets retrieved{}'.format(term_msg))
            action_result.update_summary({'records_found': len(filtered_records)})
        else:
            filter_msg = ''

            if query_filter_json:
                filter_msg = 'query filter json'
            elif search_field_name and search_value:
                filter_msg = 'field {} containing value {}'.format(search_field_name, search_value)

            if results_filter_dict:
                if filter_msg != '':
                    filter_msg = '{} and results filter json'.format(filter_msg)
                else:
                    filter_msg = 'results filter json'

            if filter_msg != '':
                filter_msg = ' with {}'.format(filter_msg)

            action_result.set_status(phantom.APP_SUCCESS, 'Found no tickets for {}{}{}'.format(app, filter_msg, term_msg))
            action_result.update_summary({'records_found': 0})

        return action_result.get_status()

    def filter_records(self, results_filter_dict, results_filter_operator, results_filter_equality, records):
        filtered_records = []

        if results_filter_operator == 'and':
            and_dict_len = len(results_filter_dict)
            for record in records:
                and_dict_count = 0
                for field in record['Field']:
                    for k, v in results_filter_dict.items():
                        if results_filter_equality == 'equals':
                            if field['@name'] == k and v.lower() == field['#text'].lower():
                                and_dict_count = and_dict_count + 1
                        else:
                            if field['@name'] == k and v.lower() in field['#text'].lower():
                                and_dict_count = and_dict_count + 1
                if and_dict_count >= and_dict_len:
                    filtered_records.append(record)

        elif results_filter_operator == 'or':
            for record in records:
                next_record = False
                for field in record['Field']:
                    for k, v in results_filter_dict.items():
                        if results_filter_equality == 'equals':
                            if field['@name'] == k and v.lower() == field['#text'].lower():
                                filtered_records.append(record)
                                next_record = True
                                break
                        else:
                            if field['@name'] == k and v.lower() in field['#text'].lower():
                                filtered_records.append(record)
                                next_record = True
                                break
                    if next_record:
                        break

        return filtered_records

    def _get_report(self, param):
        """Handles 'get_report' actions"""
        self.save_progress('Get Archer report...')
        action_result = self.add_action_result(ActionResult(dict(param)))
        guid = param.get('guid')
        max_count = param.get('max_results', 100)
        max_pages = param.get('max_pages', 10)
        results_filter_json = param.get('results_filter_json')
        if results_filter_json:
            results_filter_dict = json.loads(results_filter_json)
        else:
            results_filter_dict = None

        results_filter_operator = param.get('results_filter_operator')
        results_filter_equality = param.get('results_filter_equality')
        try:
            results_filter_operator = results_filter_operator.lower()
        except:
            pass
        try:
            results_filter_equality = results_filter_equality.lower()
        except:
            pass

        status, max_count = self._validate_integer(action_result, max_count, "max_result", False)
        if (phantom.is_fail(status)):
            return action_result.get_status()

        status, max_pages = self._validate_integer(action_result, max_pages, "max_pages", False)
        if (phantom.is_fail(status)):
            return action_result.get_status()

        if (results_filter_dict or results_filter_operator or results_filter_equality) \
          and not (results_filter_dict and results_filter_operator and results_filter_equality):
            action_result.set_status(phantom.APP_ERROR,
              'Need results filter json, results filter operator and results filter equality to filter the results')
            return action_result.get_status()

        proxy = self._get_proxy()

        try:
            result_dict = proxy.get_report_by_id(guid, max_count, max_pages)
            if result_dict['status'] != 'success':
                action_result.set_status(phantom.APP_ERROR, result_dict['message'])
                return action_result.get_status()

            records = result_dict['records']
            term_msg = proxy.terminate_session()

            if results_filter_dict:
                filtered_records = self.filter_records(results_filter_dict, results_filter_operator, results_filter_equality, records)
            else:
                filtered_records = records

            if filtered_records:
                for r in filtered_records:
                    action_result.add_data(r)
                action_result.set_status(phantom.APP_SUCCESS, 'Tickets retrieved{}'.format(term_msg))
                action_result.update_summary({'records_found': len(filtered_records)})
                action_result.update_summary({'pages_found': result_dict['page_count']})
            else:

                if results_filter_dict:
                    filter_msg = ' with results filter json'
                else:
                    filter_msg = ''

                action_result.set_status(phantom.APP_SUCCESS, 'Found no tickets{}{}'.format(filter_msg, term_msg))
                action_result.update_summary({'records_found': 0})
                action_result.update_summary({'pages_found': result_dict['page_count']})

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR,
                'Error handling get report action - e = {}'.format(e))

        return action_result.get_status()

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == consts.ARCHER_ACTION_GET_SESSION_TOKEN:
            ret_val = self._handle_get_session_token(param)

        elif action_id == consts.ARCHER_ACTION_TERMINATE_SESSION:
            ret_val = self._handle_terminate_session(param)

        elif (action_id == consts.ARCHER_ACTION_LIST_TICKET):
            ret_val = self._handle_list_tickets(param)

        elif (action_id == consts.ARCHER_ACTION_GET_REPORT):
            ret_val = self._get_report(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self.base_url = config['base_url']
        self.userName = config['userName']
        self.password = config['password']
        self.instanceName = config['instanceName']
        self.verifySSL = config['verifySSL']
        self.usersDomain = config.get('usersDomain', '')
        self.python_version = int(sys.version_info[0])

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = RsaArcherForSoarConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RsaArcherForSoarConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
