# File: archer_views.py
#
# Copyright (c) 2016-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
def get_ticket(provides, all_results, context):

    context['results'] = results = []
    for summary, action_results in all_results:
        for result in action_results:
            parameters = result.get_param()
            if 'context' in parameters:
                del parameters['context']
            rec = {'parameters': parameters}
            data = result.get_data()
            if data:
                data = data[0]['Record']['Field']
            rec['record'] = sorted(data, key=lambda x: (x['@name'] is not None, x['@name']))
            rec['content_id'] = result.get_summary().get(
                'content_id', 'Not provided')
            results.append(rec)

    return 'get_ticket.html'


def list_tickets(provides, all_results, context):

    headers = ['application', 'content id']
    context['results'] = results = []

    headers_set = set()
    for summary, action_results in all_results:
        for result in action_results:
            for record in result.get_data():
                headers_set.update([f.get('@name', '').strip()
                                    for f in record.get('Field', [])])
    if not headers_set:
        headers_set.update(headers)
    headers.extend(sorted(headers_set))

    final_result = {'headers': headers, 'data': []}

    dyn_headers = headers[2:]
    for summary, action_results in all_results:
        for result in action_results:
            data = result.get_data()
            param = result.get_param()
            for item in data:
                row = []
                row.append({'value': param.get('application'),
                            'contains': ['archer application']})
                row.append({'value': item.get('@contentId'),
                            'contains': ['archer content id']})
                name_value = {}
                for f in item.get('Field', []):
                    name_value[f['@name']] = f.get('#text')

                for h in dyn_headers:
                    if h == 'IP Address':
                        row.append({'value': name_value.get(h, ''),
                                    'contains': ['ip']})
                    else:
                        row.append({'value': name_value.get(h, '')})
                final_result['data'].append(row)

    results.append(final_result)
    return 'list_tickets.html'


def get_report(provides, all_results, context):

    headers = ['content id']
    context['results'] = results = []

    headers_set = set()
    for summary, action_results in all_results:
        for result in action_results:
            for record in result.get_data():
                headers_set.update([f.get('@name', '').strip()
                                    for f in record.get('Field', [])])
    if not headers_set:
        headers_set.update(headers)
    headers.extend(sorted(headers_set))

    final_result = {'headers': headers, 'data': []}

    dyn_headers = headers[1:]
    for summary, action_results in all_results:
        for result in action_results:
            data = result.get_data()
            for item in data:
                row = []
                row.append({'value': item.get('@contentId'),
                            'contains': ['archer content id']})
                name_value = {}
                for f in item.get('Field', []):
                    name_value[f['@name']] = f.get('#text')

                for h in dyn_headers:
                    if h == 'IP Address':
                        row.append({'value': name_value.get(h, ''),
                                    'contains': ['ip']})
                    else:
                        row.append({'value': name_value.get(h, '')})
                final_result['data'].append(row)

    results.append(final_result)
    return 'get_report.html'
