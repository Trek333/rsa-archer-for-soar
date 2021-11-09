# --
# File: archer_soap.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

import requests
from lxml import etree
from io import BytesIO
from bs4 import UnicodeDammit

SOAPNS = 'http://schemas.xmlsoap.org/soap/envelope/'
XSINS = 'http://www.w3.org/2001/XMLSchema-instance'
XSDNS = 'http://www.w3.org/2001/XMLSchema'
ARCHERNS = 'http://archer-tech.com/webservices/'

NS_MAP = {
    'soap': SOAPNS,
    'xsi': XSINS,
    'xsd': XSDNS,
}

ARCHER_MAP = {
    None: ARCHERNS,
}

ALL_NS_MAP = NS_MAP.copy()
ALL_NS_MAP['dummy'] = ARCHERNS

DEBUG = False


class ArcherSOAP(object):
    def __init__(self, host, username, password, instance, session=None, verify_cert=True, usersDomain=None, pythonVersion=2):
        self.base_uri = host + '/ws'
        self.username = username
        self.password = password
        self.instance = instance
        self.session = session
        self.verify_cert = verify_cert
        self.users_domain = usersDomain
        self.python_version = pythonVersion
        if not session:
            self._authenticate()

    def _authenticate(self):
        doc, body = self._generate_xml_stub()

        if self.users_domain:
            return self._domain_user_authenticate()

        n = etree.SubElement(
            body, 'CreateUserSessionFromInstance', nsmap=ARCHER_MAP)
        un = etree.SubElement(n, 'userName')
        un.text = self.username
        inn = etree.SubElement(n, 'instanceName')
        inn.text = self.instance
        p = etree.SubElement(n, 'password')
        p.text = self.password
        sess_doc = self._do_request(self.base_uri + '/general.asmx', doc)
        sess_root = sess_doc.getroot()
        result = sess_root.xpath(
            '/soap:Envelope/soap:Body/dummy:CreateUserSessionFromInstanceResponse/dummy:CreateUserSessionFromInstanceResult', namespaces=ALL_NS_MAP)
        if result:
            self.session = result[0].text
            return
        raise Exception('Failed to authenticate to Archer web services')

    def _domain_user_authenticate(self):
        doc, body = self._generate_xml_stub()

        n = etree.SubElement(
            body, 'CreateDomainUserSessionFromInstance', nsmap=ARCHER_MAP)
        un = etree.SubElement(n, 'userName')
        un.text = self.username
        inn = etree.SubElement(n, 'instanceName')
        inn.text = self.instance
        p = etree.SubElement(n, 'password')
        p.text = self.password
        p = etree.SubElement(n, 'usersDomain')
        p.text = self.users_domain
        sess_doc = self._do_request(self.base_uri + '/general.asmx', doc)
        sess_root = sess_doc.getroot()
        result = sess_root.xpath(
            '/soap:Envelope/soap:Body/dummy:CreateDomainUserSessionFromInstanceResponse/dummy:CreateDomainUserSessionFromInstanceResult', namespaces=ALL_NS_MAP)
        if result:
            self.session = result[0].text
            return
        raise Exception('Failed to authenticate to Archer web services')

    def find_group(self, groupname):
        if not self.session:
            raise Exception('No session')
        doc, body = self._generate_xml_stub()
        lu = etree.SubElement(body, 'LookupGroup', nsmap=ARCHER_MAP)
        to = etree.SubElement(lu, 'sessionToken')
        to.text = self.session
        u = etree.SubElement(lu, 'keyword')
        u.text = groupname
        resp_doc = self._do_request(self.base_uri + '/accesscontrol.asmx', doc)
        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:LookupGroupResponse/dummy:LookupGroupResult/dummy:Groups/dummy:/Group/dummy:Name', namespaces=ALL_NS_MAP)
        if result:
            for name_ele in result:
                if name_ele.text == groupname:
                    for node in name_ele.itersiblings(tag='Id'):
                        return int(node.text)
        return

    def find_user(self, username):
        if not self.session:
            raise Exception('No session')
        doc, body = self._generate_xml_stub()
        lu = etree.SubElement(body, 'LookupUserId', nsmap=ARCHER_MAP)
        to = etree.SubElement(lu, 'sessionToken')
        to.text = self.session
        u = etree.SubElement(lu, 'username')
        u.text = username
        resp_doc = self._do_request(self.base_uri + '/accesscontrol.asmx', doc)
        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:LookupUserIdResponse/dummy:LookupUserIdResult', namespaces=ALL_NS_MAP)
        if result:
            return int(result[0].text)
        return

    def find_domain_user(self, username):
        if not self.session:
            raise Exception('No session')
        doc, body = self._generate_xml_stub()
        lu = etree.SubElement(body, 'LookupDomainUserId', nsmap=ARCHER_MAP)
        to = etree.SubElement(lu, 'sessionToken')
        to.text = self.session
        u = etree.SubElement(lu, 'username')
        u.text = username
        u = etree.SubElement(lu, 'usersDomain')
        u.text = self.users_domain
        resp_doc = self._do_request(self.base_uri + '/accesscontrol.asmx', doc)
        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:LookupDomainUserIdResponse/dummy:LookupDomainUserIdResult', namespaces=ALL_NS_MAP)
        if result:
            return int(result[0].text)
        return

    def find_records(self, mod_id, mod_name, key_id, key_name, value, filter_type='text', max_count=1000, fields=None, comparison='Equals', sort=None, page=1):
        if not self.session:
            raise Exception('No session')
        if fields is None:
            fields = {key_id: key_name}
        doc, body = self._generate_xml_stub()
        se = etree.SubElement(body, 'ExecuteSearch', nsmap=ARCHER_MAP)
        to = etree.SubElement(se, 'sessionToken')
        to.text = self.session
        pn = etree.SubElement(se, 'pageNumber')
        pn.text = str(page)
        so = etree.SubElement(se, 'searchOptions')

        sr = etree.Element('SearchReport')
        report_doc = etree.ElementTree(sr)

        ps = etree.SubElement(sr, 'PageSize')
        ps.text = str(max_count)
        dfs = etree.SubElement(sr, 'DisplayFields')
        for field_id, field_name in list(fields.items()):
            df = etree.SubElement(dfs, 'DisplayField')
            df.text = str(field_id)
            df.set('name', UnicodeDammit(field_name).unicode_markup.encode(
                'ascii', 'xmlcharrefreplace'))

        cr = etree.SubElement(sr, 'Criteria')
        if not comparison:
            if filter_type == 'numeric':
                comparison = 'Equals'
            else:
                comparison = 'Contains'
        if value is not None and value != '':
            fi = etree.SubElement(cr, 'Filter')
            co = etree.SubElement(fi, 'Conditions')
            if filter_type == 'numeric':
                fc = etree.SubElement(co, 'NumericFilterCondition')
                op = etree.SubElement(fc, 'Operator')
                op.text = comparison
            else:
                fc = etree.SubElement(co, 'TextFilterCondition')
                op = etree.SubElement(fc, 'Operator')
                op.text = 'Contains'
            fi = etree.SubElement(fc, 'Field')
            fi.text = str(key_id)
            v = etree.SubElement(fc, 'Value')
            v.text = str(value)

        mc = etree.SubElement(cr, 'ModuleCriteria')
        m = etree.SubElement(mc, 'Module')
        if sort:
            sfs = etree.SubElement(mc, 'SortFields')
            sf = etree.SubElement(sfs, 'SortField')
            sfid = etree.SubElement(sf, 'Field')
            sfid.text = str(key_id)
            sft = etree.SubElement(sf, 'SortType')
            sft.text = sort
        m.set('name', mod_name)
        m.text = str(mod_id)

        so.text = etree.tostring(report_doc, pretty_print=True)

        resp_doc = self._do_request(self.base_uri + '/search.asmx', doc)

        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:ExecuteSearchResponse/dummy:ExecuteSearchResult', namespaces=ALL_NS_MAP)
        if not result:
            return []

        r_io = BytesIO(result[0].text.encode('UTF8'))
        xmlp = etree.XMLParser(encoding='utf-8')
        search_result = etree.parse(r_io, parser=xmlp)
        return search_result.xpath('/Records/Record')

    def get_record(self, content_id, module_id):
        doc, body = self._generate_xml_stub()
        gr = etree.SubElement(body, 'GetRecordById', nsmap=ARCHER_MAP)
        to = etree.SubElement(gr, 'sessionToken')
        to.text = self.session
        mi = etree.SubElement(gr, 'moduleId')
        mi.text = str(module_id)
        ci = etree.SubElement(gr, 'contentId')
        ci.text = str(content_id)
        resp_doc = self._do_request(self.base_uri + '/record.asmx', doc)
        resp_root = resp_doc.getroot()
        rec_xml = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:GetRecordByIdResponse/dummy:GetRecordByIdResult', namespaces=ALL_NS_MAP)

        return rec_xml[0].text

    def plain_field(self, field, parent):
        f = etree.SubElement(parent, 'Field')

        # Try the original code to set the field value, if it fails let the library have a go at it, if that also fails, the action will fail
        try:
            f.set('value', str(field['value']))
        except:
            f.set('value', field['value'])

        f.set('id', str(field['id']))

    def mv_field(self, field, parent):
        f = etree.SubElement(parent, 'Field')
        values = field['value']
        o = None
        if isinstance(values, dict):
            o = field.get('other_text')
            values = values['value_id']
        f.set('value', str(values))
        f.set('id', str(field['id']))
        f.set('type', str(field['type']))
        if o:
            f.set('othertext', str(o))
        # add this when we have proper multi value support.
        # for v in values[1:]:
        #    mv = etree.SubElement(f, 'MultiValue')
        #    mv.set('value', str(v))

    def user_field(self, field, parent):
        f = etree.SubElement(parent, 'Field')
        f.set('id', str(field['id']))
        u = etree.SubElement(f, 'Users')
        uid = etree.SubElement(u, 'User')
        uid.set('id', str(field['value']))

    def get_field_map(self):
        type_formatter_map = {}
        for i in (1, 2, 3, 19):
            type_formatter_map[i] = self.plain_field
        for i in (4, 9, 18):
            type_formatter_map[i] = self.mv_field
        for i in (8,):
            type_formatter_map[i] = self.user_field
        return type_formatter_map

    def update_record(self, content_id, module_id, fields):
        type_formatter_map = self.get_field_map()

        doc, body = self._generate_xml_stub()
        gr = etree.SubElement(body, 'UpdateRecord', nsmap=ARCHER_MAP)
        to = etree.SubElement(gr, 'sessionToken')
        to.text = self.session
        mi = etree.SubElement(gr, 'moduleId')
        mi.text = str(module_id)
        ci = etree.SubElement(gr, 'contentId')
        ci.text = str(content_id)
        fv = etree.SubElement(gr, 'fieldValues')

        r = etree.Element('Records')
        update_doc = etree.ElementTree(r)
        for field in fields:
            fn = type_formatter_map.get(field['type'])
            if fn:
                fn(field, r)

        fv.text = etree.tostring(update_doc, pretty_print=True)

        resp_doc = self._do_request(self.base_uri + '/record.asmx', doc)

        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:UpdateRecordResponse/dummy:UpdateRecordResult', namespaces=ALL_NS_MAP)
        if result and len(result) > 0:
            try:
                return int(result[0].text)
            except:
                pass
        return False

    def create_record(self, moduleid, fields):
        type_formatter_map = self.get_field_map()

        doc, body = self._generate_xml_stub()
        gr = etree.SubElement(body, 'CreateRecord', nsmap=ARCHER_MAP)
        to = etree.SubElement(gr, 'sessionToken')
        to.text = self.session
        mi = etree.SubElement(gr, 'moduleId')
        mi.text = str(moduleid)
        fv = etree.SubElement(gr, 'fieldValues')

        r = etree.Element('Record')
        update_doc = etree.ElementTree(r)
        for field in fields:
            fn = type_formatter_map.get(field['type'])
            if fn:
                fn(field, r)

        fv.text = etree.tostring(update_doc, pretty_print=True)

        resp_doc = self._do_request(self.base_uri + '/record.asmx', doc)

        resp_root = resp_doc.getroot()
        result = resp_root.xpath(
            '/soap:Envelope/soap:Body/dummy:CreateRecordResponse/dummy:CreateRecordResult', namespaces=ALL_NS_MAP)
        if result and len(result) > 0:
            try:
                return int(result[0].text)
            except:
                pass
        return False

    def _generate_xml_stub(self):
        envelope = etree.Element(etree.QName(SOAPNS, 'Envelope'), nsmap=NS_MAP)
        document = etree.ElementTree(envelope)
        body = etree.SubElement(envelope, etree.QName(SOAPNS, 'Body'))
        return document, body

    def _do_request(self, uri, doc, method='post'):
        if method == 'post':
            xml = etree.tostring(doc, pretty_print=True)
            api = doc.xpath('/soap:Envelope/soap:Body', namespaces=NS_MAP)
            api = api[0].getchildren()
            if not api:
                raise Exception('Could not find API node')
            api = api[0].tag
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': '"http://archer-tech.com/webservices/{}"'.format(api),
            }
            response = requests.post(
                uri, data=xml, headers=headers, verify=self.verify_cert)
            r_io = BytesIO(response.text.encode('UTF8'))
            resp_doc = etree.parse(r_io)
            return resp_doc
        raise ValueError('Invalid Method')
