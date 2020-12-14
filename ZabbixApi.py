#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
import requests
import sys
import csv
import re
import logging
import os.path
import time
import importlib
importlib.reload(sys)



class ZabbixApi(object):
    post_headers = {'Content-Type': 'application/json'}

    def __init__(self, url, username, password):
        self.url = url
        self.__username = username
        self.__password = password
        self.id = 0
        self.__auth = ''
        self.status = 0

    def logger(self, level, message):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)  # 设置logger的日志等级
        log_path = os.getcwd() + '/logs/'
        if not os.path.exists(log_path):
            os.mkdir(log_path)
        logfile = log_path + time.strftime('%Y%m%d', time.localtime(time.time())) + '.log'
        fh = logging.FileHandler(logfile, mode='a')
        fh.setLevel(logging.WARNING) # 输出到文件的日志等级是WARNGING
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO) # 输出到控制台的日志等级是INFO
        formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        if level == 'debug':
            logging.debug(message)
        elif level == 'info':
            logging.info(message)
        elif level == 'warning':
            logging.warning(message)
        elif level == 'error':
            logging.error(message)
        logger.removeHandler(ch)
        logger.removeHandler(fh)

    def do_requests(self, method, params):
        post_data = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params,
            'id': self.id
        }
        # apiinfo.version and user.login doesn't require auth token
        if self.__auth and (method not in ('apiinfo.version', 'user.login')):
            post_data['auth'] = self.__auth
            self.id += 1
        try:
            response = requests.post(self.url, data=json.dumps(post_data), headers=self.post_headers, timeout=3)
            if response.status_code == 200:
                if 'error' in response.json():
                    self.status = 1
                    return self.logger(level='error', message=response.json()['error'])
                return response.json()
            if response.status_code != 200:
                self.status = 1
                return self.logger(level='error', message=self.url + ' is not exists')
        except Exception:
            self.status = 1
            return self.logger(level='error', message='Connection to %s timed out' % (re.findall('.*//([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*?)/.*\.php', self.url)[0]))

    def login(self):
        method = 'user.login'
        params = {
            "user": self.__username,
            "password": self.__password
        }
        try:
            response = self.do_requests(method, params)
            self.__auth = response['result']
            self.logger(level='debug', message='Login successful')
        except Exception:
            return None

    @property
    def apiversion(self):
        method = 'apiinfo.version'
        params = []
        response = self.do_requests(method, params)
        if self.status == 1: return None
        apiversion = response['result']
        if apiversion:
            self.logger(level='info', message='apiversion: ' + json.dumps(apiversion))
            return apiversion  # such as: 5.0.1

    def get_groupids(self, group):
        if self.status == 1: return None
        method = 'hostgroup.get'
        params = {
            'output': 'groupid',
            'filter': {
                'name': group
            }
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        groupids = response['result']
        if groupids:
            self.logger(level='debug', message='Hostgroup %s: ' %(group) + json.dumps(groupids))
            return groupids # such as: [{'groupid': '183'}]

    def get_templateids(self, template=None, hostname=None):
        if self.status == 1: return None
        method = 'template.get'
        params = {}
        if template:
            params = {
                'output': 'templateid',
                'filter': {
                    'host': template
                }
            }
        elif hostname:
            hostid = self.get_hostid(hostname)
            if not hostid:
                return None
            params = {
                "output": "templateid",
                "hostids": hostid[0].get('hostid')
            }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        templateids = response['result']
        if templateids:
            self.logger(level='debug', message='template %s: ' %(template) + json.dumps(templateids))
            return templateids # such as: [{'templateid': '10093'}, {'templateid': '10216'}, {'templateid': '10265'}]

    def get_hostid(self, hostname):
        if self.status == 1: return None
        if ',' in hostname:
            return "hostname字段值必须是唯一的"
        method = 'host.get'
        params = {
            'output': 'hostid',
            'filter': {
                'host': hostname
            }
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        hostid = response['result']
        if hostid:
            self.logger(level='debug', message='hostname %s: ' %(hostname) + json.dumps(hostid))
            return hostid # such as: [{'hostid': '10563'}]

    def get_hostinfo(self, hostname):
        '''
        通过主机名获取主机的详细信息，包括主机所属的主机组、所关联的模板、主机接口信息、主机宏
        '''
        if self.status == 1: return None
        if ',' in hostname:
            return print("主机必须是唯一的")
        method = 'host.get'
        params = {
            "output": [
                "hostid",
                "name",
                "proxy_hostid"
            ],
            "selectGroups": [
                "name",
                "groupid"
            ],
            "selectInterfaces": [
                "interfaceid",
                "ip",
                "hostid",
                "main",
                "type",
                "useip",
                "ip",
                "port",
                "details"
            ],
            "selectMacros": [
                "macro",
                "value"
            ],
            "selectParentTemplates": [
                "host",
                "templateid"
            ],
            "filter": {
                "host": hostname
            }
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        hostinfo = response['result']
        if hostinfo:
            self.logger(level='debug', message='get_hostid(): ' + json.dumps(hostinfo))
            '''
            such as: [{
            "hostid": "10563", 
            "name": "dev-mysql", 
            "proxy_hostid": "10429", 
            "groups": [{"groupid": "184", "name": "Linux"}], 
            "parentTemplates": [{"host": "Template App FTP Service", "templateid": "10093"}, {"host": "Template Module Cisco Inventory SNMPv2", "templateid": "10216"}, {"host": "Template App Apache by HTTP", "templateid": "10265"}], 
            "macros": [], 
            "interfaces": [{"interfaceid": "253", "ip": "172.254.254.3", "hostid": "10563", "main": "1", "type": "1", "useip": "1", "port": "10050", "details": []}, 
                           {"interfaceid": "254", "ip": "172.254.254.3", "hostid": "10563", "main": "1", "type": "2", "useip": "1", "port": "161", "details": {"version": "2", "bulk": "1", "community": "{$SNMP_COMMUNITY}"}}]}]

            '''
            return hostinfo[0]

    def get_itemids(self, hostname, key=None):
        if self.status == 1: return None
        method = 'item.get'
        hostid = self.get_hostid(hostname)
        if not hostid:
            return None
        # 通过指定的key来获取itemid
        if key:
            params = {
                'output': 'itemid',
                'hostids': hostid[0].get('hostid'),
                "search": {
                    "key_": key
                }
            }
            response = self.do_requests(method, params)
            if self.status == 1: return None
            if response['result']:
                self.logger(level='debug', message='get_itemids(): ' + json.dumps(response['result']))
                return response['result']  # such as: [{"itemid": "39201"}]

        # 获取指定主机的所有itemid
        else:
            params = {
                "output": "itemid",
                "hostids": hostid[0].get('hostid')
            }
            response = self.do_requests(method, params)
            if self.status == 1: return None
            if response['result']:
                self.logger(level='debug', message='get_itemids(): ' + json.dumps(response['result']))
                return response['result'] # such as: [{"itemid": "39200"}, {"itemid": "39201"}]
            else: self.logger(level='error', message='hostname:%s is not exists' % (hostname))

    def get_proxyid(self, proxy):
        if self.status == 1: return None
        method = 'proxy.get'
        params = {
            "output": "proxyid",
            "filter": {
                "host": proxy
            }
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        proxyid = response['result']
        if proxyid:
            self.logger(level='debug', message='get_proxyid(): ' + json.dumps(proxyid))
            return proxyid  # such as: [{"proxyid": "10429"}]

    def get_interfaceids(self, hostname):
        if self.status == 1: return None
        hostid = self.get_hostid(hostname)
        if not hostid:
            return None
        method = 'hostinterface.get'
        params = {
            "output": "interfaceid",
            "hostids": hostid[0].get('hostid')
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='debug', message='get_interfaceids(): ' + json.dumps(response['result']))
            return response['result']  # such as: [{"interfaceid": "253"}, {"interfaceid": "254"}]

    def create_group(self, group):
        if self.status == 1: return None
        method = 'hostgroup.create'
        params = {
            "name": group
        }
        response = self.do_requests(method, params)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='debug', message='create_group(): ' + json.dumps(response['result']))

    def __get_interface(self, interface):
        if self.status == 1: return None
        type_value = {
            'agent': 1,
            'snmp': 2,
            'ipmi': 3,
            'jmx': 4
        }
        snmp_version = {
            'snmpv1': '1',
            'snmpv2': '2',
            'snmpv3': '3'
        }
        csv_interface = json.loads(interface)
        params = {}
        if csv_interface['type'] == 'agent' or csv_interface['type'] == 'jmx':
            params['ip'] = csv_interface['ip']
            params['dns'] = ''
            params['main'] = 1
            params['port'] = csv_interface['port']
            params['type'] = type_value[csv_interface['type']]
            params['useip'] = 1

        elif csv_interface['type'] == 'snmpv1' or csv_interface['type'] == 'snmpv2':
            params['ip'] = csv_interface['ip']
            params['dns'] = ''
            params['main'] = 1
            params['port'] = csv_interface['port']
            params['type'] = type_value[csv_interface['type']]
            params['useip'] = 1
            params['details'] = {
                "version": snmp_version[csv_interface['type']],
                "bulk": "1",
                "community": "{$SNMP_COMMUNITY}"
            }

        elif csv_interface['type'] == 'snmpv3':
            params['ip'] = csv_interface['ip']
            params['dns'] = ''
            params['main'] = 1
            params['port'] = csv_interface['port']
            params['type'] = type_value[csv_interface['type']]
            params['useip'] = 1
            params['details'] = {
                "version": snmp_version[csv_interface['type']],
                "bulk": "1",
                "community": "{$SNMP_COMMUNITY}",
                "securityname": csv_interface['securityname'],
                "securitylevel": csv_interface['securitylevel'],
                "authpassphrase": csv_interface['authpassphrase'],
                "privpassphrase": csv_interface['privpassphrase'],
                "authprotocol": csv_interface['authprotocol'],
                "privprotocol": csv_interface['privprotocol']
            }
        else:
            self.logger(level='error', message='interface type possible value is: agent, jmx, snmpv1, snmpv2, snmpv3')
        return params

    def create_host(self, hostname, visiblename, groups, interfaces, templates, proxy=None, tags=None, macros=None,
                    description=None, method='host.create'):
        def dict(type, values):
            dic = {}
            if type == 'tags':
                tag = re.findall('(.*)=', values)[0]
                value = re.findall('.*=(.*)', values)[0]
                dic['tag'] = tag
                dic['value'] = value
            elif type == 'macros':
                macro = re.findall('(.*)=', values)[0]
                value = re.findall('.*=(.*)', values)[0]
                dic['macro'] = macro
                dic['value'] = value
            return dic
        if self.status == 1: return None
        params = {}
        params_template = {}
        # 2. hostgroup
        groupids = []
        for group in groups.split(','):
            if not self.get_groupids(group):
                self.create_group(group)
                groupids.append(self.get_groupids(group)[0])
            else:
                groupids.append(self.get_groupids(group)[0])
        # 4. proxy
        if proxy:
            if self.get_proxyid(proxy):
                proxy = self.get_proxyid(proxy)
            else:
                proxy = None
        # 5. tags
        tagids = []
        if tags:
            for tag in tags.split(','):
                dic = dict('tags', tag)
                tagids.append(dic)
        # 6. macros
        macroids = []
        if macros:
            for macro in macros.split(','):
                dic = dict('macros', macro)
                macroids.append(dic)
        # 7. interfaces
        interfaceids = []
        for interface in re.findall('\{.+?\}', interfaces):
            interfaceids.append(self.__get_interface(interface))
        if method == 'host.create':
            # 1. host
            hostid = self.get_hostid(hostname)
            if hostid:
                return self.logger(level='error', message='Host with the same name "%s" already exists.' % (hostname))
            # 3. templates
            templateids = []
            for template in templates.split(','):
                if not self.get_templateids(template=template):
                    self.logger(level='warning',
                                message='template: %s is not exists, not link host %s' % (template, hostname))
                else:
                    templateids.append(self.get_templateids(template=template)[0])
            params = {
                "host": hostname,
                "interfaces": interfaceids,
                "groups": groupids,
                "templates": templateids,
                "name": visiblename,
                "proxy_hostid": proxy,
                "macros": macroids,
                "tags": tagids
            }
        elif method == 'host.update':
            # 1. host
            hostid = self.get_hostid(hostname)
            if not hostid:
                return self.logger(level='error', message='Host "%s" is not exists.' % (hostname))
            # 3. template
            old_templateids = self.get_templateids(hostname=hostname)
            new_templateids = []
            for new_template in templates.split(','):
                if not self.get_templateids(template=new_template):
                    self.logger(level='warning',
                                message='template: %s is not exists, not link host %s' % (new_template, hostname))
                else:
                    new_templateids.append(self.get_templateids(template=new_template)[0])
            params = {
                "hostid": hostid[0]['hostid'],
                "interfaces": interfaceids,
                "groups": groupids,
                "templates_clear": old_templateids, # unlink and clear old_templateids
                "name": visiblename,
                "proxy_hostid": proxy,
                "macros": macroids,
                "tags": tagids
            }
            params_template = {
                "hostid": hostid[0]['hostid'],
                "templates": new_templateids # link new_templateids
            }
        else:
            return self.logger(level='error', message='method possible value is: host.create or host.update.')
        response = self.do_requests(method, params)
        if method == 'host.update':
            response = self.do_requests(method, params_template)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='info', message='%s host "%s" successfully. ' %(re.findall('\.(.*)', method)[0], hostname) + json.dumps(response['result']))

    def del_host(self, hostname):
        if self.status == 1: return None
        hostid = self.get_hostid(hostname)
        if not hostid:
            return self.logger(level='error', message='Host "%s" is not exists.' %(hostname))
        method = 'host.delete'
        params = [
            hostid[0]['hostid']
        ]
        response = self.do_requests(method, params)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='info', message='delete host "%s" successfully. ' %(hostname) + json.dumps(response['result']))

    def del_group(self, group):
        if self.status == 1: return None
        groupid = self.get_groupids(group)
        if not groupid:
            return self.logger(level='error', message='Hostgroup "%s" is not exists.' %(group))
        method = 'hostgroup.delete'
        params = [
            groupid[0]['groupid']
        ]
        response = self.do_requests(method, params)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='info',message='delete Hostgroup "%s" successfully. ' % (group) + json.dumps(response['result']))

    def del_template(self, template):
        if self.status == 1: return None
        templateid = self.get_templateids(template=template)
        if not templateid:
            return self.logger(level='error', message='Template "%s" is not exists.' %(template))
        method = 'template.delete'
        params = [
            templateid[0]['templateid']
        ]
        response = self.do_requests(method, params)
        if self.status == 1: return None
        if response['result']:
            self.logger(level='info',message='delete Template "%s" successfully. ' % (template) + json.dumps(response['result']))

class ZabbixExcel(ZabbixApi):
    def __init__(self, url, username, password, filename):
        self.filename = filename
        super().__init__(url, username, password)
        super().login()

    def excel_to_csv(self):
        ...

    def create_host_over_excel(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for i in csv_reader:
                self.create_host(i.get('hostname'), i.get('visiblename'), i.get('groups'), i.get('interfaces'),
                                 i.get('proxy'), i.get('templates'), i.get('tags'), i.get('macros'), i.get('description'),
                                 method='host.create')

    def del_host_over_excel(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for i in csv_reader:
                self.del_host(i.get('hostname'))

    def update_host_over_excel(self):
        with open(self.filename, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for i in csv_reader:
                self.create_host(i.get('hostname'), i.get('visiblename'), i.get('groups'), i.get('interfaces'),
                                 i.get('proxy'), i.get('templates'), i.get('tags'), i.get('macros'),
                                 i.get('description'),
                                 method='host.update')
