#!/usr/bin/python 
#coding:utf-8 
"""
user_login  是帐号密码验证
host_get    是列出监控机  
hostgroup_get  是获取主机组的ID
template_get   是获取模板的ID
host_create    添加主机
运行方式：（前提是test-group这个主机组和test-template这个模板必须存在）
./zabbix_tools.py  192.168.3.100  test-group  test-template 

""" 
import json 
import urllib2 
from urllib2 import URLError 
import sys 
import pprint
 
class ZabbixApi: 
    def __init__(self,host,user,passwd): 
        self.url = 'http://%s/zabbix/api_jsonrpc.php' % (host)
        self.header = {"Content-Type":"application/json"} 
        proxy=urllib2.ProxyHandler({})
        opener=urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
        self.user_login(user,passwd) # set self.authID
         
         
    def send_request(self,data):
        buf=json.dumps(data)
        request = urllib2.Request(self.url, buf) 
        for key in self.header: 
            request.add_header(key, self.header[key]) 
        try:
            result=urllib2.urlopen(request)
        except URLError as e: 
            print('send_request %s Failed!'%(data['method']), e.code)
        else:
            response=json.loads(result.read()) 
            result.close()
            if response.get('error'):
                raise ValueError(`response['error']`)
            return response.get('result')
            
    def user_login(self,user,passwd): 
        data = { 
            "jsonrpc": "2.0", 
            "method": "user.login", 
            "params": { 
                       "user": user, 
                       "password": passwd,
                       }, 
            "id": 0 
            }
         
        self.authID = self.send_request(data) 
        return self.authID 
         
    def host_get(self,groupids=None,hostids=None,graphids=None,templateids=None): 
        data = { 
            "jsonrpc":"2.0", 
            "method":"host.get", 
            "params":{"output":["hostid","host","name"]}, 
            "auth":self.authID, 
            "id":1, 
            }
        if groupids:
            data['params']['groupids']=groupids
        if hostids:
            data['params']['hostids']=hostids
        if graphids:
            data['params']['graphids']=graphids
        if templateids:
            data['params']['templateids']=templateids
         
        return self.send_request(data) 
    def host_get_byname(self,hostip): 
        data = { 
            "jsonrpc":"2.0", 
            "method":"host.get", 
            "params":{ "filter":{"host":hostip},"output":['hostid']}, 
            "auth":self.authID, 
            "id":1}
        return self.send_request(data)[0].get('hostid')

    def hostgroup_get(self, groupids=None,hostids=None,graphids=None,templateids=None): 
        data = { 
            "jsonrpc":"2.0", 
            "method":"hostgroup.get", 
            "params":{ "output": "extend"}, 
            "auth":self.authID, 
            "id":1}
        if groupids:
            data['params']['groupids']=groupids
        if hostids:
            data['params']['hostids']=hostids
        if graphids:
            data['params']['graphids']=graphids
        if templateids:
            data['params']['templateids']=templateids
            
        return self.send_request(data) 
        
    def hostgroup_get_byname(self,groupname): 
        data = { 
            "jsonrpc":"2.0", 
            "method":"hostgroup.get", 
            "params":{ "filter":{"name":groupname},"output":['groupid']}, 
            "auth":self.authID, 
            "id":1}
        return self.send_request(data)[0].get('groupid')
    def template_get_byname(self,templatename): 
        data = { 
            "jsonrpc":"2.0", 
            "method":"template.get", 
            "params":{ "filter":{"name":templatename},"output":['templateid']}, 
            "auth":self.authID, 
            "id":1}
        return self.send_request(data)[0].get('templateid')
        
    def template_get(self,groupids=None,hostids=None,graphids=None,templateids=None): 
        data = { 
            "jsonrpc":"2.0", 
            "method": "template.get", 
            "params": { 
                       "output": "extend", 
                       "filter": {}
                       }, 
            "auth":self.authID, 
            "id":1, 
            }
        if groupids:
            data['params']['groupids']=groupids
        if hostids:
            data['params']['hostids']=hostids
        if graphids:
            data['params']['graphids']=graphids
        if templateids:
            data['params']['templateids']=templateids
         
        return self.send_request(data) 

    def host_create(self, hostip, visname,hostgroupName, templateName): 
        data ={ 
               "jsonrpc":"2.0", 
               "method":"host.create", 
               "params":{ 
                         "host": hostip, 
                         "name": visname,
                         "interfaces": [ 
                                            { 
                                                "type": 1, 
                                                "main": 1, 
                                                "useip": 1, 
                                                "ip": hostip, 
                                                "dns": "", 
                                                "port": "10050" 
                                            } 
                                        ], 
                        "groups": [ 
                                        { 
                                            "groupid": self.hostgroup_get_byname(hostgroupName) 
                                        } 
                                   ], 
                        "templates": [ 
                                        { 
                                            "templateid": self.template_get_byname(templateName) 
                                        } 
                                      ], 
                         }, 
               "auth": self.authID, 
               "id":1                   
        }
        return self.send_request(data) 

    def host_enable(self, hostid,status,visname=None): 
        data ={ 
               "jsonrpc":"2.0", 
               "method":"host.update", 
               "params":{ 
                         "hostid": hostid, 
                         "status":status
                        },
               "auth": self.authID, 
               "id":1                   
        }
        if visname:
            data['params']['name']=visname
        return self.send_request(data) 
         
                 
                 
if __name__ == "__main__": 
    za = ZabbixApi('127.0.0.1','Admin','zabbix') 
    hostid=za.host_get_byname('10.112.13.95')
    d=za.host_get(hostids=(hostid))
    oldname=d[0]['name']
    print oldname
