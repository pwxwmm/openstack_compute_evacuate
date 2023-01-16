#!/usr/bin/env python
# coding: utf-8
# author: mmwei3
# date: 2021/12/12
import subprocess
import sys
from imp import reload
import requests
import time
import logging
import os
import concurrent.futures
import subprocess as sp
from ConfigParser import ConfigParser
import json

reload(sys)
sys.setdefaultencoding('utf8')

DEVNULL = open(os.devnull, 'wb')
logfile = "/var/log/cmpha.log"
debug = True

level = logging.WARNING if not debug else logging.DEBUG
logging.basicConfig(level=level,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=logfile,
                    filemode='a')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('[line:%(lineno)d]:%(levelname)s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


class baseInfo(object):
    """
    init the info of all compute, and get the token for access the api
    """

    def __init__(self):
        confFile = sys.argv[1]
        headers = {}
        headers["Content-Type"] = "application/json"
        self.cf = ConfigParser()
        self.cf.read(confFile)
        self.conf = self.get_conf()
        self.headers = headers
        self.catalog, self.token = self.get_token()
        self.url = [url for url in self.catalog if url["name"] == "nova"]
        self.url_cinder = [url for url in self.catalog if url["name"] == "cinder"]
        self.url = self.url[0]["endpoints"][0]["url"]
        self.url_cinder = self.url_cinder[0]["endpoints"][0]["url"]

    def get_conf(self):
        try:
            conf = {
                "url": self.cf.get("ser", "OS_AUTH_URL"),
                "uname": self.cf.get("ser", "OS_USERNAME"),
                "passwd": self.cf.get("ser", "OS_PASSWORD"),
                "tname": self.cf.get("ser", "OS_TENANT_NAME"),
                "interval": self.cf.get("ser", "INTERVAL"),
                "disable_reason": self.cf.get("ser", "DISABLE_REASON")}

        except Exception as e:
            logging.critical("加载配置文件失败")
            logging.critical(e)
            sys.exit(1)

        return conf

    def get_token(self):
        """get token"""
        headers = self.headers
        url = self.conf["url"] + "/auth" + "/tokens"
        data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "domain": {
                                "name": "default"
                            },
                            "name": "%s",
                            "password": "%s"
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "name": "default"
                        },
                        "name": "%s"
                    }
                }
            }
        }
        # logging.info(data)
        datas = json.dumps(data)
        datas = datas % (self.conf["uname"], self.conf["passwd"], self.conf["tname"])
        data = json.loads(datas)
        # logging.debug(self.conf["tname"])
        try:
            logging.debug("开始获取Token")
            ret_token = requests.post(url, json=data, headers=headers).headers["X-Subject-Token"]
            ret = requests.post(url, json=data, headers=headers)
            logging.debug("request url:%s" % ret.url)
            ret = ret.json()
            # logging.info(ret)
        except Exception as e:
            msg = "获取Token失败  data:%s headers:%s url: %s" % (data, headers, url)
            logging.critical(msg)
            logging.critical(e)
        # catalog = ret["access"]["serviceCatalog"]
        catalog = ret["token"]["catalog"]
        token = ret_token
        return catalog, token

    def get_resp(self, suffix, method, kind=None, data=None, headers=None, params=None, isjson=True):
        """
        return the result of requests
        """
        if kind == 'cinder':
            url = self.url_cinder + suffix
        else:
            url = self.url + suffix
        logging.info(url)

        if headers == None:
            headers = self.headers.copy()
        headers["X-Auth-Token"] = self.token

        req = getattr(requests, method)
        # logging.info(req)
        try:
            ret = req(url, data=data, headers=headers, params=params, verify=False)
            logging.debug("request url:%s" % ret.url)
        except Exception as e:
            msg = "%s访问%s失败 data:%s headers:%s" % (method, suffix, data, headers)
            logging.critical(msg)
            logging.critical(e)
            sys.exit(1)

        if ret.status_code == 401:
            logging.warning("Token 过期,重新获取Token")
            self.catalog, self.token = self.get_token()
            headers["X-Auth-Token"] = self.token
            logging.debug("request headers:%s" % ret.request.headers)
            ret = req(url, data=data, headers=headers)

        if isjson:
            ret = ret.json()

        return ret


class check(baseInfo):
    """
    check the status of compute node
    """

    # def __init__(self):
    #    self.cmp_down = []
    #   self.cmp_all = []
    #   self.real_cmp_downs = self.real_cmp_down()

    def check(self):
        self.rabbitmq_status = self.chk_rabbitmq()
        self.pcs_status = self.chk_pcs_status()
        self.cmp_down_pre = []
        self.cmp_down = []
        self.cmp_all = []
        self.cmp_disable_prepare = []
        self.cmp_down, self.cmp_all, self.cmp_disable_prepare = self.chk_node()
        self.ser_down_pre = []
        self.ser_down = []
        self.ser_ip = []
        self.ser_down, self.ser_ip = self.chk_ser_from_node()
        self.real_cmp_downs, self.real_ser_downs = self.real_cmp_down()
        self.get_group_name = []
        self.get_group_user = []
        self.new_ser_owners = []
        # self.results = self.chk_fping_file()

    def chk_rabbitmq(self):
        rabbitmq_status = 'ok'
        return rabbitmq_status

    def chk_pcs_status(self):
        pcs_status = 'ok'
        return pcs_status

    def chk_fping(self, ip):
        if ip:
            ping_cmd = '/sbin/fping ' + str(ip)
            logging.info('ping_cmd: %s' % ping_cmd)
            # time.sleep(10)
            ping_res = os.popen(ping_cmd).read()
            logging.debug('computes ping result: %s' % ping_res)
            logging.info('ping_res: %s' % ping_res)
            if 'unreachable' in ping_res:
                result = str(ip)
            else:
                result = 'no_host_down'
        else:
            result = 'no_host_down'
        return result

    def chk_fping_file(self, ser_ip_list, down_host):
        """
        write server ip datas to a files
        """
        if ser_ip_list:
            file = open('/tmp/ser_ip_list', 'w')
            for i in range(len(ser_ip_list)):
                s = str(ser_ip_list[i]).replace('[', '').replace(']', '')
                s = s.replace("'", '').replace(',', '') + '\n'
                file.write(s)
            file.close()
            ping_cmd = '/sbin/fping  -f /tmp/ser_ip_list '
            ping_res = os.popen(ping_cmd).read()
            logging.debug('instances ping result: %s' % ping_res)
            if 'alive' not in ping_res:
                self.results = down_host
            else:
                self.results = 'no_server_down'
        else:
            self.results = 'no_server_down'
        results = self.results
        return results

    def get_hypervisor_ip(self, host):
        """
        get down hypervisor ip
        """
        suffix = "/os-hypervisors"
        hostname = host
        data = {}
        hypervisor_id = 11111
        ret = self.get_resp(suffix, "get", data=data)
        logging.info(ret)
        for key, value in ret.items():
            if key == 'hypervisors':
                for i in value:
                    if i.get('hypervisor_hostname') == hostname:
                        hypervisor_id = i.get('id')
        logging.info("get hypervisor_id is : %s " % hypervisor_id)
        suffix_url = "/os-hypervisors/%s" % hypervisor_id
        logging.info(suffix_url)
        ret = self.get_resp(suffix_url, "get", data=data)
        if ret['hypervisor']['host_ip']:
            hypervisor_ip = ret['hypervisor']['host_ip']
        else:
            logging.info("get hypervisor_id is : %s " % hypervisor_id)
            logging.info("get_hypervisor_ip API error")
            sys.exit(1)
        return hypervisor_ip

    def chk_node(self):
        """
        get the compute list service down
        """
        suffix = "/os-services"
        ret = self.get_resp(suffix, "get")
        disable_reason = self.conf["disable_reason"]
        logging.info("disbale_reason : %s" % disable_reason)
        ret = ret["services"]
        cmp_all = [host["host"] for host in ret if host["binary"] == "nova-compute" and 'ostack' in host["host"]]
        # get disable compute nodes, disable reason is normal_auto_pre_mmwei3
        cmp_disable_prepare = [host["host"] for host in ret if host["binary"] == "nova-compute" and host[
            'disabled_reason'] == disable_reason]
        logging.info(cmp_disable_prepare)
        logging.info('All compute nodes:%s' % cmp_all)
        logging.info('Auto prepare compute nodes:%s' % cmp_disable_prepare)
        cmp_down_pre = [host["host"] for host in ret if
                        host["state"] != "up" and host["binary"] == "nova-compute" and host[
                            "status"] == "enabled" and 'ostack' in host["host"]]
        # check computePre is alive
        if len(cmp_down_pre) < 2:
            for i in cmp_down_pre:
                if self.chk_fping(self.get_hypervisor_ip(i)) != 'no_host_down':
                    self.cmp_down.append(i)
            cmp_down = self.cmp_down
            cmp_all = self.cmp_all
            logging.info('Check the faulty compute node for the first time:%s' % cmp_down)
        else:
            logging.info('Check the faulty compute node numbers gt two : %s' % self.cmp_down)
            sys.exit(1)
        return cmp_down, cmp_all, cmp_disable_prepare

    def chk_ser_from_node(self):
        """
        get the server list from failed node
        """
        if self.cmp_down:
            suffix = "/servers/detail"
            params = {"all_tenants": 1, "host": self.cmp_down[0]}
            ret = self.get_resp(suffix, "get", params=params)
            ret = ret["servers"]
            # get server uuid for down compute
            # ser_down = [ser["id"] for ser in ret if ser["OS-EXT-SRV-ATTR:host"] in self.cmp_down]
            ser_down = [ser["id"] for ser in ret]
            # ser_owners = [ser["metadata"].get('owner') for ser in ret if ser["OS-EXT-SRV-ATTR:host"] in self.cmp_down]
            ser_owners = [ser["metadata"].get('owner') for ser in ret]
            new_ser_owners = list(set(ser_owners))
            logging.info(new_ser_owners)
            # get server ip for down compute
            ser_ips = [ser["addresses"] for ser in ret if ser["OS-EXT-SRV-ATTR:host"] in self.cmp_down]
            for i in ser_ips:
                for key, value in i.items():
                    for m in value:
                        one_ser_ip = m.get('addr')
                        self.ser_ip.append(one_ser_ip)
            ser_down = self.ser_down.extend(ser_down)
            ser_ip = self.ser_ip
            ser_down = self.ser_down
            logging.info(ser_down)

        else:
            ser_ip = []
            ser_down = []
        return ser_down, ser_ip

    def get_exec_rbd_watcher(self, volume_rbd):
        """
        exec rbd status check watcher for ceph
        0: the server no watcher
        1: the server have watcher
        :return:
        """
        popen = subprocess.Popen("rbd status %s" % volume_rbd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 bufsize=1, shell=True)
        is_watcher_data = popen.stdout.read()
        if 'cookie' in is_watcher_data:
            is_watchers = '1'
        else:
            is_watchers = '0'
        logging.info("is watcher : %s " % is_watchers)
        return is_watchers

    def get_server_volume_id(self, server_uuid):
        """
        get server volume id and volume type to rbd status
        :return:
        """
        if len(server_uuid) > 0:
            suffix = "/servers/%s/os-volume_attachments" % server_uuid
            ret = self.get_resp(suffix, "get")
            server_volume = ret['volumeAttachments'][0]['volumeId']
            suffix = "/volumes/%s" % server_volume
            ret_volume = self.get_resp(suffix, 'get', kind='cinder')
            volume_type = ret_volume['volume']['volume_type']
            rbd_name = volume_type + '/' + 'volume-' + server_volume
            logging.info("the server volume rbd_name is %s" % rbd_name)
            get_rbd_result = self.get_exec_rbd_watcher(rbd_name)
        else:
            get_rbd_result = '2'
        logging.info("the get rbd result is %s " % get_rbd_result)
        return get_rbd_result

    def get_server_rbd_name(self):
        """
        get server volume id and volume type to rbd name
        :return: server volume rbd
        """
        server_volumes_rbd = []
        server_uuids, server_ips = self.chk_ser_from_node()
        # max_workers is 100
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            # 线程列表
            to_do = []
            for i in server_uuids:
                future = executor.submit(self.get_server_volume_id, i)
                to_do.append(future)
        for future in concurrent.futures.as_completed(to_do):
            server_volumes_rbd.append(future.result())
        logging.debug("the server volume rbd result is :  ")
        # logging.debug("the server volume rbd result is : %s " % server_volumes_rbd)
        logging.debug(server_volumes_rbd)
        return server_volumes_rbd

    def real_cmp_down(self):
        """
        get real compute node down
        """
        # self.serDown, self.serIp = self.chkSerFromNode()
        # self.cmpDown, self.cmpAll = self.chkNode()
        rbd_volume_watcher = self.get_server_rbd_name()
        logging.debug('first_check_ser_ip: %s' % self.ser_ip)
        logging.debug('firsh_check_cmp_down: %s' % self.cmp_down)
        logging.debug('firsh_check_cmp_down: %s' % rbd_volume_watcher)
        if self.cmp_down and self.ser_ip and '1' not in rbd_volume_watcher:
            logging.info('aleary check real compute down compute and server ---- start chk_fing_file()')
            chk_ser_status_result = self.chk_fping_file(self.ser_ip, self.cmp_down)
            logging.info("chk_ser_status_result: %s" % chk_ser_status_result)
        else:
            chk_ser_status_result = 'no_server_down'
        if chk_ser_status_result != 'no_server_down':
            suffix = "/os-services/enable"
            data = '{"host": "%s","binary": "nova-compute"}' % self.cmp_disable_prepare[0]
            logging.info(data)
            ret = self.get_resp(suffix, "put", data=data, isjson=False)
            real_cmp_downs = self.cmp_down
            # logging.info(self.ser_ip)
            real_ser_downs = self.ser_down
            logging.info(real_ser_downs)
            suffix_agg = "/os-aggregates"
            ret_aggregate_name = self.get_resp(suffix_agg, "get")
            for i in ret_aggregate_name['aggregates']:
                if i['name'] == 'normal':
                    aggregate_ids = i['id']
                else:
                    aggregate_ids = 1
            logging.info("get aggregate id is %s " % aggregate_ids)
            # add aggregate for cmp_disable_prepare
            suffixs = "/os-aggregates/%s/action" % aggregate_ids
            datas = '{"add_host":{"host":"%s"}}' % self.cmp_disable_prepare[0]
            ret = self.get_resp(suffixs, "put", data=datas, isjson=False)
            logging.info(data)

        else:
            real_cmp_downs = []
            real_ser_downs = []
        logging.debug('Final confirmed compute node:%s' % real_cmp_downs)
        logging.debug('Final confirmed server uuid:%s' % real_ser_downs)
        return real_cmp_downs, real_ser_downs

    def test(self):
        logging.debug('cmp_down: %s' % self.cmp_down)
        logging.debug('ser_down: %s' % self.ser_down)
        logging.debug('serve_ip: %s' % self.ser_ip)
        logging.debug('real_cmp_downs: %s' % self.real_cmp_downs)
        logging.debug('real_ser_downs: %s' % self.real_ser_downs)

    def send_email(self, subject, content, email):
        data = dict()
        mail = {'subject': subject, 'to': email, 'body': content}
        data['mail'] = json.dumps(mail)
        mail_server = 'http://x.x.x.x/mail'
        logging.info(data['mail'])
        resp = requests.post(mail_server, data['mail'])
        logging.info(resp)
        logging.info('---mail send ok---')
        logging.info(resp.text)

    def get_group_user(self, owners_list):
        self.names = []
        for i in owners_list:
            i = i + '@x.x.x.x.com'
            self.names.append(i)
        names = self.names
        logging.info(names)
        return names

    def get_group_name(self):
        group_name = 'cloud@iflytek.com'
        return group_name

    def send_sms(self, hostname):
        resp = requests.get('http://x.x.x.x/sms?hostname=%s&type=1' % hostname)

    def send_sms_insert_mongo(self, hostname, types):
        resp = requests.get('http://x.x.x.x/api/hostname=%s&type=%s' % (hostname, types))

    def get_vms_info(self, hostname):
        resp_vms_info = requests.get('http://x.x.x.x/api/hostname=%s' % hostname)
        resp_vms_infos = resp_vms_info.json()
        return resp_vms_infos

    def get_vms_user(self, hostname):
        resp_vms_user = requests.get('http://x.x.x.x/api/hostname=%s' % hostname)
        resp_vms_users = resp_vms_user.json()
        return resp_vms_users

    def get_oncall(self):
        resp_onall = requests.get(
            'http://x.x.x.x')

    def get_recover_info(self, hostname, types):
        resp_get_recover = requests.get(
            'http:/x.x.x.x' % (hostname, types))

    def ify_verification_code(self, users):
        """
        func: ixf send verification code
        :param users: type list
        :return:
        """
        tmp_list = []
        for i in users:
            tmp_list.append(i.split('|'))
        instance_infos = []
        for i in tmp_list:
            tmp_str_ops = str(
                str(i[3]) + '|' + str(i[4]) + '|' + str(i[7] + '|' + str(i[8]) + '|' + str(i[9])))
            tmp_str_owner = str(
                str(i[3]) + '|' + str(i[4]) + '|' + str(i[7] + '|' + str(i[8]) + '|' + str(i[9])))
            tmp_key_ops = {'name': i[5], 'value': tmp_str_ops}
            tmp_key_owner = {'name': i[6], 'value': tmp_str_owner}
            instance_infos.append(tmp_key_ops)
            instance_infos.append(tmp_key_owner)
        new_infos = []
        for i in instance_infos:
            if i not in new_infos:
                new_infos.append(i)
        try:
            headers = {
                'Content-Type': 'application/json',
            }
            for i in new_infos:
                data = {"user": i.get('name', 'xxx'),
                        "msg": "【重要】宿主机宕机，受影响的虚机：" + str(i.get('value', 'null'))}
                response = requests.post('http://x.x.x.x', headers=headers, json=data)
                response.json()
        except Exception as e:
            logging.critical(e)

    def get_owner_instances(self):
        """
        get owner for instance
        """
        logging.info(self.real_cmp_downs)
        if self.real_cmp_downs:
            # get server owner for down compute
            try:
                new_ser_owners = self.get_vms_user(self.real_cmp_downs[0])
                new_ser_owners = new_ser_owners.get('vmsinfo')
                logging.info(new_ser_owners)
                vms_infos = self.get_vms_info(self.real_cmp_downs[0])
                vms_infos = vms_infos.get('vmsinfo')
                logging.info(vms_infos)
                content_server_mail = "<br>".join(vms_infos)
                user_mail = []
                self.send_sms(self.real_cmp_downs[0])
                types = 1
                # self.send_sms_insert_mongo(self.real_cmp_downs[0], types)
                self.get_recover_info(self.real_cmp_downs[0], types)
                for i in new_ser_owners:
                    i = i + '@x.x.x.x'
                    user_mail.append(i)
                mail_to = ['cloud@iflytek.com'] + user_mail
                logging.info(mail_to)
                content = "xxxxxxxx <br>" % self.real_cmp_downs
                contents = content + content_server_mail.decode('utf-8')
                logging.info(contents)
                title = '【重要】xxxx云服务器宕机通知'
                self.send_email(title, contents, mail_to)
                self.ify_verification_code(vms_infos)
            except Exception as e:
                logging.critical(e)
        else:
            new_ser_owners = ''
            mail_to = ''


class fence(baseInfo):
    """
    fence the compute node
    """

    def __init__(self):
        super(fence, self).__init__()
        pass

    def fence_pre(self, host):
        """
        disable nova-compute
        """
        # suffix = "/os-services/disable"
        ticks = time.time()
        suffix = "/os-services/disable-log-reason"
        data = '{"host": "%s","binary": "nova-compute", "disabled_reason": "auto_check_compute_down_%d" }' % (
            host, ticks)
        logging.info(data)
        ret = self.get_resp(suffix, "put", data=data, isjson=False)

        return ret.ok

    def get_hypervisor_ip(self, host):
        """
        get down hypervisor ip
        """
        suffix = "/os-hypervisors/detail"
        data = '{"hypervisor_hostname_pattern": "%s"}' % host
        ret = self.get_resp(suffix, "get", data=data)
        logging.info(ret)

    def ipmitool_action(self, host):
        """
        exec ipmitool command - power off

        """
        urls = 'http://x.x.x.x/api/ipmi_openstack'
        hosts = host
        datas = {"hostname": hosts}
        headers = {"User_Agent": "PostmanRuntime/7.28.4",
                   "Connection": "keep-alive",
                   "Accept-Encoding": "gzip, deflate, br",
                   "Cookie": 'x.x.x.x"'}
        resp_ipmitool_cmd = requests.post(url=urls, data=datas, headers=headers)

    def fence_test(self, host):
        """
        fence for test
        """
        cmd = " ".join(["ssh", host, "'touch /tmp/`date +%Y-%m-%d`'"])
        p = sp.Popen(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        ret_code = p.wait()

        return ret_code

    def test(self):
        for h in self.host:
            logging.info('fence_pre: %s' % self.fence_pre(h))
            # logging.info('fence_test: %s' % self.fence_test(h))

    def fence(self, host):
        for h in host:
            self.fence_pre(h)
            # self.get_hypervisor_ip(h)
            # self.fence_test(h)
            self.ipmitool_action(h)


class recover(baseInfo):
    """
    evacuate the all installce from the failed compute node
    """

    def __init__(self):
        super(recover, self).__init__()
        pass

    def evacuate(self, ser_id):
        """
        evacuate the server
        """
        suffix = "/servers/%s/action" % ser_id
        data = '{"evacuate": {"onSharedStorage": "True"}}'
        ret = self.get_resp(suffix, "post", data=data, isjson=False)

        return ret.ok

    def check(self, ser_id):
        """
        check the instance whether if evacuated success
        """
        suffix = "/servers/%s" % ser_id
        ret = self.get_resp(suffix, "get")
        status = ret["server"]["status"]

        return status

    def check_evacuate_server_host(self, ser_id):
        """
        check the instance lauch on compute nodes whether if evacuated success
        """
        suffix = "/servers/%s" % ser_id
        ret = self.get_resp(suffix, "get")
        instance_hosts = ret["server"]["OS-EXT-SRV-ATTR:host"]

        return instance_hosts

    def recover(self, ser_id):
        """
        evacuate server start
        """
        global flag_number
        flag_number = 1
        global evacuate_result_id
        evacuate_result_id = []
        logging.info("ser_id is length: %s  " % len(ser_id))
        if len(ser_id) > 0:
            for s in ser_id:
                st = self.check(s)
                if st == "ACTIVE" or st == "ERROR":
                    self.evacuate(s)
                    flag_number = flag_number + 1
                    evacuate_result_id.append(s)
                    time.sleep(0.5)
                else:
                    logging.warning(u"Virtual_Machine_Not_Evacuate---%s---Because_The_VM_Stautus_is:%s" % (s, st))
            time.sleep(120)
        else:
            pass

    def send_sms_result(self, hosts, types):
        resp_get_recover = requests.get(
            'http://x.x.x.x/getvmscall?hostname=%s&type=%s' % (hosts, types))

    def send_sms(self, hostname):
        resp = requests.get('http://x.x.x.x/hostname=%s&type=2' % hostname)

    def get_oncall(self):
        resp_onall = requests.get(
            'http://x.x.x.x')

    def check_evacuate_result(self, host):
        """
        check evacuate result
        """
        logging.info(flag_number)
        logging.info(evacuate_result_id)
        evacuate_hosts = []
        if flag_number != 1:
            for i in evacuate_result_id:
                ihost = self.check_evacuate_server_host(i)
                evacuate_hosts.append(ihost)
            logging.info(host[0])
            logging.info(evacuate_hosts)
            if host[0] not in evacuate_hosts:
                logging.info(evacuate_hosts)
                logging.info(host[0])
                for j in host:
                    host = j
                logging.info('evacuate server successful')
                self.send_sms_result(host, 2)
                self.send_sms(host)
            else:
                for j in host:
                    host = j
                logging.info('evacuate server failed')
                self.get_oncall()
                self.send_sms_result(host, 3)
        else:
            logging.info('pass')
            pass


def main():
    logging.info('---------start-----------')
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        ch = check()
        fen = fence()
        recov = recover()
        while True:
            interval = ch.conf["interval"]
            logging.info(interval)
            try:
                interval = int(interval)
            except Exception as e:
                msg = "time set error for interval:%s" % interval
                logging.critical(msg)
                logging.critical(e)
                sys.exit(1)

            cmd = "lsl"
            # logging.info(cmd)
            p = sp.Popen(cmd, shell=True, stdout=DEVNULL, stderr=sp.STDOUT)
            logging.info(p)
            vip = p.wait()
            logging.info(vip)
            if vip:
                ch.check()
                logging.info("ch.check()")
                ch.test()
                logging.info("ch.test()")
                fen.fence(ch.real_cmp_downs)
                logging.info("ch.real_ser_downs: %s " % ch.real_ser_downs)
                logging.info("ch.real_cmp_downs: %s " % ch.real_cmp_downs)
                logging.info("Virtual machines on the down compute nodes %s" % ch.real_ser_downs)
                ch.get_owner_instances()
                recov.recover(ch.real_ser_downs)
                recov.check_evacuate_result(ch.real_cmp_downs)

            time.sleep(interval)

    else:
        print("The configuration file does not exist.")


if __name__ == "__main__":
    main()
