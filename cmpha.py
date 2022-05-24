#!/usr/bin/env python
# coding: utf-8
# author: mmwei3
# date: 2021/12/12
import sys
from imp import reload

import requests
import time
import logging
import os
import subprocess as sp
from ConfigParser import ConfigParser
from pprint import pprint
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
        # logging.info(self.url)
        self.url = self.url[0]["endpoints"][0]["url"]

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
            logging.critical("The configuration file does not exist.")
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
            logging.debug("Start Get Token")
            ret_token = requests.post(url, json=data, headers=headers).headers["X-Subject-Token"]
            ret = requests.post(url, json=data, headers=headers)
            logging.debug("request url:%s" % ret.url)
            ret = ret.json()
            # logging.info(ret)
        except Exception as e:
            msg = "Get Token failed data:%s headers:%s url: %s" % (data, headers, url)
            logging.critical(msg)
            logging.critical(e)

        # catalog = ret["access"]["serviceCatalog"]
        catalog = ret["token"]["catalog"]
        token = ret_token
        return catalog, token

    def get_resp(self, suffix, method, data=None, headers=None, params=None, isjson=True):
        """
        return the result of requests
        """
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
            msg = "%s access %s failed data:%s headers:%s" % (method, suffix, data, headers)
            logging.critical(msg)
            logging.critical(e)
            sys.exit(1)

        if ret.status_code == 401:
            logging.warning("Token expire, afresh get Token")
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
            logging.info('ping_cmd: %' % ping_cmd)
            # time.sleep(10)
            ping_res = os.popen(ping_cmd).read()
            logging.debug('computes ping result: %s' % ping_res)
            logging.info('ping_res: %' % ping_res)
            if 'alive' not in ping_res:
                result = str(ip)
            else:
                result = ''
        else:
            result = ''
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
                self.results = ''
        else:
            self.results = ''
        results = self.results
        return results

    def chk_node(self):
        """
        get the compute list service down
        """
        suffix = "/os-services"
        ret = self.get_resp(suffix, "get")
        ret = ret["services"]
        disable_reason = self.conf["disable_reason"]
        cmp_all = [host["host"] for host in ret if host["binary"] == "nova-compute" and 'ostack' in host["host"]]
        # get disable compute nodes, disable reason is normal_auto_pre_mmwei3
        cmp_disable_prepare = [host["host"] for host in ret if host["binary"] == "nova-compute" and host[
            'disabled_reason'] == disable_reason]
        logging.info(cmp_disable_prepare)
        logging.debug('All compute nodes:%s' % cmp_all)
        logging.debug('Auto prepare compute nodes:%s' % cmp_disable_prepare)
        cmp_down_pre = [host["host"] for host in ret if
                        host["state"] != "up" and host["binary"] == "nova-compute" and host[
                            "status"] == "enabled" and 'ostack' in host["host"]]
        # check computePre is alive
        for i in cmp_down_pre:
            if self.chk_fping(i):
                self.cmp_down.append(i)
        cmp_down = self.cmp_down
        cmp_all = self.cmp_all
        logging.debug('Check the faulty compute node for the first time:%s' % cmp_down)
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
            # logging.info(ret)
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
        else:
            ser_ip = []
            ser_down = []
        ser_ip = self.ser_ip
        ser_down = self.ser_down
        return ser_down, ser_ip

    def real_cmp_down(self):
        """
        get real compute node down
        """
        # self.serDown, self.serIp = self.chkSerFromNode()
        # self.cmpDown, self.cmpAll = self.chkNode()
        logging.debug('first_check_ser_ip: %s' % self.ser_ip)
        logging.debug('firsh_check_cmp_down: %s' % self.cmp_down)
        if self.cmp_down and self.ser_ip:
            logging.info('-----------')
            chk_ser_status_result = self.chk_fping_file(self.ser_ip, self.cmp_down)
            logging.info(chk_ser_status_result)
        else:
            chk_ser_status_result = ''
        if chk_ser_status_result:
            suffix = "/os-services/enable"
            data = '{"host": "%s","binary": "nova-compute"}' % self.cmp_disable_prepare[0]
            logging.info(data)
            ret = self.get_resp(suffix, "put", data=data, isjson=False)
            real_cmp_downs = self.cmp_down
            # logging.info(self.ser_ip)
            real_ser_downs = self.ser_down
            logging.info(real_ser_downs)
            # add aggregate for cmp_disable_prepare
            suffixs = "/os-aggregates/1/action"
            datas = '{"add_host":{"host":"%s"}}' % self.cmp_disable_prepare[0]
            ret = self.get_resp(suffixs, "put", data=datas, isjson=False)
            logging.info(data)

        else:
            real_cmp_downs = []
            real_ser_downs = []
        real_ser_downs = real_ser_downs
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
        pass

    def get_group_user(self, owners_list):
        pass

    def get_group_name(self):
        pass

    def send_sms(self, hostname):
        pass

    def send_sms_insert_mongo(self, hostname, types):
        pass

    def get_vms_info(self, hostname):
        pass

    def get_vms_user(self, hostname):
        pass

    def get_oncall(self):
        pass

    def get_recover_info(self, hostname, types):
        pass

    def get_owner_instances(self):
        pass


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

        pass

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
            logging.info('fence_test: %s' % self.fence_test(h))

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
        for s in ser_id:
            st = self.check(s)
            if st == "ACTIVE" or st == "ERROR":
                cmd = "lls %s" % ser_id
                p = sp.Popen(cmd, shell=True, stdout=DEVNULL, stderr=sp.STDOUT)
                r = p.wait()
                self.evacuate(s)
                flag_number = flag_number + 1
                evacuate_result_id.append(s)
                time.sleep(0.5)
            else:
                logging.warning(u"Virtual_Machine_Not_Evacuate---%s---Because_The_VM_Stautus_is:%s" % (s, st))

    def send_sms_result(self, hosts, types):
        pass

    def send_sms(self, hostname):
        pass

    def get_oncall(self):
        pass

    def check_evacuate_result(self, host):
        """
        check evacuate result
        """
        logging.info(flag_number)
        logging.info('+++++++++++++')
        logging.info(evacuate_result_id)
        evacuate_hosts = []
        if flag_number != 1:
            for i in evacuate_result_id:
                ihost = self.check_evacuate_server_host(i)
                evacuate_hosts.append(ihost)
            if host not in evacuate_hosts:
                logging.info(evacuate_hosts)
                logging.info(host)
                logging.info('evacuate server successful')
                self.send_sms_result(host, 2)
                self.send_sms(host)
            else:
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
            if vip:
                ch.check()
                ch.test()
                fen.fence(ch.real_cmp_downs)
                logging.info("Virtual machines on the down compute nodes %s" % ch.ser_down)
                ch.get_owner_instances()
                recov.recover(ch.ser_down)
                recov.check_evacuate_result(ch.real_cmp_downs)

            time.sleep(interval)
    else:
        print("The configuration file does not exist.")

if __name__ == "__main__":
    main()