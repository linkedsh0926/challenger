#!/usr/bin/python
# -*- coding: utf-8 -*-

import getopt
import json
import logging
import re
import subprocess
import sys

import requests

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s: %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)

CHALLENGER_CONFIG_PATH = "/opt/challenger/conf/challenger.json"
V2RAY_CLIENT_CONFIG_PATH = "/opt/challenger/conf/v2ray-client.json"
DNS_SERVICE_CONFIG_PATH = "/opt/challenger/conf/dns-service.json"
NAT_SERVICE_CONFIG_PATH = "/opt/challenger/conf/nat-service.json"
SOFTETHER_SERVER_CONFIG_PATH = "/opt/challenger/conf/softether-server.json"


def load_config(configPath):
    with open(configPath, 'r') as f:
        configText = f.read()
        configDict = json.loads(configText)

    return configDict


def print_list(cmd):
    cmdLine = ""
    for s in cmd:
        cmdLine += "%s " % s

    return cmdLine


def kill_process_by_path(path):
    cmd = "ps -ef | grep %s | grep -v grep | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1" % path
    logging.debug("Running %s ..." % cmd)
    rc = subprocess.call(cmd, shell=True, stdout=None, stderr=None)

    return rc


def format_command(cmdParamList):
    formattedCmdParamList = []
    for cmdParam in cmdParamList:
        cmdParam = str(cmdParam)
        formattedCmdParamList += cmdParam.split()

    return formattedCmdParamList


class Challenger(object):
    def __init__(self, challengerConfPath, v2rayClientConfPath, dnsServiceConfPath, natServiceConfPath, softEtherConfPath):
        challengerConfDict = load_config(challengerConfPath)
        v2rayClientConfDict = load_config(v2rayClientConfPath)
        dnsServiceConfDict = load_config(dnsServiceConfPath)
        natServiceConfDict = load_config(natServiceConfPath)
        softEtherConfDict = load_config(softEtherConfPath)

        self.V2RayClient = self.V2RayClient(
            challengerConfDict, v2rayClientConfDict)
        self.DNSService = self.DNSService(
            challengerConfDict, dnsServiceConfDict)
        self.NATService = self.NATService(
            challengerConfDict, natServiceConfDict)
        self.SoftEtherServer = self.SoftEtherServer(
            challengerConfDict, softEtherConfDict)

    def start(self):
        self.V2RayClient.start()
        self.DNSService.start()
        self.NATService.start()
        self.SoftEtherServer.start()

    def stop(self):
        self.SoftEtherServer.stop()
        self.NATService.stop()
        self.DNSService.stop()
        self.V2RayClient.stop()

    def restart(self):
        self.V2RayClient.restart()
        self.DNSService.restart()
        self.NATService.restart()
        self.SoftEtherServer.restart()

    class V2RayClient(object):
        def __init__(self, challengerConfDict, v2rayClientConfDict):
            self.binaryPath = v2rayClientConfDict["binaryPath"]
            # [challengerConfDict["upStreamAddr"]]
            self.settingsDict = v2rayClientConfDict["settings"]

        def generate_v2ray_json(self):
            logging.info(
                "Generating V2Ray client configuration to /tmp/v2ray-client.json ...")
            confJson = json.dumps(self.settingsDict)
            with open("/tmp/v2ray-client.json", 'w') as f:
                f.write(confJson)

        def start(self):
            logging.info("Starting V2Ray client ...")
            self.generate_v2ray_json()
            cmd = [
                self.binaryPath,
                "-config",
                "/tmp/v2ray-client.json"
            ]

            logging.debug("Running %s ..." % print_list(cmd))
            child = subprocess.Popen(cmd, stdout=None, stderr=None)

        def stop(self):
            logging.info("Stopping V2Ray client ...")
            kill_process_by_path(self.binaryPath)

        def restart(self):
            logging.info("Restarting V2Ray client ...")
            self.stop()
            self.start()

    class DNSService(object):
        def __init__(self, challengerConfDict, dnsConfDict):
            self.Config = self.Config(challengerConfDict, dnsConfDict)
            self.Daemon = self.Daemon(challengerConfDict, dnsConfDict)

        def start(self):
            self.Config.generate_dnsmasq_config()
            self.Daemon.start()

        def stop(self):
            logging.info("Stopping DNS service ...")
            self.Daemon.stop()

        def restart(self):
            logging.info("Restarting DNS service ...")
            self.stop()
            self.start()

        class Config(object):
            def __init__(self, challengerConfDict, dnsConfDict):
                self.ispDNSAddr = challengerConfDict["ispDNSAddr"]
                self.ispDNSPort = challengerConfDict["ispDNSPort"]
                self.overseasDNSAddr = "127.0.0.1"
                self.overseasDNSPort = dnsConfDict["chinaDNS"]["listenPort"]
                self.resolveStrategy = challengerConfDict["strategy"]
                self.gfwlistDownloadUrl = challengerConfDict["gfwlistDownloadUrl"]
                self.gfwlistPath = challengerConfDict["gfwlistPath"]

                self.customRules = dnsConfDict["customRules"]
                self.dnsmasqConfDict = dnsConfDict["dnsmasq"]

            def generate_server_rule(self, domain, dnsAddr, dnsPort):
                return "server=/%s/%s#%s" % (domain, dnsAddr, dnsPort)

            def generate_ipset_rule(self, domain, ipsetName):
                return "ipset=/%s/%s" % (domain, ipsetName)

            def generate_address_rule(self, domain, ipAddr):
                return "address=/%s/%s" % (domain, ipAddr)

            def generate_black_rules(self):
                logging.info("Generating blacklist DNS resolve rules ...")
                domainList = self.customRules["blackList"]
                ruleStr = "\n\n# Blacklist rules\n"
                for domain in domainList:
                    ruleStr += "%s\n%s\n" % (self.generate_server_rule(domain, self.overseasDNSAddr, self.overseasDNSPort),
                                             self.generate_ipset_rule(domain, "blackList"))

                return ruleStr

            def generate_white_rules(self):
                logging.info("Generating whitelist DNS resolve rules ...")
                domainList = self.customRules["whiteList"]
                ruleStr = "\n\n# Whitelist rules\n"
                for domain in domainList:
                    ruleStr += "%s\n%s\n" % (self.generate_server_rule(domain, self.ispDNSAddr, self.ispDNSPort),
                                             self.generate_ipset_rule(domain, "whiteList"))

                return ruleStr

            def generate_custom_rules(self):
                logging.info("Generating custom DNS resolve rules ...")
                customRuleList = self.customRules["others"]
                ruleStr = "\n\n# Custom rules\n"
                for ruleDict in customRuleList:
                    if ruleDict["type"] == "server":
                        domain = ruleDict["domain"]
                        dnsAddr = self.ispDNSAddr
                        dnsPort = self.ispDNSPort
                        ipsetName = "whiteList"
                        if ruleDict["network"] == "overseas":
                            dnsAddr = self.overseasDNSAddr
                            dnsPort = self.overseasDNSPort
                            ipsetName = "blackList"

                        ruleStr += "%s\n%s\n" % (self.generate_server_rule(domain, dnsAddr, dnsPort),
                                                 self.generate_ipset_rule(domain, ipsetName))
                    elif ruleDict["type"] == "address":
                        ruleStr += "%s\n" % (self.generate_address_rule(
                            ruleDict["domain"], ruleDict["address"]))
                    else:
                        pass

                return ruleStr

            def generate_gfwlist_rules(self):
                logging.info("Generating gfwlist rules ...")
                gfwRuleStr = "\n\n# GFWList rules\n"
                gfwDomainList = []

                # # 下载最新 GFWList
                # logging.debug("Downloading latest gfwlist from %s ..." %
                #               self.gfwlistDownloadUrl)
                # rawGfwList = requests.get(self.gfwlistDownloadUrl)
                # rawGfwList = rawGfwList.content.decode('base64').split('\n')
                # for line in rawGfwList:
                for line in open(self.gfwlistPath, 'r'):
                    # 忽略注释行
                    commentRegexp = "^!.*"
                    if re.findall(commentRegexp, line):
                        continue

                    # 匹配域名规则
                    domainRegexp = "^([\|@]{1,4})?(?:http[s]*://)?((?:[\w\-\*]+)?(?:\.[\w\-]+)+)"
                    r = re.findall(domainRegexp, line)
                    if not r:
                        continue

                    rule = r[0][0]
                    gfwDomain = r[0][1]

                    if "@@" in rule:
                        ipsetName = "ispNetwork"
                        dnsAddr = self.ispDNSAddr
                        dnsPort = self.ispDNSPort
                    else:
                        ipsetName = "overseasNetwork"
                        dnsAddr = self.overseasDNSAddr
                        dnsPort = self.overseasDNSPort

                    if '|' in rule:
                        if "||" in rule:
                            if gfwDomain[0] != '.':
                                gfwDomain = '.' + gfwDomain
                        else:
                            if gfwDomain[0] == '.':
                                gfwDomain = gfwDomain.split('.')[1]

                    if not gfwDomain in gfwDomainList:
                        gfwDomainList.append(gfwDomain)
                        gfwRuleStr += "%s\n%s\n" % (self.generate_server_rule(gfwDomain, dnsAddr, dnsPort),
                                                    self.generate_ipset_rule(gfwDomain, ipsetName))

                return gfwRuleStr

            def generate_dnsmasq_config(self):
                logging.info(
                    "Generating dnsmasq configuration to /tmp/dnsmasq.conf ...")

                # 国内优先解析模式
                defaultDNSAddr = self.ispDNSAddr
                defaultDNSPort = self.ispDNSPort
                # 国外优先解析模式
                if self.resolveStrategy != "gfwlist":
                    defaultDNSAddr = self.overseasDNSAddr
                    defaultDNSPort = self.overseasDNSPort

                configText = "# Auto generated by Challenger v0.1\n"
                configText += "\n# Dnsmasq basic configurations\n"
                if self.dnsmasqConfDict.has_key("bindDynamic") and self.dnsmasqConfDict["bindDynamic"]:
                    configText += "bind-dynamic\n"
                if self.dnsmasqConfDict.has_key("noPoll") and self.dnsmasqConfDict["noPoll"]:
                    configText += "no-poll\n"
                if self.dnsmasqConfDict.has_key("noResolv") and self.dnsmasqConfDict["noResolv"]:
                    configText += "no-resolv\n"
                if self.dnsmasqConfDict.has_key("noNegcache") and self.dnsmasqConfDict["noNegcache"]:
                    configText += "no-negcache\n"
                if self.dnsmasqConfDict.has_key("log-queries") and self.dnsmasqConfDict["log-queries"]:
                    configText += "log-queries\n"

                configText += "listen-address=%s\n" % self.dnsmasqConfDict["listenIP"]
                configText += "port=%s\n" % self.dnsmasqConfDict["listenPort"]
                configText += "pid-file=%s\n" % self.dnsmasqConfDict["pidFile"]
                configText += "user=%s\n" % self.dnsmasqConfDict["underUser"]
                configText += "server=%s#%s\n" % (defaultDNSAddr,
                                                  defaultDNSPort)
                configText += "cache-size=%s\n" % self.dnsmasqConfDict["cacheSize"]
                configText += "min-port=%s\n" % self.dnsmasqConfDict["minPort"]

                configText += self.generate_black_rules()
                configText += self.generate_white_rules()
                configText += self.generate_custom_rules()

                if self.resolveStrategy == "gfwlist":
                    configText += self.generate_gfwlist_rules()

                with open("/tmp/dnsmasq.conf", 'w') as f:
                    f.write(configText)

        class Daemon(object):
            def __init__(self, challengerConfDict, dnsConfDict):
                self.Dns2socks = self.Dns2socks(
                    challengerConfDict, dnsConfDict)
                self.ChinaDNS = self.ChinaDNS(challengerConfDict, dnsConfDict)
                self.Dnsmasq = self.Dnsmasq(challengerConfDict, dnsConfDict)

            def start(self):
                logging.info("Starting DNS daemon processes ...")
                self.Dns2socks.start()
                self.ChinaDNS.start()
                self.Dnsmasq.start()

            def stop(self):
                logging.info("Stopping DNS daemon processes ...")
                self.Dnsmasq.stop()
                self.ChinaDNS.stop()
                self.Dns2socks.stop()

            def restart(self):
                self.stop()
                self.start()

            class Dns2socks(object):
                def __init__(self, challengerConfDict, dnsConfDict):
                    self.binaryPath = dnsConfDict["dns2socks"]["binaryPath"]
                    self.listenIP = dnsConfDict["dns2socks"]["listenIP"]
                    self.listenPort = dnsConfDict["dns2socks"]["listenPort"]
                    self.logOutputPath = dnsConfDict["dns2socks"]["logPath"]

                    self.upStreamSocksAddr = dnsConfDict["dns2socks"]["upStreamSocksAddr"]
                    self.upStreamSocksPort = dnsConfDict["dns2socks"]["upStreamSocksPort"]
                    self.overseasDNSAddr = challengerConfDict["overseasDNSAddr"]
                    self.overseasDNSPort = challengerConfDict["overseasDNSPort"]

                def start(self):
                    logging.info(
                        "Starting dns2socks daemon process, logging to %s" % self.logOutputPath)
                    logOutputPipe = open(self.logOutputPath, "a")
                    cmd = [
                        self.binaryPath,
                        "%s:%s" % (self.upStreamSocksAddr,
                                   self.upStreamSocksPort),
                        "%s:%s" % (self.overseasDNSAddr, self.overseasDNSPort),
                        "%s:%s" % (self.listenIP, self.listenPort)
                    ]
                    self.child = subprocess.Popen(
                        cmd, stdout=logOutputPipe, stderr=logOutputPipe)
                    logging.info("Running %s ..." % print_list(cmd))

                def stop(self):
                    logging.info("Stopping dns2socks daemon process ...")
                    kill_process_by_path(self.binaryPath)

            class ChinaDNS(object):
                def __init__(self, challengerConfDict, dnsConfDict):
                    self.binaryPath = dnsConfDict["chinaDNS"]["binaryPath"]
                    self.listenIP = dnsConfDict["chinaDNS"]["listenIP"]
                    self.listenPort = dnsConfDict["chinaDNS"]["listenPort"]
                    self.logOutputPath = dnsConfDict["chinaDNS"]["logPath"]

                    self.chnRoutePath = challengerConfDict["chnRouteList"]
                    self.ispDNSAddr = challengerConfDict["ispDNSAddr"]
                    self.ispDNSPort = challengerConfDict["ispDNSPort"]
                    self.overseasDNSAddr = dnsConfDict["dns2socks"]["listenIP"]
                    self.overseasDNSPort = dnsConfDict["dns2socks"]["listenPort"]

                    self.resolvStrategy = challengerConfDict["strategy"]

                def start(self):
                    logging.info(
                        "Starting ChinaDNS daemon process, logging to %s" % self.logOutputPath)
                    logOutputPipe = open(self.logOutputPath, "a")
                    cmd = [
                        self.binaryPath,
                        "-b", self.listenIP,
                        "-p", str(self.listenPort),
                        "-c", self.chnRoutePath,
                        "-s", "%s,%s:%s" % (
                            self.ispDNSAddr,
                            self.overseasDNSAddr, self.overseasDNSPort
                        ),
                        "-v"
                    ]
                    if self.resolvStrategy == "gfwlist":
                        cmd += ["-d"]

                    self.child = subprocess.Popen(
                        cmd, stdout=logOutputPipe, stderr=logOutputPipe)
                    logging.info("Running %s ..." % print_list(cmd))

                def stop(self):
                    logging.info("Stopping ChinaDNS daemon process ...")
                    kill_process_by_path(self.binaryPath)

            class Dnsmasq(object):
                def __init__(self, challengerConfDict, dnsConfDict):
                    self.binaryPath = dnsConfDict["dnsmasq"]["binaryPath"]
                    self.logOutputPath = dnsConfDict["dnsmasq"]["logPath"]

                def start(self):
                    logging.info(
                        "Starting dnsmasq daemon process, logging to %s" % self.logOutputPath)
                    logOutputPipe = open(self.logOutputPath, "a")
                    cmd = [
                        self.binaryPath,
                        "--conf-file=/tmp/dnsmasq.conf",
                        "-d",
                        "-q"
                    ]
                    self.child = subprocess.Popen(
                        cmd, stdout=logOutputPipe, stderr=logOutputPipe)
                    logging.info("Running %s ..." % print_list(cmd))

                def stop(self):
                    logging.info("Stopping ChinaDNS daemon process ...")
                    kill_process_by_path(self.binaryPath)

    class NATService(object):
        def __init__(self, challengerConfDict, natServiceConfDict):
            self.chnRoutePath = challengerConfDict["chnRouteList"]
            self.natStrategy = challengerConfDict["strategy"]
            self.upStreamAddr = challengerConfDict["upStreamAddr"]

            self.ipsetConfList = natServiceConfDict["ipsetList"]
            self.iptablesConf = natServiceConfDict["iptables"]

            self.ipsetRuleDict = {}
            self.chainDict = {}

        def start(self):
            logging.info("Generating NAT rules ...")

            # 初始化 ipset
            logging.info("Initializing ipset ...")
            for ipsetConf in self.ipsetConfList:
                ipsetRule = self.Ipset(ipsetConf["name"], ipsetConf["type"])
                ipsetRule.create()
                ipsetRule.flush()
                self.ipsetRuleDict[ipsetConf["name"]] = ipsetRule

            # 添加自定义规则到对应 ipset
            logging.info("Adding custom rules to ipset ...")
            for ipsetConf in self.ipsetConfList:
                for ipAddrMask in ipsetConf["rules"]:
                    self.ipsetRuleDict[ipsetConf["name"]].add_child(ipAddrMask)

            # 添加上游 ip 到白名单
            logging.info("Adding upstream server ip to whitelist ...")
            self.ipsetRuleDict["whiteList"].add_child(self.upStreamAddr)

            # 添加 chnroute 到 ispNetwork
            if self.natStrategy == "chnroute":
                logging.info(
                    "Adding China mainland routing table to whitelist ...")
                for ipAddrMask in open(self.chnRoutePath, 'r'):
                    ipAddrMask = ipAddrMask.strip('\n')
                    ipAddrMaskRegexp = "((1[0-9][0-9]\.)|(2[0-4][0-9]\.)|(25[0-5]\.)|([1-9][0-9]\.)|([0-9]\.)){3}((1[0-9][0-9])|(2[0-4][0-9])|(25[0-5])|([1-9][0-9])|([0-9]))/(\w+)"
                    r = re.search(ipAddrMaskRegexp, ipAddrMask)

                    if r and r.group(0) == ipAddrMask:
                        self.ipsetRuleDict["ispNetwork"].add_child(ipAddrMask)

            # 初始化 iptables
            logging.info("Initializing iptables chains ...")
            chainDict = {}
            chainConfList = self.iptablesConf["chains"]
            for chainConf in chainConfList:
                logging.info("Initializing iptables chain `%s` ..." %
                             chainConf["name"])
                chain = self.Chain(chainConf["name"], chainConf["table"])
                chain.action("add")
                chain.action("flush")

                for ruleConf in chainConf["rules"]:
                    for item in ("table", "chain", "protocol", "module", "moduleParams", "action", "actionParams"):
                        if item not in ruleConf.keys():
                            ruleConf[item] = None

                    chain.add_rule(
                        protocol=ruleConf["protocol"],
                        module=ruleConf["module"],
                        moduleParams=ruleConf["moduleParams"],
                        action=ruleConf["action"],
                        actionParams=ruleConf["actionParams"]
                    )

                chainDict[chainConf["name"]] = chain

            # 直连网关自身流量
            logging.info("Redirecting gateway traffic to the main chain ...")
            outputChain = self.Chain("OUTPUT", "nat")
            outputChain.insert_rule(
                "CHALLENGER"
            )

            # 重定向流量
            logging.info("Redirecting remaining traffic to the main chain ...")
            chainDict["CHALLENGER"].add_rule(
                self.iptablesConf["natStrategy"][self.natStrategy])

            preroutingChain = self.Chain("PREROUTING", "nat")
            preroutingChain.insert_rule(
                "CHALLENGER"
            )

        def stop(self):
            logging.info("Flushing NAT rules ...")

            # 清空流量重定向规则
            logging.info("Clearing remaining traffic redirection rules ...")
            preroutingChain = self.Chain("PREROUTING", "nat")
            preroutingChain.delete_rule(
                "CHALLENGER"
            )

            # 清空网关自身流量重定向规则
            logging.info("Clearing gateway traffic redirection rules ...")
            outputChain = self.Chain("OUTPUT", "nat")
            outputChain.delete_rule(
                "CHALLENGER"
            )

            # 清空 iptables
            logging.info("Clearing iptables ...")
            chainConfList = self.iptablesConf["chains"]
            for chainConf in chainConfList:
                chain = self.Chain(chainConf["name"], chainConf["table"])
                chain.action("flush")
                chain.action("delete")

            # 清空 ipset
            logging.info("Clearing ipset ...")
            for ipsetConf in self.ipsetConfList:
                ipsetRule = self.Ipset(ipsetConf["name"], ipsetConf["type"])
                ipsetRule.flush()
                ipsetRule.destroy()

        def restart(self):
            logging.info("Regenerating NAT rules ...")

            self.stop()
            self.start()

        class Ipset(object):
            def __init__(self, name, setType):
                self.name = name
                self.setType = setType

            def add_child(self, ipAddrMask):
                cmd = [
                    "ipset",
                    "add",
                    self.name,
                    ipAddrMask
                ]

                rc = subprocess.call(format_command(cmd))
                logging.debug("Running command `%s`" % print_list(cmd))
                if rc == 0:
                    logging.debug("Adding ipset rule %s to %s successfully." %
                                  (ipAddrMask, self.name))
                else:
                    logging.error("Adding ipset rule %s to %s failed(%s)." %
                                  (ipAddrMask, self.name, rc))

            def create(self):
                cmd = [
                    "ipset",
                    "-!",
                    "create",
                    self.name,
                    self.setType
                ]

                rc = subprocess.call(format_command(cmd))
                logging.debug("Running command `%s`" % print_list(cmd))
                if rc == 0:
                    logging.debug("Creating ipset rule %s(%s) successfully." %
                                  (self.name, self.setType))
                else:
                    logging.error("Creating ipset rule %s(%s) failed(%s)." %
                                  (self.name, self.setType, rc))

            def flush(self):
                cmd = [
                    "ipset",
                    "flush",
                    self.name
                ]

                rc = subprocess.call(format_command(cmd))
                logging.debug("Running command `%s`" % print_list(cmd))
                if rc == 0:
                    logging.debug("Flushing ipset rule %s successfully." %
                                  (self.name))
                else:
                    logging.error("Flushing ipset rule %s failed(%s)." %
                                  (self.name, rc))

            def destroy(self):
                cmd = [
                    "ipset",
                    "destroy",
                    self.name
                ]

                rc = subprocess.call(format_command(cmd))
                logging.debug("Running command `%s`" % print_list(cmd))
                if rc == 0:
                    logging.debug("Destroy ipset rule %s successfully." %
                                  (self.name))
                else:
                    logging.error("Destroy ipset rule %s failed(%s)." %
                                  (self.name, rc))

        class Chain(object):
            def __init__(self, name, table):
                self.name = name
                self.table = table

            def add_rule(self, action, protocol="tcp", module=None, moduleParams=None, actionParams=None):
                rule = self.Rule(self.table, self.name, protocol,
                                 module, moduleParams, action, actionParams)

                rule.action("add")

            def delete_rule(self, action, protocol="tcp", module=None, moduleParams=None, actionParams=None):
                rule = self.Rule(self.table, self.name, protocol,
                                 module, moduleParams, action, actionParams)

                rule.action("delete")

            def insert_rule(self, action, protocol="tcp", module=None, moduleParams=None, actionParams=None):
                rule = self.Rule(self.table, self.name, protocol,
                                 module, moduleParams, action, actionParams)

                rule.action("insert")

            def action(self, actionName):
                legalActions = {
                    "add": "-N",
                    "delete": "-X",
                    "flush": "-F"
                }
                if actionName not in legalActions.keys():
                    logging.error("Unknown iptables rule action: %s." %
                                  (actionName))
                    exit()

                cmd = [
                    "iptables",
                    "-t",
                    self.table,
                    legalActions[actionName],
                    self.name
                ]

                rc = subprocess.call(format_command(cmd))
                logging.debug("Running command `%s`" % print_list(cmd))
                if rc == 0:
                    logging.info("Action %s iptables chain %s excuted successfully." %
                                 (actionName, self.name))
                else:
                    logging.error("Action %s iptables chain %s excuted failed(%s)." %
                                  (actionName, self.name, rc))

            class Rule(object):
                def __init__(self, table, chain, protocol, module, moduleParams, action, actionParams):
                    self.table = table
                    self.chain = chain
                    self.cmdBase = []
                    if protocol:
                        self.cmdBase += ["-p", protocol]
                    if module:
                        self.cmdBase += ["-m", module]
                    if moduleParams and type(moduleParams) == type({}):
                        for k, v in moduleParams.items():
                            self.cmdBase += [k]
                            self.cmdBase += v
                    self.cmdBase += ["-j", action]
                    if actionParams and type(actionParams) == type({}):
                        for k, v in actionParams.items():
                            self.cmdBase += [k, v]

                def action(self, actionName):
                    legalActions = {
                        "add": "-A",
                        "delete": "-D",
                        "insert": "-I"
                    }
                    if actionName not in legalActions.keys():
                        logging.error("Unknown iptables rule action: %s." %
                                      (actionName))
                        exit()

                    if actionName == "insert":
                        cmd = [
                            "iptables",
                            "-t",
                            self.table,
                            "-I",
                            self.chain,
                            1
                        ]
                    else:
                        cmd = [
                            "iptables",
                            "-t",
                            self.table,
                            legalActions[actionName],
                            self.chain
                        ]

                    cmd += self.cmdBase

                    rc = subprocess.call(format_command(cmd))
                    logging.debug("Running command `%s`" %
                                  print_list(cmd))
                    if rc == 0:
                        logging.info("Action %s rule `%s` to chain %s excuted successfully." %
                                     (actionName, print_list(self.cmdBase), self.chain))
                    else:
                        logging.error("Action %s rule `%s` to chain %s excuted failed(%s)." %
                                      (actionName, print_list(self.cmdBase), self.chain, rc))

    class SoftEtherServer(object):
        def __init__(self, challengerConfDict, softEtherConfDict):
            self.binaryPath = softEtherConfDict["binaryPath"]

        def start(self):
            logging.info("Starting SoftEther Server ...")
            cmd = [
                self.binaryPath,
                "start"
            ]

            logging.debug("Running %s ..." % print_list(cmd))
            child = subprocess.Popen(cmd, stdout=None, stderr=None)

        def stop(self):
            logging.info("Stopping SoftEther Server ...")
            cmd = [
                self.binaryPath,
                "stop"
            ]

            logging.debug("Running %s ..." % print_list(cmd))
            child = subprocess.Popen(cmd, stdout=None, stderr=None)

        def restart(self):
            logging.info("Restarting SoftEther Server ...")
            self.stop()
            self.start()


def main():
    helpMsg = '''
Usage:
    python %s [OPTIONS]

Options:
    --start                 | --stop                | --restart
    --start-v2ray-client    | --stop-v2ray-client   | --restart-v2ray-client
    --start-dns             | --stop-dns            | --restart-dns
    --start-nat             | --stop-nat            | --restart-nat
    --start-softether       | --stop-softether      | --restart-softether

    ''' % sys.argv[0]

    oAction = None

    try:
        opts, _ = getopt.getopt(
            sys.argv[1:],
            "h",
            [
                "help",
                "start",
                "stop",
                "restart",
                "start-v2ray-client",
                "stop-v2ray-client",
                "restart-v2ray-client",
                "start-dns",
                "stop-dns",
                "restart-dns",
                "start-nat",
                "stop-nat",
                "restart-nat",
                "start-softether",
                "stop-softether",
                "restart-softether"
            ]
        )
    except getopt.GetoptError:
        print(helpMsg)
        exit(1)

    for opt, arg in opts:
        if opt == "--start":
            oAction = "startAllService"
        elif opt == "--stop":
            oAction = "stopAllService"
        elif opt == "--restart":
            oAction = "restartAllService"
        elif opt == "--start-v2ray-client":
            oAction = "startV2rayClient"
        elif opt == "--stop-v2ray-client":
            oAction = "stopV2rayClient"
        elif opt == "--restart-v2ray-client":
            oAction = "restartV2rayClient"
        elif opt == "--start-dns":
            oAction = "startDNSService"
        elif opt == "--stop-dns":
            oAction = "stopDNSService"
        elif opt == "--restart-dns":
            oAction = "restartDNSService"
        elif opt == "--start-nat":
            oAction = "startNATService"
        elif opt == "--stop-nat":
            oAction = "stopNATService"
        elif opt == "--restart-nat":
            oAction = "restartNATService"
        elif opt == "--start-softether":
            oAction = "startSoftEther"
        elif opt == "--stop-softether":
            oAction = "stopSoftEther"
        elif opt == "--restart-softether":
            oAction = "restartSoftEther"
        else:
            print(helpMsg)
            exit(1)

    if not oAction:
        print(helpMsg)
        exit(1)

    challenger = Challenger(CHALLENGER_CONFIG_PATH, V2RAY_CLIENT_CONFIG_PATH,
                            DNS_SERVICE_CONFIG_PATH, NAT_SERVICE_CONFIG_PATH,
                            SOFTETHER_SERVER_CONFIG_PATH)

    if oAction == "startAllService":
        challenger.start()
    elif oAction == "stopAllService":
        challenger.stop()
    elif oAction == "restartAllService":
        challenger.restart()
    elif oAction == "startV2rayClient":
        challenger.V2RayClient.start()
    elif oAction == "stopV2rayClient":
        challenger.V2RayClient.stop()
    elif oAction == "restartV2rayClient":
        challenger.V2RayClient.restart()
    elif oAction == "startDNSService":
        challenger.DNSService.start()
    elif oAction == "stopDNSService":
        challenger.DNSService.stop()
    elif oAction == "restartDNSService":
        challenger.DNSService.restart()
    elif oAction == "startNATService":
        challenger.NATService.start()
    elif oAction == "stopNATService":
        challenger.NATService.stop()
    elif oAction == "restartNATService":
        challenger.NATService.restart()
    elif oAction == "startSoftEther":
        challenger.SoftEtherServer.start()
    elif oAction == "stopSoftEther":
        challenger.SoftEtherServer.stop()
    elif oAction == "restartSoftEther":
        challenger.SoftEtherServer.restart()


if __name__ == "__main__":
    main()
