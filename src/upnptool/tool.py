#! /usr/bin/env python3
from sys import argv
from scapy.all import *
import threading
import time
import re
import requests
from xml.etree import ElementTree as ET

DEBUG           =   -1
SUCCESS         =   0
ERROR           =   1

FAKE_MAC        =   "ab:cd:ef:ab:cd:ef"
SPOOFED_IP_SRC  =   "192.168.0.10"
SSDP_SERVER     =   "239.255.255.250"

GLOBAL_DEVICES = {}



"""

"""
class action(object):

    def __init__(self, service = None, serviceTable = None, XML = ""):

        self.service            = service           # Service owning action
        self.tag                = service.tag.replace("device", "service")       
        self.serviceStateTable  = serviceTable      # Service Table for variables
        self.xml                = XML               # XML Content
        self.name               = ""                # Action name
        self.arguments          = {}                # List for holding arguments                    

        self.build()


    def print_self(self):

        log("Action created: {} belonging to service: {}".format(self, self.service))
        y = vars(self)
        for x in y:
            print("%-25s" % str(x) + ' : ' + str(y[x]))
        print("\n")

        return


    def build(self):

        self.parse_action()
        self.print_self()

        return

    def parse_action(self):

        if self.xml == "":
            return
  
        self.name = self.xml[0].text
        arguments = self.xml[1]      

        for arg in arguments:
            argname     =   arg.find(f'{self.tag}name').text
            stateVar     =   arg.find(f'{self.tag}relatedStateVariable').text
            direction  =   arg.find(f'{self.tag}direction').text

            self.arguments[argname] = [argname, stateVar, direction]



"""

"""
class service(object): 

    def __init__(self, device = None, XML = ""):

        self.device             = device        # Device owning service
        self.xml                = XML           # XML Content for the service
        self.tag                = device.tag    # Tag for XML extraction
        self.serviceType        = None          # Service type                  
        self.serviceId          = None          # Service ID
        self.SCPDURL            = None          # URL for SCPD
        self.SCPDXML            = None          # XML SCPD Data
        self.controlURL         = None          # Control URL
        self.eventSubURL        = None          # Event subscription URL
        self.baseURL            = self.device.location[: - (len(self.device.uuid) + 4)]
        self.actions            = {}            # List for holding actions

        self.build()


    def print_self(self):

        log("Service created: {} belonging to: {}".format(self, self.device.uuid))
        y = vars(self)
        for x in y:
            print("%-25s" % str(x) + ' : ' + str(y[x]))
        print("\n")

        return


    def build(self):

        self.parse_service()
        self.retrieve_scpd()
        self.create_actions()
        self.print_self()

        return


    def retrieve_scpd(self):
        
        if self.SCPDURL is None:
            return

        try:
            
            r = requests.get(self.baseURL + self.SCPDURL)  # SCPD Data at BASE + SCPD extension
            self.SCPDXML = r
            log("Retrieved {} bytes of SCPD data for service: {}".format(len(self.SCPDXML.text), self))

        except Exception as e:
            log("Failed to retrieve SCPD data for service: {}\nERROR:{}".format(self))
  
        return 


    def parse_service(self):

        try:
            self.SCPDURL = self.xml.find(f'{self.tag}SCPDURL').text
        except Exception as e:
            pass

        try:
            self.controlURL = self.xml.find(f'{self.tag}controlURL').text
        except Exception as e:
            pass

        try:
            self.eventSubURL = self.xml.find(f'{self.tag}eventSubURL').text
        except Exception as e:
            pass

        try:
            self.serviceId = self.xml.find(f'{self.tag}serviceId').text
        except Exception as e:
            pass

        try:
            self.serviceType = self.xml.find(f'{self.tag}serviceType').text
        except Exception as e:
            pass

        return

    
    def create_actions(self):

        tree = ET.fromstring(self.SCPDXML.text)
        actionlist = tree[1]

        for x in actionlist:
            index = x[0].text
            self.actions[index] = action(self, tree[2], x) 

        return
  


"""

"""
class device(object):

    def __init__(self, uuid="None", ip="None", port = 0):

        self.port               = port          # Port of service
        self.uuid               = uuid          # Unique identifier
        self.ip                 = ip            # IP of service

        self.modelName          = ""
        self.modelNumber        = ""
        self.location           = None          # Location of XML File
        self.baseurl            = None          # Pass SOAP requests to URLBASE
        self.xml                = None          # XML File
        self.tag                = None          # TAG for extraction the service types.

        self.services           = {}            # List of services

        self.build()
        


    def print_self(self):

        log("Device created: {} UUID: {}".format(self, self.uuid))
        y = vars(self)
        for x in y:
            print("%-25s" % str(x) + ' : ' + str(y[x]))
        print("\n")

        return


    def build(self):

        self.location = "http://{}:{}/{}.xml".format(self.ip, self.port, self.uuid)
        self.retrieve_xml()
        self.parse_xml()
        self.print_self()

        return


    def retrieve_xml(self):

        if self.location == "":
            return

        try:
            r = requests.get(self.location)
            self.xml = r.text
            log("Retrieved {} bytes of XML for device: {}".format(len(self.xml), self.uuid))
        except Exception as e:
            log("Failed to retrieve XML data for device: {}\nERROR:{}".format(self.uuid, e))

        return


    def create_services(self, index, XML):
        
        self.services[index] = service(self, XML)

        return


    def parse_xml(self):

        if self.xml == None:
            return

        try:
            
            tree = ET.fromstring(self.xml)[1]
            self.xml = tree
            self.tag = re.search(r'{(.*)}', tree.tag)[0]

            try:
                self.modelName = tree.find(f'{self.tag}modelName').text
            except Exception as e:
                self.modelName = "Unknown"
                pass

            try:
                self.modelNumber = tree.find(f'{self.tag}modelNumber').text
            except Exception as e:
                self.modelNumber = "Unknown"
                pass

            x =  tree.find(f'{self.tag}serviceList')
            for y in x:
                index = y.find(f'{self.tag}serviceType').text.split(":")[3]
                self.create_services(index, y)

        except Exception as e:
            log("Failed to parse XML data for device: {}\nERROR: {}".format(self.uuid, e))

        return


    
"""
Thread object for sniffing and handling packets
"""
class threadObject(threading.Thread):

    def __init__(self, args):

        threading.Thread.__init__(self)
        self.id = os.getpid()
        self.args = args
        self.data = ""
        self.stop = False
        log("Created Thread: {} ID: {}".format(self, self.id), DEBUG)


    def stopfilter(self, arg):

        if self.stop is True:
            return True
        else:
            return False

    def run(self):

        self.stop = False
        log("Started sniffing!", DEBUG)
        sniff(iface=self.args.interface, store=False, stop_filter=self.stopfilter, prn=self.filter_pkt)
        log("Stopped sniffing!", DEBUG)

        return


    def filter_pkt(self, pkt):

        if pkt.haslayer(UDP) and pkt[UDP].dport == 1900:
            self.handle_ssdp_httpnotify(pkt)

        return
    

    def handle_ssdp_httpnotify(self, pkt):

        raw = pkt[Raw].load.decode("UTF-8")

        if "NOTIFY" in raw:

            split = raw.replace("\r", "")
    
            if "Location" in split or "LOCATION" in split:

                m = re.search(r'Location:(.*).xml', split)
                if m is None:
                    return

                m = m[0][17:]
                if ":80" in m:
                    return

                data = m.split("/")
                ip_data = data[0].split(":")
                ip = ip_data[0]
                port = ip_data[1]
                uuid = data[1][:-4]

                if uuid not in GLOBAL_DEVICES.keys():

                    GLOBAL_DEVICES[uuid] = device(uuid, ip, port)

            return 


    def _stopsniff(self):

        log("Stopping sniffing!", DEBUG)
        self.stop = True

        return



"""
Output formatter / log function
"""
def log(message, level=DEBUG):

    if level == DEBUG:
        print("[*]: {}".format(message))

    elif level == SUCCESS:
        print("[+]: {}".format(message))

    else:
        print("[-]: {}".format(message))



"""
Sniffer API
"""
class SnifferAPI(object):

    def __init__(self, interface):

        log("Created: {}".format(self), DEBUG)
        self.interface = interface
        self.t = None


    def sniff(self):

        self.t =  threadObject(self)
        self.t.start()


    def stop(self):

        self.t._stopsniff()
        self.t.join()

"""

"""
def display():

    for d in GLOBAL_DEVICES:

        d = GLOBAL_DEVICES[d]

        print("[*] Device: {} at: {}:{}".format(d.modelName, d.ip, d.port))
        
        for service in d.services.keys():

            print("\t-> {}".format(service))

            for action in d.services[service].actions.keys():

                print("\t\t{}".format(action))

                for arg in d.services[service].actions[action].arguments.keys():

                    print("\t\t\t{}".format(arg))


"""
Classes for identifying and interacting with UPnP Devices.
"""
class UPnP(object):

    def __init__(self, interface="enp0s3"):

        log("Created: {} iface: {}".format(self, interface), DEBUG)
        self.interface = interface
        self.sniffer = SnifferAPI(self.interface)


    def ssdp(self):

        log("Probing SSDP Devices!", DEBUG)
        payload = "M-SEARCH * HTTP/1.1\r\n" \
        "HOST:"+SSDP_SERVER+":1900\r\n" \
        "ST:upnp:rootdevice\r\n" \
        "MAN: \"ssdp:discover\"\r\n" \
        "MX:2\r\n\r\n"

        ssdp = Ether(dst='ff:ff:ff:ff:ff:ff') / IP(src=SPOOFED_IP_SRC, dst=SSDP_SERVER) / UDP(sport=1900, dport=1900) / payload
        sendp(ssdp, count=1, iface=self.interface)



    def turnun(self):

        log("Sending SOAP call to device!")

        UUID        = list(GLOBAL_DEVICES.keys())[0]
        IP          = GLOBAL_DEVICES[UUID].ip
        PORT        = GLOBAL_DEVICES[UUID].port
    
        # Trigger action by:
        # SERVICETYPE#ACTION
        SERVICE         = GLOBAL_DEVICES[UUID].services["SwitchPower"]                      #  urn:schemas-upnp-org:service:SwitchPower:1
        ACTION          = SERVICE.actions["SetTarget"]                                      #  SetTarget
        SOAPACTION      = SERVICE.serviceType+"#"+ACTION.name                               #  urn:schemas-upnp-org:service:SwitchPower:1#SetTarget

        ARGUMENT        = ACTION.arguments["newTargetValue"][0]                                            #  <name>newTargetValue</name>

        CTRL_URL        = SERVICE.baseURL +SERVICE.controlURL[1:]

        headers = {
            "SOAPACTION" : SOAPACTION,
            "CONTENT-TYPE" : 'text/xml; charset="utf-8"'
        }

        body = f"""<?xml version="1.0" encoding="utf-8"?>
                <s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"      xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                <u:{ACTION.name} xmlns:u="{SERVICE.serviceType}">
                    <{ARGUMENT}>1
                </{ARGUMENT}>
                </u:{ACTION.name}>
                </s:Body>"""
        
        try:
            r = requests.post(CTRL_URL, data=body, headers=headers)
            log("Success!")
        except Exception as e:
            log("Failed to send SOAP request!")
            pass

        return  


    def send_soap(self, device, service, action, argument, value):
        
        log("Sending SOAP call to device!")

        DEVICE      = GLOBAL_DEVICES[device]
        IP          = DEVICE.ip
        PORT        = DEVICE.port

        # Trigger action by:
        # SERVICETYPE#ACTION
        SERVICE         = DEVICE.services[service]                     #  urn:schemas-upnp-org:service:SwitchPower:1
        ACTION          = SERVICE.actions[action]                                      #  SetTarget
        SOAPACTION      = SERVICE.serviceType+"#"+ACTION.name                               #  urn:schemas-upnp-org:service:SwitchPower:1#SetTarget

        ARGUMENT        = ACTION.arguments[argument][0]                                            #  <name>newTargetValue</name>

        CTRL_URL        = SERVICE.baseURL +SERVICE.controlURL[1:]

        headers = {
            "SOAPACTION" : SOAPACTION,
            "CONTENT-TYPE" : 'text/xml; charset="utf-8"'
        }

        body = f"""<?xml version="1.0" encoding="utf-8"?>
                <s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"      xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                <u:{ACTION.name} xmlns:u="{SERVICE.serviceType}">
                    <{ARGUMENT}>{value}
                </{ARGUMENT}>
                </u:{ACTION.name}>
                </s:Body>"""
        
        try:
            r = requests.post(CTRL_URL, data=body, headers=headers)
            log("Success!")
        except Exception as e:
            log("Failed to send SOAP request!")
            pass

        return  


    def soap(self):


        log("Attemtping to send SOAP call to device!")

        '''
        UUID        = list(GLOBAL_DEVICES.keys())[0]
        IP          = GLOBAL_DEVICES[UUID].ip
        PORT        = GLOBAL_DEVICES[UUID].port
        CTRL_URL    = GLOBAL_DEVICES[UUID].services[0].baseURL + GLOBAL_DEVICES[UUID].services[0].controlURL[1:]
    
        # Trigger action by:
        # SERVICETYPE#ACTION
        SERVICETYPE     = GLOBAL_DEVICES[UUID].services[0].serviceType                      #  urn:schemas-upnp-org:service:SwitchPower:1
        ACTION          = GLOBAL_DEVICES[UUID].services[0].actions[0].name                  #  SetTarget
        SOAPACTION      = SERVICETYPE+"#"+ACTION                                            #  urn:schemas-upnp-org:service:SwitchPower:1#SetTarget

        ARGUMENT        = GLOBAL_DEVICES[UUID].services[0].actions[0].arguments[0][0]       #<name>newTargetValue</name>

        CTRL_URL    = GLOBAL_DEVICES[UUID].services[0].baseURL + GLOBAL_DEVICES[UUID].services[0].controlURL[1:]

        headers = {
            "SOAPACTION" : SOAPACTION,
            "CONTENT-TYPE" : 'text/xml; charset="utf-8"'
        }

        body = f"""<?xml version="1.0" encoding="utf-8"?>
                <s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"      xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                <u:{ACTION} xmlns:u="{SERVICETYPE}">
                    <{ARGUMENT}>1
                </{ARGUMENT}>
                </u:{ACTION}>
                </s:Body>"""
        
        try:
            r = requests.post(CTRL_URL, data=body, headers=headers)
        except Exception as e:
            log("Failed to send SOAP request!")
            pass

        return  

        '''
    
    

"""
Main
"""
def main(args):

    try:

        L = UPnP()
        L.sniffer.sniff()
        L.ssdp()
        time.sleep(2.5)
        L.sniffer.stop()

        display()

        input()

        UUID        = list(GLOBAL_DEVICES.keys())[0]
        L.send_soap(UUID, "SwitchPower", "SetTarget", "newTargetValue", 1)
        time.sleep(1)
        L.send_soap(UUID, "SwitchPower", "SetTarget", "newTargetValue", 0)
        time.sleep(0)

  




    except KeyboardInterrupt as e:

        L.stop()

if __name__ == "__main__":
    main(argv)

