import sys
import time
import os
import argparse
import re
import json
import logging
import csv
import atexit
from pyVim import connect
from pyVmomi import vim, vmodl

from logging.handlers import RotatingFileHandler
from argparse import ArgumentParser

##### logint to vSphere #####
import hashlib
from hashlib import md5
from getpass import getpass

pwd = "8d6fb6121b3c9c29f1beb3a6d2e1cf66"

def checkPassword():
    p = getpass(prompt='PIN:')
    if (hashlib.md5(p.encode()).hexdigest() == pwd):
      print("PIN Authentication Success")
    else:
      print("PIN Authentication Failed")
      exit()

checkPassword()

def connectvSphere():
 logging.debug(namespace.jobname + " Request Received to connect vSphere.")
 if namespace.password is None:
  print("Enter the vSphere Password")
  vSphere_password = getpass()
 else:
  print("Password argument passed")
  vSphere_password = namespace.password
 
 if int(namespace.ssl_verify) == 0:
  disableSSL=True
 try:
  service_instance = connect.SmartConnect(host=namespace.vSpherehost,
           user=namespace.vSphereuser,
           pwd=vSphere_password,
           port=namespace.port, disableSslCertValidation=disableSSL)
  atexit.register(connect.Disconnect, service_instance)
  content = service_instance.RetrieveContent()
  print("vSphere Authentication Success")
 except Exception as e:
  print("vSphere Authentication Failed")
  logging.critical(namespace.jobname + " Unable to connect vSphere. Exception : " + str(e))
  service_instance = False
  
 return service_instance
 
##### Read content from service Instance #####

def getContent(service_instance):
 try:
  content = service_instance.RetrieveContent()
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive content from service_instance. Exception : " + str(e))
  content = False
  
 return content
 
##### Read Data Centers from content #####
def getDatacenters(content):
 try:
  dcs = content.rootFolder.childEntity
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive Data Centers from content. Exception : " + str(e))
  dcs = False
  
 return dcs

##### Read Clusters from Data Centers #####
def getClusters(dc):
 try:
  clusters=[]
  for eachcluster in dc.hostFolder.childEntity:
   clusters.append(eachcluster)
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive Clusters from DataCenters. Exception : " + str(e))
  clusters = False

 return clusters

##### Read Hosts from Clusters Data #####
def getHosts(cluster):
 try:
  hosts=[]
  for eachhost in cluster.host:
   hosts.append(eachhost)
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive hosts from clusters. Exception : " + str(e))
  hosts = False
  
 return hosts
 
##### Read VMs from Hosts Data #####
def getVMs(host):
 try:
  vms=[]
  for eachvm in host.vm:
   vms.append(eachvm)
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive vms from hosts. Exception : " + str(e))
  vms = False
  
 return vms
 
##### Read Networks from VMs Data #####
def getNetworks(vm):
 try:
  networks={}
  for device in vm.config.hardware.device:
   if "NETWORK" not in device.deviceInfo.label.upper():
    continue
   networks[device.deviceInfo.label] = {}
   networks[device.deviceInfo.label]['object'] = ""
   # if device.deviceInfo.summary == "none":
   #  continue
   for devPortGrp in vm.network:
    if devPortGrp.name == "none":
     continue
    if hasattr(device.backing,'port'):
     if devPortGrp.key.upper() == device.backing.port.portgroupKey.upper():
      networks[device.deviceInfo.label]['object'] = devPortGrp
      break
    elif hasattr(device.backing,'opaqueNetworkId'):
     if device.backing.opaqueNetworkId == devPortGrp.summary.opaqueNetworkId:
      networks[device.deviceInfo.label]['object'] = devPortGrp
      break
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to retrive networks for VM : " + str(vm) + ", Exception : " + str(device))
  networks = False 
 return networks

##### Write to CSV #####
def write_to_csv(vSpheredata,vSphereheaders):
 try:
   with open(namespace.outputFile, 'w', encoding='utf8', newline='') as output_file:
    fc = csv.DictWriter(output_file,fieldnames=vSphereheaders.keys(),)
    fc.writeheader()
    fc.writerows(vSpheredata)
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to write data to output file, Export Failed. Exception : " + str(e))
  exit()

##### Read from CSV #####
def read_from_csv():
 try:
  if not os.path.exists(namespace.inputFile):
   logging.critical(namespace.jobname + " Input File : '" + namespace.inputFile + "', does NOT exist!!")
   exit()
  with open(namespace.inputFile) as f:
   file_data=csv.reader(f)
   headers=next(file_data)
   return [dict(zip(headers,i)) for i in file_data]
 except Exception as e:
  logging.critical(namespace.jobname + " Unable to read data from input file, Export Failed. Exception : " + str(e))
  exit()
  
##### Get VM Object #####
def get_vm_object(vSphereObjJson,vm):
 for dcname,clusters in vSphereObjJson.items():
  if not isinstance(clusters,dict):
   continue
  for clustername,hosts in clusters.items():
   if not isinstance(hosts,dict):
    continue
   for hostname,vms in hosts.items():
    if not isinstance(vms,dict):
     continue
    for eachvm,networks in vms.items():
     if eachvm.upper() == vm.upper():
      return hosts['object'],vms['object'],networks['object']
 return "","",""
 
##### Gets Host's Cluster Object using Host Name. #####
def get_hosts_cluster_object(vSphereObjJson,host):
 for dcname,clusters in vSphereObjJson.items():
  if not isinstance(clusters,dict):
   continue
  for clustername,hosts in clusters.items():
   if not isinstance(hosts,dict):
    continue
   for hostname,vms in hosts.items():
    if not isinstance(vms,dict):
     continue
    if hostname.upper() == host.upper():
     return hosts['object']
 return ""

##### Validate Data center #####
def validateDC(configuration,dc):
 if len(configuration) == 0 or 'DC' not in configuration or configuration['DC'] == "":
  return True
 if re.match('(^'+configuration['DC'].replace('(','\(').replace(')','\)').replace('.','\.').replace('*','.*').replace(':','\:').replace('-','\-').upper().strip()+'$)',dc.upper()):
  return True
 return False

##### Validate Cluster#####
def validateCLUSTER(configuration,cluster):
 if len(configuration) == 0 or 'CLUSTER' not in configuration or configuration['CLUSTER'] == "":
  return True
 if re.match('(^'+configuration['CLUSTER'].replace('(','\(').replace(')','\)').replace('.','\.').replace('*','.*').replace(':','\:').replace('-','\-').upper().strip()+'$)',cluster.upper()):
  return True
 return False

##### Validate Host#####
def validateHOST(configuration,host):
 if len(configuration) == 0 or 'HOST' not in configuration or configuration['HOST'] == "":
  return True
 if re.match('(^'+configuration['HOST'].replace('(','\(').replace(')','\)').replace('.','\.').replace('*','.*').replace(':','\:').replace('-','\-').upper().strip()+'$)',host.upper()):
  return True
 return False

##### Validate Virtual Machine #####
def validateVM(configuration,vm):
 if len(configuration) == 0 or 'VM' not in configuration or configuration['VM'] == "":
  return True
 if re.match('(^'+configuration['VM'].replace('(','\(').replace(')','\)').replace('.','\.').replace('*','.*').replace(':','\:').replace('-','\-').upper().strip()+'$)',vm.upper()):
  return True
 return False

##### Validate VM N/W #####
def validateNETWORK(configuration,network):
 if len(configuration) == 0 or 'NETWORK' not in configuration or configuration['NETWORK'] == "":
  return True
 if re.match('(^'+configuration['NETWORK'].replace('(','\(').replace(')','\)').replace('.','\.').replace('*','.*').replace(':','\:').replace('-','\-').upper().strip()+'$)',network.upper()):
  return True
 return False

###### Read configuration file ######

def readConfig():
 config = {}
 if not os.path.exists(namespace.configfile):
  logging.critical(namespace.jobname + " vSphere Configuration file : '" + namespace.unitmapfile + "', does NOT exist!!")
  return config
# read json file
 with open(namespace.configfile, 'r') as configrow:
  configdata=configrow.read()
# parse json file
  config = json.loads(configdata)
 return config
 
##### Setup Network map #####
 
def setupNetworks(vm, host, networks, nic_devices):
 # this requires vsphere 7 API
 nics = []
 for d in vm.config.hardware.device:
  if isinstance(d, vim.vm.device.VirtualEthernetCard):
   nics.append(d)
 
 if len(nics) > len(networks):
  logging.critical(namespace.jobname + " not enough Networks for " + str(len(nics)) + " on vm.")
  print("not enough networks for %d nics on vm" %len(nics))
  return None
 
 netdevs = []

 for i in range(0,len(nics)):
# for v in nics:
  v = nics[i]
  n = networks[i]
  if n is not "":
#  for n in networks:
   vif_id = vm.config.instanceUuid + ":" + str(v.key)
#  if n.name.upper() != nwname:
#   continue
   if isinstance(n, vim.OpaqueNetwork):
#   if not isinstance(v.backing, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
#    continue
#   print(n.summary.opaqueNetworkId)
#   print(v.backing.opaqueNetworkId)
#   if n.summary.opaqueNetworkId != v.backing.opaqueNetworkId:
#    continue

   # Is the source opaque net same as destination?
    opaque=False
    if isinstance(v.backing, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
     if v.backing.opaqueNetworkId == n.summary.opaqueNetworkId:
      opaque=True
      originalLs=v.backing.opaqueNetworkId
 
    v.backing = vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo()
    v.backing.opaqueNetworkId = n.summary.opaqueNetworkId
    v.backing.opaqueNetworkType = n.summary.opaqueNetworkType
    v.externalId = vif_id
 
   elif isinstance(n, vim.DistributedVirtualPortgroup):
   # create dvpg handling
    vdsPgConn = vim.dvs.PortConnection()
    vdsPgConn.portgroupKey = n.key
    vdsPgConn.switchUuid = n.config.distributedVirtualSwitch.uuid
    v.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
    v.backing.port = vdsPgConn
    v.externalId = vif_id
   
   else:
    v.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
    v.backing.network = n
    v.backing.deviceName = n.name
 
   virdev = vim.vm.device.VirtualDeviceSpec()
   virdev.device = v
   virdev.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
   netdevs.append(virdev)
 return netdevs
 
##### Import Migration VM #####

def migrate_vm(vSphereObjJson,importData):
 if namespace.type.upper() == 'RELOCATE':
  relocSpec = vim.vm.RelocateSpec()
 elif namespace.type.upper() == 'RECONFIG':
  reConfigSpec = vim.vm.ConfigSpec()
 else: 
  print("  1   ***********--Process argument is missing--***********")
  exit()
 for row in importData:
  logging.info(namespace.jobname + " Processing Record : " + str(row))
  dc = row['DC']
  if dc not in vSphereObjJson:
   logging.warning(namespace.jobname + " Data Center : " + str(dc) + ", not available.")
   continue
   
  cluster = row['Cluster']
  host = row['Host']
  vm = row['VM']
  
  if not cluster and not host:
   logging.critical(namespace.jobname + " Cluster Name or Host Name is mandatory in input file.")
   continue
  
  if not vm:
   logging.critical(namespace.jobname + " VM Name is missing in input file.")
   continue
   
  dstclusterObj = ""
  
  if not cluster:
   logging.warning(namespace.jobname + " Cluster : " + str(cluster) + ", empty in input file.")
   dstclusterObj = get_hosts_cluster_object(vSphereObjJson,host)
   if not dstclusterObj:
    logging.critical(namespace.jobname + " Host : " + str(host) + ", not found in any of cluster.")
    continue
  elif cluster not in vSphereObjJson[dc]:
   logging.warning(namespace.jobname + " Cluster : " + str(cluster) + " not present in the Data Center : " + str(dc))
   continue
  else:
   dstclusterObj = vSphereObjJson[dc][cluster]['object']

  srcclusterObj,hostObj,vmObj = get_vm_object(vSphereObjJson,vm)
  
  if not vmObj:
   logging.critical(namespace.jobname + " VM : " + str(vm) + " not present in Data Center : " + str(dc))
   continue
  
  cluster = dstclusterObj.name
#  if not dstclusterObj:
#   dstclusterObj = srcclusterObj
#   cluster = srcclusterObj.name

  if host and host not in vSphereObjJson[dc][cluster]:
   logging.warning(namespace.jobname + " Host : " + str(host) + ", not present in the Cluster : " + str(cluster))
   continue

  if namespace.type.upper() == 'RECONFIG':
   if host and vm in vSphereObjJson[dc][cluster][host]:
    logging.info(namespace.jobname + " VM : " + str(vm) + ", is in the same cluster : " + str(cluster) + ", and same Host : " + str(host))
    # continue   
   else:
    logging.critical(namespace.jobname + " Started preparations to move VM : " + str(vm) + " under the host : " + str(host))

  elif namespace.type.upper() == 'RELOCATE':
   if host and vm in vSphereObjJson[dc][cluster][host]:
    logging.info(namespace.jobname + " VM : " + str(vm) + ", is in the same cluster : " + str(cluster) + ", and same Host : " + str(host))
    continue   
   else:
    logging.critical(namespace.jobname + " Started preparations to change network : " + str(vm) + " under the host : " + str(host))

    if host:
     hostObj = vSphereObjJson[dc][cluster][host]['object']    
   
     print("Destination cluster %s found, checking for DRS recommendation..." %dstclusterObj.name)
     logging.info(namespace.jobname + " Destination cluster : " + str(dstclusterObj.name) + " found, checking for DRS recommendation...")
     if hostObj and hostObj.parent.resourcePool != dstclusterObj.resourcePool:
      logging.critical(namespace.jobname + " Destination host : " + str(hostObj.name) + " and cluster : " + str(dstclusterObj.name) + ", are not resource poll.")
      print("Destination host %s and cluster %s are not resource pool" %(hostObj.name, dstclusterObj.name))
      continue
 
     if not dstclusterObj.configuration.drsConfig.enabled and not hostObj:
      logging.critical(namespace.jobname + " Destination cluster : " + str(dstclusterObj.name) + ", is not DRS enabled. Must specify the host.")
      print("Destination cluster %s is not DRS enabled, must specify host" %dstclusterObj.name)
      continue
 
     if not hostObj and dstclusterObj.resourcePool == vmObj.resourcePool:
      logging.warning(namespace.jobname + " Must provide host when migrating within same cluster.")
      print("Must provide host when migrating within same cluster")
      continue

    else:
     if srcclusterObj.name.upper() == cluster.upper():
      logging.critical(namespace.jobname + " VM : " + str(vmObj.name) + " is already in the same cluster : " + str(cluster) + ", Must specify the host name.")
      continue

     rhost = dstclusterObj.RecommendHostsForVm(vm=vmObj, pool=dstclusterObj.resourcePool)

     if len(rhost) == 0:
      logging.critical(namespace.jobname + " VM : " + str(vmObj.name) + ", No hosts found in the cluster : " + str(dstclusterObj.name) + " to migrate.")
      print("No hosts found in cluster %s from DRS recommendation for migration" %dstclusterObj.name)
      continue
     else:
      logging.info(namespace.jobname + " DRS recommends " + str(len(rhost)) + " number of hosts.")
      print("DRS recommends %d hosts" %len(rhost))
      hostObj = rhost[0].host
      logging.info(namespace.jobname + " DRS recommended Host : " + str(hostObj.name))
      if hostObj.name.upper() == host.upper():
       logging.critical(namespace.jobname + " VM : " + str() + ", is already in the same host.")
       continue

    relocSpecObj=hostObj.parent.resourcePool
    if hostObj:
     relocSpec.host = hostObj
     if vmObj.resourcePool.name.lower() == "nsxt":
      relocSpecObj=hostObj.parent.resourcePool
#     for eachpoll in vmObj.resourcePool:
#      if eachpoll.name.lower() == "nsxt":
#       relocSpecObj = eachpoll
#       break
     relocSpec.pool = relocSpecObj
    if not host:
     relocSpec.pool = dstclusterObj.resourcePool
     #relocSpec.pool = vmObj.resourcePool
  else: 
   print("  1   ***********--Process argument is missing--***********")
   exit()
  
  existing_networks = {}
  for en in hostObj.network:
   existing_networks[en.name.upper()] = en
  networksObj = []
  existing_networks.update({'NONE':''});
  for key,value in row.items():
   if key[:7].upper() == "NETWORK" and value:
    if value.upper() not in existing_networks:
     break
    networksObj.append(existing_networks[value.upper()])

  devices = vmObj.config.hardware.device
  nic_devices = [device for device in devices if isinstance(device, vim.vm.device.VirtualEthernetCard)]
  vnic_changes = []
  netSpec=setupNetworks(vmObj, hostObj, networksObj, nic_devices)

  if namespace.type.upper() == 'RELOCATE':
   relocSpec.deviceChange = netSpec
   logging.info("Initiating migration for VM : " + str(vmObj.name))
   try:
    vmObj.RelocateVM_Task(spec=relocSpec, priority=vim.VirtualMachine.MovePriority.highPriority)
    logging.info("VM : " + str(vmObj.name) + ", Migrated Successfully.")
    print("VM : " + str(vmObj.name) + ", Migrated Successfully.")
   except Exception as e:
    print("Migration failed for the VM : " + str(vmObj.name) + ", Exception : " + str(e))
    logging.critical("Migration failed for the VM : " + str(vmObj.name) + ", Exception : " + str(e))

  elif namespace.type.upper() == 'RECONFIG':
   reConfigSpec.deviceChange = netSpec
   logging.info("Initiating network change for VM : " + str(vmObj.name))
   try:
    vmObj.ReconfigVM_Task(spec=reConfigSpec)
    logging.info("VM : " + str(vmObj.name) + ", Network reconfigured Successfully.")
    print("VM : " + str(vmObj.name) + ", Network reconfigured Successfully.")
   except Exception as e:
    print("Reconfigure failed for the VM : " + str(vmObj.name) + ", Exception : " + str(e))
    logging.critical("Reconfigure failed for the VM : " + str(vmObj.name) + ", Exception : " + str(e))

  else: 
   print("  1   ***********--Process argument is missing--***********")
   exit()

########################################################
#==========>>>    Job Starts from here    <<<==========#
########################################################

if __name__ == '__main__':

 ###### Parse and add arguments for the Job ######
 parser = argparse.ArgumentParser()
 parser.add_argument("--debug", default=os.getenv('DEBUG_COLLECTOR', 1),
      help="Debug logging for the collector. Default: 0")

      
 # Static Arguments
 parser.add_argument("--totalrecords",action='store_const',const=0,help="Should not pass any value, constant value 0")
      
 # vSphere Authentication Arguments 
 parser.add_argument("-vSpherehost", default=os.getenv('vSphere_HOST', 'mcts-vc-a.mastercom.local'),
      help="Host name/IP of the vSphere. Default: '127.0.0.1'")
 parser.add_argument("-vSphereuser", default=os.getenv('vSphere_USER', 'administrator@vsphere.local'),
                     help="User name to login vSphere. Default: 'administrator@vsphere.local'")
 parser.add_argument("-password", help="Password to login vSphere. Default: 'Mcts@1234'")
 parser.add_argument("-port", default=os.getenv('PORT', '443'),
                     help="Port to login vSphere. Default: '443'")
 parser.add_argument("-ssl_verify", default=os.getenv('SSL_VERIFY', '0'),
                     help="SSL Verify, Default: '0'")
 parser.add_argument("-action", default=os.getenv('Action', 'Export'),
                     help="Action to be Export or Import, Default : 'Export'")
                
 parser.add_argument("--loglevel", default=os.getenv("LOG_LEVEL", 'DEBUG'), 
 help="Log level. Default: 'ERROR'")
 parser.add_argument("--logfile", default=os.getenv("LOG_FILE", '/var/log/vSphere.log'),
 help="Log file location. Default: '/var/log/vSphere.log'")
 parser.add_argument("--jobname", default=os.getenv('COLLECTOR_NAME', 'vSphere_Export_Import |'), 
 help="Name of the Collector. Default: 'vSphere_Export_Import |'")
 parser.add_argument("--configfile", default=os.getenv("CONFIG_FILE", '/opt/vSpere_Automation/config/vSphere.json'),
 help="vSphere Config File. Default: '/opt/vSpere_Automation/config/vSphere.json'")
 
 parser.add_argument("-outputFile", default=os.getenv('EXPORT_FILE','/opt/vSpere_Automation/data/vms_export.csv'),
 help="Export File , Default: '/opt/vSpere_Automation/data/vms_export.csv'")
 parser.add_argument("-inputFile", default=os.getenv('IMPORT_FILE','/opt/vSpere_Automation/data/vms_import.csv'),
 help="Import File , Default: '/opt/vSpere_Automation/data/vms_import.csv'")

 parser.add_argument("--maxlogfilesize", default=os.getenv("MAX_LOG_FILE_SIZE", 104857600),
 help="Maximum Log file size in Bytes. Default: 104857600")
 parser.add_argument("--maxlogfilecount", default=os.getenv("MAX_LOG_FILE_COUNT", 5),
 help="Maximum Log file count. Default: 5")
 parser.add_argument("-type", default=os.getenv('Relocate', 'Reconfig'),
 help="type to be Relocate or Reconfig, Default : 'Relocate'")
 ###### Reading Arguments to namespace and otherArgs ######

 namespace, otherArgs = parser.parse_known_args()

 ###### Creating Logging configuration ######

 loglevels = {'CRITICAL' : logging.CRITICAL, 'ERROR' : logging.ERROR, 'WARNING' : logging.WARNING, 'INFO' : logging.INFO, 'DEBUG' : logging.DEBUG }
 loglevel = namespace.loglevel
 loglevel = loglevel.upper()
 namespace.maxlogfilesize=int(namespace.maxlogfilesize)
 logging.basicConfig(handlers=[RotatingFileHandler(namespace.logfile,"a", maxBytes=namespace.maxlogfilesize, backupCount=int(namespace.maxlogfilecount))],
                     format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                     datefmt='%Y-%m-%d %H:%M:%S %Z',
                     level=loglevels[loglevel])

 start_time = int(time.time())
 logging.critical(namespace.jobname + ' is ===== Starting ===== at ' + time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(start_time)) + ' (' + str(start_time) + ')')

###### Connect to vSphere ######

 service_instance = connectvSphere()
 if not service_instance:
  # print("vSphere Authentication Failed")
  logging.critical(namespace.jobname + " vSphere connnecion Failed, unable to continue the Job.")
  exit()
  
##### Collect content #####

 content = getContent(service_instance)
 if not content:
  logging.critical(namespace.jobname + " Failed to retrive content from service_instance Object.")
  exit()
 
 vSpheredata=[]
 vSphereheaders={}
 previousdatasetlen=0
 vSphereObjJson={}
 
 configuration = readConfig()
 
 if namespace.action.upper() == 'IMPORT':
  importData = read_from_csv()
  if len(importData) == 0:
   logging.warning(namespace.jobname + " Input file : " + str(namespace.inputFile) + " file empty.")
   exit()
 
##### Collect Data Centers #####

 dcs = getDatacenters(content)
 if not dcs or len(dcs) == 0:
  logging.critical(namespace.jobname + " Failed to retrive Data centers from Content.")
  exit()
  
 logging.info(namespace.jobname + " Number of DCs Found for the vCenter : " + str(content.about.name) + ", is " + str(len(dcs)))
  
##### Collect Clusters #####

 for dc in dcs:
  if namespace.action.upper() == 'EXPORT' and not validateDC(configuration,dc.name):
   logging.warning(namespace.jobname + " DC : " + str(dc.name) + " is not configured, ignoring this data.")
   continue
  
  vSphereObjJson[dc.name] = {}
  vSphereObjJson[dc.name]['object'] = dc
  
  clusters = getClusters(dc)
 
  if not clusters or len(clusters) == 0:
   logging.critical(namespace.jobname + " Failed to retrive clsuters for Data Center : " + str(dc.name))
   continue
  
  logging.info(namespace.jobname + " Number of Clusters Found for the DC : " + str(dc.name) + ", is " + str(len(clusters)))
   
##### Collect Hosts #####
  for cluster in clusters:
   if namespace.action.upper() == 'EXPORT' and not validateCLUSTER(configuration,cluster.name):
    logging.warning(namespace.jobname + " CLUSTER : " + str(cluster.name) + ", is not configured, ignoring this data.")
    continue
    
   vSphereObjJson[dc.name][cluster.name] = {}
   vSphereObjJson[dc.name][cluster.name]['object'] = cluster
  
   hosts = getHosts(cluster)
   if not hosts or len(hosts) == 0:
    logging.critical(namespace.jobname + " Failed to retrive hosts for Cluster : " + str(cluster.name))
    continue
    
   logging.info(namespace.jobname + " Number of Hosts Found for the Cluster : " + str(cluster.name) + ", is " + str(len(hosts)))
 
##### Collect VMs #####

   for host in hosts:
    if namespace.action.upper() == 'EXPORT' and not validateHOST(configuration,host.name):
     logging.warning(namespace.jobname + " HOST : " + str(host.name) + ", is not configured, ignoring this data.")
     continue
     
    vSphereObjJson[dc.name][cluster.name][host.name] = {}
    vSphereObjJson[dc.name][cluster.name][host.name]['object'] = host

    vms = getVMs(host)
    if not vms or len(vms) == 0:
     logging.critical(namespace.jobname + " Failed to retrive VMs for Host : " + str(host.name))
     continue
    
    logging.info(namespace.jobname + " Number of VMs Found for the Host : " + str(host.name) + ", is " + str(len(vms)))
  
##### Collect Networks #####

    for vm in vms:
     if namespace.action.upper() == 'EXPORT' and not validateVM(configuration,vm.name):
      logging.warning(namespace.jobname + " VM : " + str(vm.name) + ", is not configured, ignoring this data.")
      continue
      
     vSphereObjJson[dc.name][cluster.name][host.name][vm.name] = {}
     vSphereObjJson[dc.name][cluster.name][host.name][vm.name]['object'] = vm
     
     eachdataset = {}
     
     eachdataset['DC']=dc.name
     eachdataset['VM']=vm.name
     eachdataset['Cluster']=cluster.name
     eachdataset['Host']=host.name
     
     networks = getNetworks(vm)

     #if not networks or len(networks) == 0:
      #logging.critical(namespace.jobname + " Failed to retrive Networks for VM : " + str(vm.name))
      #continue
     if networks and len(networks) > 0:
      logging.info(namespace.jobname + " Number of Networks Found for the VM : " + str(vm.name) + ", is " + str(len(networks)))
      

      
#      nc=1
      for name,network in networks.items():
       nname=network['object'].name if network['object'] else "none"
       if namespace.action.upper() == 'EXPORT' and not validateNETWORK(configuration,nname):
        logging.warning(namespace.jobname + " NETWORK : " + str(network['object'].name) + ", is not configured, ignoring this data.")
        continue
        
       vSphereObjJson[dc.name][cluster.name][host.name][vm.name][name] = {}
       vSphereObjJson[dc.name][cluster.name][host.name][vm.name][name]['name'] = network['object'].name if network['object'] else "none"
       vSphereObjJson[dc.name][cluster.name][host.name][vm.name][name]['object'] = network['object'] if network['object'] else "none"
      
#       key="Network - " + str(nc)
       eachdataset[name]=network['object'].name if network['object'] else "none"
#       nc+=1
       
      if len(eachdataset) > previousdatasetlen:
       vSphereheaders = eachdataset
       previousdatasetlen = len(eachdataset)
       
     vSpheredata.append(eachdataset)
 if namespace.action.upper() == "EXPORT" and vSpheredata:
  write_to_csv(vSpheredata,vSphereheaders)
  
 if namespace.action.upper() == "IMPORT":
  migrate_vm(vSphereObjJson,importData)
