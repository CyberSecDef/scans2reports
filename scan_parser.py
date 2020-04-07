import os
import sys
import re
import time
import uuid
import pprint
import logging
import numpy as np
import pandas as pd
import xlrd

from scar_pickles import SCARPickles

from lxml import etree
from scan_file import ScanFile
from scan_requirement import ScanRequirement
from utils import Utils
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets

#TODO Make faster
class ScanParser:
    
    def __init__(self, main_app):
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        self.main_app = main_app
        
        self.scar_conf = SCARPickles.loader( os.path.join(application_path, "data", "scar_configs.pkl") )
        self.scar_data = SCARPickles.loader( os.path.join(application_path, "data", "scar_data.pkl") )

        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{self.scar_conf.get('application_path')}/scans2reports.log", level=logging.INFO, format=FORMAT)
    
    def parseXlsx(self, filename):

        df = pd.read_excel(filename, None);

        if 'POAM' in df.keys():
            poam_rows = pd.read_excel(filename, 'POAM', header=0, index_col=None, na_values=['NA'], mangle_dupe_cols=True)
            
            poam_results = {}
            poam_results['type'] = 'Mitigations'
            poam_results['mitigations'] = []
            
            for poam in poam_rows.index:
            
                source = poam_rows['Security Checks'][poam]
                
                plugin_id = re.search('^([0-9]{3,6})$', source.strip())
                plugin_id = plugin_id.group(1).strip() if plugin_id is not None else ''
            
                rule_id = re.search('(SV-[0-9.]+r[0-9]+_rule)', source.strip())
                rule_id = rule_id.group(1).strip() if rule_id is not None else ''
            
                vuln_id = re.search('([^S]V-[0-9]+)', source.strip())
                vuln_id = vuln_id.group(1).strip() if vuln_id is not None else ''
            
                control = poam_rows['Security Control Number (NC/NA controls only)'][poam]
                
                mitigation = poam_rows['Mitigations'][poam]
                
                poam_results['mitigations'].append({
                    'plugin_id': plugin_id,
                    'rule_id': rule_id,
                    'vuln_id': vuln_id,
                    'control': control,
                    'mitigation': mitigation
                })
            
            return poam_results
            
        if 'Test Result Import' in df.keys():
            tr_rows = pd.read_excel(filename, 'Test Result Import', header=5, index_col=None, na_values=['NA'], mangle_dupe_cols=True)
            
            test_results_data = {}
            test_results_data['type'] = 'Test Results'
            for tr in tr_rows.index:
                test_results_data[ str( tr_rows['CCI'][tr]).strip().replace('CCI-','').zfill(6) ] = {
                    'control'           : tr_rows['Control Acronym'][tr],
                    'implementation'    : tr_rows['Control Implementation Status'][tr],
                    'ap'                : tr_rows['AP Acronym'][tr],
                    'cci'               : tr_rows['CCI'][tr],
                    'inherited'        : tr_rows['Inherited'][tr],
                    
                    'compliance_status' : tr_rows['Compliance Status.1'][tr],
                    'date_tested'       : tr_rows['Date Tested.1'][tr],
                    'tested_by'         : tr_rows['Tested By.1'][tr],
                    'test_results'      : tr_rows['Test Results.1'][tr]
                }
                
            return test_results_data
    
    def parseNessus(self, filename):
        logging.info('Parsing ACAS File %s', filename)
        sf = None
        try:
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            content = ''.join(content)
            tree = etree.fromstring( str(content ) )

            version = re.search(
                'Nessus version : ([0-9.]+)',
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/ReportItem[@pluginID='19506']/plugin_output/text()")), ''))
            )
            version =  version.group(1) if version is not None else ''

            feed = re.search(
                'Plugin feed version : ([0-9.]+)',
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/ReportItem[@pluginID='19506']/plugin_output/text()")), ''))
            )
            feed =  feed.group(1) if feed is not None else ''
            
            sf = ScanFile({
                'type'         :'ACAS',
                'filename'     : str(filename),
                'scan_date'     : str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), '')),
                'title'        : "Assured Compliance Assessment Solution (ACAS) Nessus Scanner\nVersion: {}\nFeed: {}".format(version, feed),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'policy'       : str(next(iter(tree.xpath("/NessusClientData_v2/Policy/policyName/text()")), '')) + str(next(iter(tree.xpath("/NessusClientData_v2/Policy/PolicyName/text()")), '')),
                'hostname'     : '',
                'os'           : '',
                'ip'           : '',
                'hosts'        : [],
                'feed'         : feed,
            })
            
            for host in tree.xpath("/NessusClientData_v2/Report/ReportHost"):
                scan_user = ""
                port_range = ""
                duration = ""
                scan_info = str( host.xpath("./ReportItem[@pluginID=19506]/plugin_output/text()") ).split("\\n")
                for line in scan_info:
                    if 'Credentialed checks' in line:
                        k,v = line.split(':', 1)
                        try:
                            if str(v).strip() == 'no':
                                scan_user = 'NONE'
                            elif len( v.split(' as ') ) > 0:
                                scan_user = str(v.split(' as ')[1]).strip().replace('\\\\','\\')
                            else:
                                scan_user = str(v)
                        except:
                            scan_user = 'UNKNOWN'
                            
                    if 'Port range' in line:
                        k,v = line.split(':', 1)
                        port_range = str(v).strip()
                        
                    if 'Scan Duration' in line:
                        k,v = line.split(':', 1)
                        duration = str(v).strip()
                
                wmi_info = str( host.xpath("./ReportItem[@pluginID=24270]/plugin_output/text()") ).split("\\n")
                device_type = ""
                manufacturer = ""
                model = ""
                serial = ""
                for line in wmi_info:
                    if ':' in line:
                        k,v = line.split(':', 1)
                        try:
                            if str(k).strip() == 'Computer Manufacturer':
                                manufacturer = str(v).strip()
                            elif str(k).strip() == 'Computer Model':
                                model = str(v).strip()
                            elif str(k).strip() == 'Computer SerialNumber':
                                serial = str(v).strip()
                            elif str(k).strip() == 'Computer Type':
                                device_type = str(v).strip()
                        except:
                            device_type = ""
                            manufacturer = ""
                            model = ""
                            serial = ""
                
                fqdn_val = ""
                if next(iter(host.xpath("./HostProperties/tag[@name='host-fqdn']/text()")),''):
                    fqdn_val = str( next(iter(host.xpath("./HostProperties/tag[@name='host-fqdn']/text()")),'') ).lower()
                elif next(iter(host.xpath("./HostProperties/tag[@name='hostname']/text()")),''):
                    fqdn_val =  str(next(iter(host.xpath("./HostProperties/tag[@name='hostname']/text()")),'')).lower()
                elif next(iter(host.xpath("./HostProperties/tag[@name='host-ip']/text()")),''):
                    fqdn_val = str(next(iter(host.xpath("./HostProperties/tag[@name='host-ip']/text()")),'')).lower()
                else:
                    fqdn_val = 'UNKNOWN'
                
                host_data = {
                    'hostname'      : fqdn_val,
                    'ip'            : next(iter(host.xpath("./HostProperties/tag[@name='host-ip']/text()")),''),
                    'mac'           : next(iter(host.xpath("./HostProperties/tag[@name='mac-address']/text()")),''),
                    'os'            : next(iter(host.xpath("./HostProperties/tag[@name='operating-system']/text()")),''),
                    
                    'device_type'   : device_type,
                    'manufacturer'  : manufacturer,
                    'model'         : model,
                    'serial'        : serial,
                    
                    'host_date'     : str(next(iter(host.xpath("./HostProperties/tag[@name='HOST_START']/text()")), '')),
                    'credentialed'  : Utils.parse_bool(str(next(iter( host.xpath("./HostProperties/tag[@name='Credentialed_Scan']/text()"))))),
                    'scan_user'     : scan_user,
                    'port_range'    : port_range,
                    'duration'      : duration,
                    'requirements'  : []
                }

                for req in host.xpath("./ReportItem"):
                    if self.main_app.main_window:
                        QtGui.QGuiApplication.processEvents()
                    
                    severity = int(next(iter(req.xpath("./@severity")),''))
                    plugin_id = int(next(iter(req.xpath("./@pluginID")),''))
                    
                    if not self.scar_conf.get('skip_info') or ( severity != 0 or plugin_id in self.scar_data.get('data_mapping')['acas_required_info'] ):
                        req = {
                            'cci'              : '',
                            'comments'         : next(iter(req.xpath("./plugin_output/text()")),''),
                            'description'      : next(iter(req.xpath("./synopsis/text()")),'') + "\n\n" + next(iter(req.xpath("./description/text()")),''),
                            'finding_details'   : '',
                            'fix_id'            : '',
                            'mitigation'       : '',
                            'port'             : int(next(iter(req.xpath("./@port")),'')),
                            'protocol'         : next(iter(req.xpath("./@protocol")),''),
                            'service'          : next(iter(req.xpath("./@svc_name")),''),
                            'grp_id'            : next(iter(req.xpath("./@pluginFamily")),''),
                            'iava'             : next(iter(req.xpath("./iava/text()")),''),
                            'plugin_id'         : plugin_id,
                            'resources'        : '',
                            'rule_id'           : '',
                            'solution'         : next(iter(req.xpath("./solution/text()")),''),
                            'references'       : '',
                            'severity'         : severity,
                            'req_title'         : next(iter(req.xpath("./@pluginName")),''),
                            'vuln_id'           : '',
                            'ia_controls'       : [],
                            'status'           : 'O',
                            'publication_date'  : next(iter(req.xpath("./plugin_publication_date/text()")),''),
                            'modification_date' : next(iter(req.xpath("./plugin_modification_date/text()")),''),
                        }

                        host_data['requirements'].append(req)
                sf['hosts'].append( host_data )

        except Exception as e:
            sf = None
            logging.error('Error parsing scap file %s', filename)
            logging.error(str(e))
            print(filename)
            print(str(e))

        return sf
        
    def parseScap(self, filename):
        logging.info('Parsing scap file %s', filename)
        sf = None
        try:
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            content = content[2:]
            content = ''.join(content)
            content = ''.join([i if ord(i) < 128 else ' ' for i in content])

            tree = etree.fromstring( str(content ) )
            ns = tree.nsmap

            version = re.search(
                '([0-9]+)\.[0-9]+',
                str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])
            )
            version =  version.group(1) if version is not None else str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])

            if version.isdigit():
                version = str(int(version))
                
            release = re.search(
                '[0-9]+\.([0-9]+)',
                str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])
            )
            release =  release.group(1) if release is not None else str(next(iter(tree.xpath("/cdf:Benchmark/cdf:plain-text/text()", namespaces = ns)), '').split(',')[0])
            if ':' in release:
                release = re.search('Release: [0-9]+\.([0-9]+) Benchmark', release)
                release = release.group(1) if release is not None else '0'

            if release.isdigit():
                release = str(int(release))

            fqdn_val = ""
            if next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:fqdn']/text()", namespaces = ns)), ''):
                fqdn_val = str( next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:fqdn']/text()", namespaces = ns)), '') ).lower()
            elif next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target/text()", namespaces = ns)), ''):
                fqdn_val =  str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target/text()", namespaces = ns)), '')).lower()
            elif next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), ''):
                fqdn_val = str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), '')).lower()
            else:
                fqdn_val = 'UNKNOWN'
            
            sf = ScanFile({
                'type'         :'SCAP',
                'filename'     : str(filename),
                'scan_date'     : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@start-time", namespaces = ns )), ''),
                'duration'     :
                    datetime.strptime(
                        str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@end-time", namespaces = ns )), '')),
                        '%Y-%m-%dT%H:%M:%S'
                    ) -
                    datetime.strptime(
                        str(next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@start-time", namespaces = ns )), '')),
                        '%Y-%m-%dT%H:%M:%S'
                    )
                ,
                'policy'       : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:profile/@idref", namespaces = ns)), ''),
                'scanner_edition' : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@test-system", namespaces = ns)), ''),
                'title'        : next(iter(tree.xpath("/cdf:Benchmark/cdf:title/text()", namespaces = ns)), ''),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'release'      : release,
                'stigid'       : next(iter(tree.xpath("/cdf:Benchmark/@id", namespaces = ns)), '').split(',')[0],
                'description'  : next(iter(tree.xpath("/cdf:Benchmark/cdf:description/text()", namespaces = ns)), '').split(',')[0],
                'hostname'     : fqdn_val,
                'ip'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), ''),
                'mac'          : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:mac']/text()", namespaces = ns)), ''),
                'device_type'  : '',
                'manufacturer' : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:manufacturer']/text()", namespaces = ns)), ''),
                'model'        : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:model']/text()", namespaces = ns)), ''),
                'serial'       : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:ein']/text()", namespaces = ns)), ''),  
                'os'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:os_version']/text()", namespaces = ns)), ''),
                'credentialed' : Utils.parse_bool(str( next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/@privileged", namespaces = ns)), '') )),
                'scan_user'     : next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/text()", namespaces = ns)), ''),

            })

            for vuln in tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result", namespaces = ns):
                if self.main_app.main_window:
                    QtGui.QGuiApplication.processEvents()
                
                idref = next(iter(vuln.xpath("./@idref", namespaces = ns)), '')

                if str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')).strip() != '':
                    try:
                        descriptionTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        description = str(next(iter(descriptionTree.xpath('/root/VulnDiscussion/text()')), ''))

                        mitigationTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        mitigations = str(next(iter(mitigationTree.xpath('/root/Mitigations/text()')), ''))

                        impactTree = etree.fromstring( '<root>' + str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), '')) + '</root>' )
                        impact = str(next(iter(impactTree.xpath('/root/PotentialImpacts/text()')), ''))

                        resources = []
                        for resource in descriptionTree.xpath('/root/Responsibility/text()'):
                            resources.append(str(resource))
                        resources = ",".join(resources)

                    except:
                        description = ""
                        resources = ""
                        mitigations = ""
                        impact = ""
                else:
                    description = re.search(
                        '<VulnDiscussion>(.*)<\/VulnDiscussion>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    description =  description.group(1) if description is not None else ''

                    resources = re.search(
                        '<Responsibility>(.*)<\/Responsibility>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    resources =  resources.group(1) if resources is not None else ''

                    impact = re.search(
                        '<PotentialImpacts>(.*)<\/PotentialImpacts>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    impact =  impact.group(1) if impact is not None else ''

                    mitigations = re.search(
                        '<Mitigations>(.*)<\/Mitigations>',
                        str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:description/text()", namespaces = ns)), ''))
                    )
                    mitigations =  mitigations.group(1) if mitigations is not None else ''


                rmf = ""
                ap = ""
                cci = str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:ident[contains(./text(),'CCI')]/text()", namespaces = ns)), ''))
                if cci != '' and self.scar_data.get('data_mapping') is not None:
                    for rmf_cci in self.scar_data.get('data_mapping')['rmf_cci']:
                        if rmf_cci['cci'] == cci:
                            rmf = rmf_cci['control']
                    
                    if cci in self.scar_data.get('data_mapping')['ap_mapping']:
                        ap = self.scar_data.get('data_mapping')['ap_mapping'][cci]
                        
                rule_id = next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_rule_','')
                status = Utils.status(
                    str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), '')) ,
                    'ABBREV'
                )
                            
                sf.add_requirement(
                    ScanRequirement({
                        'vuln_id'        : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_group_',''),
                        'rule_id'        : rule_id,
                        'grp_id'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:title/text()", namespaces = ns)), '') ,
                        'plugin_id'      : '',
                        'rule_ver'       : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:version/text()", namespaces = ns)), '') ,
                        'cci'           : cci,
                        'check_id'       : '',
                        'check_text'     : '',
                        'fix_id'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fix/@id", namespaces = ns)), '') ,
                        'solution'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fixtext/text()", namespaces = ns)), '') ,
                        'mitigation'    : mitigations,
                        'impact'        : impact,
                        'req_title'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:title/text()", namespaces = ns)), '') ,
                        'severity'      : Utils.risk_val(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@severity", namespaces = ns)), '')) ,
                            'NUM'
                        ),
                        'status'        : status,
                        'finding_details': "SCAP scan found this requirement result was '{}'".format(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), ''))
                        ),
                        'comments'      : '',
                        'description'   : description,
                        'ia_controls'    : '',
                        'rmf_controls'   : rmf,
                        'assessments'   : ap,
                        'references'    : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:reference/dc:publisher/text()", namespaces = ns)), '') ,
                        'resources'     : resources,
                    })
                )

        except Exception as e:
            sf = None
            logging.error('Error parsing scap file %s', filename)
            logging.error(str(e))
            print(filename)
            print(str(e))
        return sf

    def parseCkl(self, filename):
        logging.info('Parsing CKL file %s', filename)
        sf = None
        try:
            with open(filename, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            start = 0
            if '?' in content[start]:
                start += 1
            if '!' in content[start]:
                start += 1
            
            content = content[start:]
            content = ''.join(content)
            content = ''.join([i if ord(i) < 128 else ' ' for i in content])

            tree = etree.fromstring( str(content ) )


            version = str(next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='version']/SID_DATA/text()")), ''))
            if '.' in version:
                version = version.split('.')[0]
                
            if version.isdigit():
                version = str(int(version))

            release = re.search('Release: ([0-9\*.]+) Benchmark', str( next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='releaseinfo']/SID_DATA/text()")), '')  ))
            release = release.group(1) if release is not None else '0'
            if '.' in release:
                release = release.split('.')[1]
            
            if release.isdigit():
                release = str(int(release))
                
            fqdn_val = ""
            if next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_FQDN/text()")), ''):
                fqdn_val = str( next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_FQDN/text()")), '') ).lower()
            elif next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_NAME/text()")), ''):
                fqdn_val =  str(next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_NAME/text()")), '')).lower()
            elif next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), ''):
                fqdn_val = str(next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), '')).lower()
            else:
                fqdn_val = 'UNKNOWN'
                
                    
            sf = ScanFile({
                'type'         :'CKL',

                'filename'     : str(filename),
                'scan_date'    : time.strftime( '%Y-%m-%dT%H:%M:%S', time.gmtime( os.path.getmtime( filename ))),
                'duration'     : 0,

                'scanner_edition' : '',
                'title'        : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='title']/SID_DATA/text()")), ''),
                'uuid'         : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='uuid']/SID_DATA/text()")), ''),
                'version'      : version,
                'release'      : release,
                'stigid'       : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='stigid']/SID_DATA/text()")), ''),
                'description'  : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='description']/SID_DATA/text()")), ''),

                'hostname'     : fqdn_val,
                'ip'           : next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), ''),
                'mac'          : next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_MAC/text()")), ''),
                'os'           : '',
                'device_type'  : '',
                'manufacturer' : '',
                'model'        : '',
                'serial'       : '',
                
                'credentialed' : True
            })

            for vuln in tree.xpath("//VULN"):
                if self.main_app.main_window:
                    QtGui.QGuiApplication.processEvents()
                
                rmf = ""
                ap = ""
                cci = str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='CCI_REF']/ATTRIBUTE_DATA/text()")), ''))
                if cci != '' and self.scar_data.get('data_mapping') is not None:
                    for rmf_cci in self.scar_data.get('data_mapping')['rmf_cci']:
                        if rmf_cci['cci'] == cci:
                            rmf = rmf_cci['control']
                    
                    if cci in self.scar_data.get('data_mapping')['ap_mapping']:
                        ap = self.scar_data.get('data_mapping')['ap_mapping'][cci]
                
                rule_id = next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA/text()")), '')
                status = Utils.status( next(iter(vuln.xpath("./STATUS/text()")), ''), 'ABBREV')
                
                sf.add_requirement(
                    ScanRequirement({
                        'vuln_id'        : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), ''),
                        'rule_id'        : rule_id,
                        'grp_id'         : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Group_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'plugin_id'      : '',
                        'rule_ver'       : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Ver']/ATTRIBUTE_DATA/text()")), ''),
                        'cci'           : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='CCI_REF']/ATTRIBUTE_DATA/text()")), ''),
                        'check_id'       : '',
                        'fix_id'         : '',

                        'req_title'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'severity'      : Utils.risk_val(
                            str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Severity']/ATTRIBUTE_DATA/text()")), '')),
                            'NUM'
                        ),
                        'status'        : status,
                        'finding_details': next(iter(vuln.xpath("./FINDING_DETAILS/text()")), ''),
                        'comments'      : next(iter(vuln.xpath("./COMMENTS/text()")), ''),
                        'mitigation'    : '',

                        'description'   : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Discuss']/ATTRIBUTE_DATA/text()")), ''),
                        'ia_controls'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='IA_Controls']/ATTRIBUTE_DATA/text()")), ''),
                        'rmf_controls'   : rmf,
                        'assessments'   : ap,
                        'check_text'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Check_Content']/ATTRIBUTE_DATA/text()")), ''),
                        'solution'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Fix_Text']/ATTRIBUTE_DATA/text()")), ''),
                        'references'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='STIGRef']/ATTRIBUTE_DATA/text()")), ''),
                        'resources'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Responsibility']/ATTRIBUTE_DATA/text()")), ''),
                    })
                )

        except Exception as e:
            sf = None
            logging.error('Error parsing scap file %s', filename)
            logging.error(str(e))
            print(filename)
            print(repr(e))
        
        return sf
