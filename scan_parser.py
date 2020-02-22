import os
import re
import time
import uuid
import pprint
import requests
from lxml import etree
from scan_file import ScanFile
from scan_requirement import ScanRequirement
from utils import Utils
from datetime import datetime

class ScanParser:
    json_rmf_cci = {}

    def __init__(self):
        r = requests.get('https://cyber.trackr.live/api/cci')
        if r.status_code == 200:
            self.json_rmf_cci = r.json()
        else:
            self.json_rmf_cci = None

    def parseScap(self, filename):
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

            release = re.search(
                '[0-9]+\.([0-9]+)',
                str(next(iter(tree.xpath("/cdf:Benchmark/cdf:version/text()", namespaces = ns)), '').split(',')[0])
            )
            release =  release.group(1) if release is not None else str(next(iter(tree.xpath("/cdf:Benchmark/cdf:plain-text/text()", namespaces = ns)), '').split(',')[0])
            if ':' in release:
                release = re.search('Release: [0-9]+\.([0-9]+) Benchmark', release)
                release = release.group(1) if release is not None else '0'

            sf = ScanFile({
                'type'         :'SCAP',
                'fileName'     : str(filename),
                'scanDate'     : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@start-time", namespaces = ns )), ''),
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
                'scannerEdition' : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/@test-system", namespaces = ns)), ''),
                'title'        : next(iter(tree.xpath("/cdf:Benchmark/cdf:title/text()", namespaces = ns)), ''),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'release'      : release,
                'stigid'       : next(iter(tree.xpath("/cdf:Benchmark/@id", namespaces = ns)), '').split(',')[0],
                'description'  : next(iter(tree.xpath("/cdf:Benchmark/cdf:description/text()", namespaces = ns)), '').split(',')[0],
                'hostname'     : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target/text()", namespaces = ns)), ''),
                'ip'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-address/text()", namespaces = ns)), ''),
                'mac'          : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:mac']/text()", namespaces = ns)), ''),
                'os'           : next(iter(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:target-facts/cdf:fact[@name='urn:scap:fact:asset:identifier:os_name']/text()", namespaces = ns)), ''),
                'credentialed' : bool( next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/@privileged", namespaces = ns)), '') ),
                'scanUser'     : next(iter(tree.xpath(" /cdf:Benchmark/cdf:TestResult/cdf:identity/text()", namespaces = ns)), ''),
                'catI'         : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@severity='high' and ./cdf:result != 'pass']", namespaces = ns) ),
                'catII'        : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@severity='medium' and ./cdf:result != 'pass']", namespaces = ns) ),
                'catIII'       : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@severity='low' and ./cdf:result != 'pass']", namespaces = ns) ),
                'catIV'        : 0,
                'open'         : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[./cdf:result = 'fail']", namespaces = ns) ),
                'closed'       : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[./cdf:result = 'pass']", namespaces = ns) ),
                'error'        : len(tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result[./cdf:result = 'error']", namespaces = ns) ),
                'notReviewed'  : 0,
                'notApplicable': 0,
            })
            sf['total'] = sf['catI'] + sf['catII'] + sf['catIII']
            sf['score'] = 10*sf['catI'] + 3*sf['catII'] + sf['catIII']

            for vuln in tree.xpath("/cdf:Benchmark/cdf:TestResult/cdf:rule-result", namespaces = ns):
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
                if cci != '' and self.json_rmf_cci is not None:
                    rmf_list = list(filter( lambda x: x['cci'] == cci, self.json_rmf_cci['data']))
                    rmf_list = next(iter(rmf_list), None)
                    if rmf_list is not None:
                        ap = rmf_list['assessments']
                        rmf = rmf_list['rmf']

                sf.add_requirement(
                    ScanRequirement({
                        'vulnId'        : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_group_',''),
                        'ruleId'        : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@id", namespaces = ns)), '').replace('xccdf_mil.disa.stig_rule_',''),
                        'grpId'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:title/text()", namespaces = ns)), '') ,
                        'pluginId'      : '',
                        'ruleVer'       : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:version/text()", namespaces = ns)), '') ,
                        'cci'           : cci,
                        'checkId'       : '',
                        'checkText'     : '',
                        'fixId'         : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fix/@id", namespaces = ns)), '') ,
                        'solution'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:fixtext/text()", namespaces = ns)), '') ,
                        'mitigation'    : mitigations,
                        'impact'        : impact,
                        'reqTitle'      : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:title/text()", namespaces = ns)), '') ,
                        'severity'      : Utils.risk_val(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/@severity", namespaces = ns)), '')) ,
                            'NUM'
                        ),
                        'status'        : Utils.status(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), '')) ,
                            'ABBREV'
                        ),
                        'findingDetails': "SCAP scan found this requirement result was '{}'".format(
                            str(next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:TestResult/cdf:rule-result[@idref='{idref}']/cdf:result/text()", namespaces = ns)), ''))
                        ),
                        'comments'      : '',
                        'description'   : description,
                        'iaControls'    : '',
                        'rmfControls'   : rmf,
                        'assessments'   : ap,
                        'references'    : next(iter(vuln.xpath(f"/cdf:Benchmark/cdf:Group[./cdf:Rule/@id = '{idref}']/cdf:Rule/cdf:reference/dc:publisher/text()", namespaces = ns)), '') ,
                        'resources'     : resources,
                    })
                )

        except Exception as e:
            print(filename)
            print(str(e))
            pass

        return sf

    def parseNessus(self, filename):
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
                'fileName'     : str(filename),
                'scanDate'     : str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), '')),
                'title'        : "Assured Compliance Assessment Solution (ACAS) Nessus Scanner\nVersion: {}\nFeed: {}\nPolicy:{}".format( 
                    version,
                    feed,
                    str(next(iter(tree.xpath("/NessusClientData_v2/Policy/policyName/text()")), '')) 
                ),
                'uuid'         : str(uuid.uuid4()),
                'version'      : version,
                'hostname'     : '',
                'os'           : '',
                'ip'           : '',
                'hosts'        : [],
            })


            for host in tree.xpath("/NessusClientData_v2/Report/ReportHost"):
                scanUser = ""
                scan_info = str( host.xpath("./ReportItem[@pluginID=19506]/plugin_output/text()") ).split("\\n")
                for line in scan_info:
                    if 'Credentialed checks' in line:
                        k,v = line.split(':', 1)
                        try:
                            if str(v).strip() == 'no':
                                scanUser = 'NONE'
                            elif len( v.split(' as ') ) > 0:
                                scanUser = str(v.split(' as ')[1]).strip().replace('\\\\','\\')
                            else:
                                scanUser = str(v)
                        except:
                            
                            scanUser = 'Unknown'
                host_data = {
                    'hostname'      : next(iter(host.xpath("./HostProperties/tag[@name='host-fqdn']/text()")),''),
                    'ip'            : next(iter(host.xpath("./HostProperties/tag[@name='host-ip']/text()")),''),
                    'mac'           : next(iter(host.xpath("./HostProperties/tag[@name='mac-address']/text()")),''),
                    'os'            : next(iter(host.xpath("./HostProperties/tag[@name='operating-system']/text()")),''),
                    'credentialed'  : bool(str( host.xpath("./HostProperties/tag[@name='Credentialed_Scan']/text()"))),
                    'scanUser'      : scanUser,
                    'catI'          : len(host.xpath("./ReportItem[@severity>=3]") ),
                    'catII'         : len(host.xpath("./ReportItem[@severity=2]") ),
                    'catIII'        : len(host.xpath("./ReportItem[@severity=1]") ),
                    'catIV'         : len(host.xpath("./ReportItem[@severity=0]") ),
                    'open'          : len(host.xpath("./ReportItem[@severity>0]") ),
                    'closed'        : 0,
                    'error'         : 0,
                    'notReviewed'   : 0,
                    'notApplicable' : 0,
                    'requirements'  : [],
                }

                host_data['total'] = host_data['catI'] + host_data['catII'] + host_data['catIII']
                host_data['score'] = 10*host_data['catI'] + 3*host_data['catII'] + host_data['catIII']

                for req in host.xpath("./ReportItem"):
                    req = {
                        'cci'            : [],
                        'comments'       : next(iter(req.xpath("./plugin_output/text()")),''),
                        'description'    : next(iter(req.xpath("./synopsis/text()")),'') + "\n\n" + next(iter(req.xpath("./description/text()")),''),
                        'findingDetails' : '',
                        'fixId'          : '',
                        'mitigation'     : '',
                        'port'           : int(next(iter(req.xpath("./@port")),'')),
                        'protocol'       : next(iter(req.xpath("./@protocol")),''),
                        'service'        : next(iter(req.xpath("./@svc_name")),''),
                        'grpId'          : next(iter(req.xpath("./@pluginFamily")),''),
                        'iava'           : next(iter(req.xpath("./iava/text()")),''),
                        'pluginId'       : next(iter(req.xpath("./@pluginID")),''),
                        'resources'      : '',
                        'ruleId'         : '',
                        'solution'       : next(iter(req.xpath("./solution/text()")),''),
                        'references'     : '',
                        'severity'       : int(next(iter(req.xpath("./@severity")),'')),
                        'reqTitle'       : next(iter(req.xpath("./@pluginName")),''),
                        'vulnId'         : '',
                        'iaControls'     : [],
                        'status'         : 'Ongoing'
                    }

                    host_data['requirements'].append(req)
                sf['hosts'].append( host_data )


        except Exception as e:
            print(filename)
            print(str(e))
            pass

        return sf


    def parseCkl(self, filename):
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

            release = re.search('Release: ([0-9\*.]+) Benchmark', str( next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='releaseinfo']/SID_DATA/text()")), '')  ))
            release = release.group(1) if release is not None else '0'
            if '.' in release:
                release = release.split('.')[1]

            sf = ScanFile({
                'type'         :'CKL',

                'fileName'     : str(filename),
                'scanDate'     : time.strftime( '%Y-%m-%dT%H:%M:%S', time.gmtime( os.path.getmtime( filename ))),

                'title'        : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='title']/SID_DATA/text()")), ''),
                'uuid'         : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='uuid']/SID_DATA/text()")), ''),
                'version'      : version,
                'release'      : release,
                'stigid'       : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='stigid']/SID_DATA/text()")), ''),
                'description'  : next(iter(tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='description']/SID_DATA/text()")), ''),


                'hostname'     : next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_NAME/text()")), ''),
                'ip'           : next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_IP/text()")), ''),
                'mac'          : next(iter(tree.xpath("/CHECKLIST/ASSET/HOST_MAC/text()")), ''),
                'os'           : '',
                'credentialed' : True,

                'catI'         : len(tree.xpath("//VULN[./STATUS!='NotAFinding' and ./STIG_DATA[./VULN_ATTRIBUTE='Severity' and ./ATTRIBUTE_DATA='high']]") ),
                'catII'        : len(tree.xpath("//VULN[./STATUS!='NotAFinding' and ./STIG_DATA[./VULN_ATTRIBUTE='Severity' and ./ATTRIBUTE_DATA='medium']]") ),
                'catIII'       : len(tree.xpath("//VULN[./STATUS!='NotAFinding' and ./STIG_DATA[./VULN_ATTRIBUTE='Severity' and ./ATTRIBUTE_DATA='low']]") ),
                'catIV'        : '',
                'open'         : len(tree.xpath("//VULN[./STATUS='Open']") ),
                'closed'       : len(tree.xpath("//VULN[./STATUS='NotAFinding']") ),
                'error'        : len(tree.xpath("//VULN[./STATUS='Error']") ),
                'notReviewed'  : len(tree.xpath("//VULN[./STATUS='Not_Reviewed']") ),
                'notApplicable': len(tree.xpath("//VULN[./STATUS='Not_Applicable']") ),
            })
            sf['total'] = sf['catI'] + sf['catII'] + sf['catIII']
            sf['score'] = 10*sf['catI'] + 3*sf['catII'] + sf['catIII']

            for vuln in tree.xpath("//VULN"):
                rmf = ""
                ap = ""
                cci = str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='CCI_REF']/ATTRIBUTE_DATA/text()")), ''))
                if cci != '' and self.json_rmf_cci is not None:
                    rmf_list = list(filter( lambda x: x['cci'] == cci, self.json_rmf_cci['data']))
                    rmf_list = next(iter(rmf_list), None)
                    if rmf_list is not None:
                        ap = rmf_list['assessments']
                        rmf = rmf_list['rmf']


                sf.add_requirement(
                    ScanRequirement({
                        'vulnId'        : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), ''),
                        'ruleId'        : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA/text()")), ''),
                        'grpId'         : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Group_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'pluginId'      : '',
                        'ruleVer'       : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Ver']/ATTRIBUTE_DATA/text()")), ''),
                        'ruleVer'       : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Ver']/ATTRIBUTE_DATA/text()")), ''),
                        'cci'           : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='CCI_REF']/ATTRIBUTE_DATA/text()")), ''),
                        'checkId'       : '',
                        'fixId'         : '',

                        'reqTitle'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Rule_Title']/ATTRIBUTE_DATA/text()")), ''),
                        'severity'      : Utils.risk_val(
                            str(next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Severity']/ATTRIBUTE_DATA/text()")), '')),
                            'NUM'
                        ),
                        'status'        : Utils.status( next(iter(vuln.xpath("./STATUS/text()")), ''), 'ABBREV'),
                        'findingDetails': next(iter(vuln.xpath("./FINDING_DETAILS/text()")), ''),
                        'comments'      : next(iter(vuln.xpath("./COMMENTS/text()")), ''),
                        'mitigation'    : '',

                        'description'   : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Discuss']/ATTRIBUTE_DATA/text()")), ''),
                        'iaControls'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='IA_Controls']/ATTRIBUTE_DATA/text()")), ''),
                        'rmfControls'   : rmf,
                        'assessments'   : ap,
                        'checkText'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Check_Content']/ATTRIBUTE_DATA/text()")), ''),
                        'solution'      : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Fix_Text']/ATTRIBUTE_DATA/text()")), ''),
                        'references'    : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='STIGRef']/ATTRIBUTE_DATA/text()")), ''),
                        'resources'     : next(iter(vuln.xpath("*[./VULN_ATTRIBUTE='Responsibility']/ATTRIBUTE_DATA/text()")), ''),
                    })
                )
                pass

        except Exception as e:
            print(filename)
            print(str(e))
            pass

        return sf
