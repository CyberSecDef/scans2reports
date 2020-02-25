""" reports module of scans to poam"""
# pylint: disable=C0301
import re
import pprint
import os.path
import string
import datetime
import logging
from functools import reduce
from dateutil import parser

import xlsxwriter

from utils import Utils

class Reports:
    """ reports class of scans to reports """
    workbook = None
    scan_results = []
    data_mapping = {}
    contact_info = {}
    poam_conf = {}
    scans_to_reports = None
    strings = {
        'STIG' : 'Security Technical Implementation Guide',
        'IGN_SOFT' : r'/driver|library|framework|patch|update|runtime|chipset|redistributable|kb[0-9]+'
    }

    def __init__(self, scan_results, data_mapping, contact_info, poam_conf, scans_to_reports=None):
        """ constructor """
        FORMAT = "[%(asctime)s | %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
        logging.basicConfig(filename='scans2reports.log', level=logging.INFO, format=FORMAT)
        logging.info('Building Reports Object')
        self.scan_results = scan_results

        report_name = "{}/results/{}".format(
            os.path.dirname(os.path.realpath(__file__)),
            datetime.datetime.now().strftime("scans2reports-%Y%m%d_%H%M%S.xlsx")
        )

        self.workbook = xlsxwriter.Workbook(report_name)
        self.data_mapping = data_mapping
        self.contact_info = contact_info
        self.poam_conf = poam_conf
        self.scans_to_reports = scans_to_reports

    def close(self):
        """ Close the excel file """
        logging.info('Closing Workbook')
        self.workbook.close()

    def rpt_issues(self):
        """ SCAP - CKL Inconsistencies tab """
        logging.info('Building SCAP-CKL Inconsistencies report')
        worksheet = self.workbook.add_worksheet('SCAP-CKL Inconsistencies')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'SCAP-CKL Inconsistencies' Tab")

        widths = [50,25,25,50,15,15,15,15,50,15,15,50,15,15,15,15,50,50,50,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)
        report = []
        #differences between scap status and ckl status
        for scap in filter(lambda x: x['type'] == 'SCAP', self.scan_results):
            for sreq in filter(lambda x: x['status'] != 'C', scap['requirements']):
                #see if there are any matching stig (CKL) requirements
                for ckl in filter(lambda x: x['type'] == 'CKL', self.scan_results):
                    for creq in filter(lambda x: x['vulnId'] == sreq['vulnId'] and x['status'] != sreq['status'], ckl['requirements']):
                        report.append({
                            'Title': scap['title'].replace(self.strings['STIG'], 'STIG'),
                            'SCAP Hosts': scap['hostname'] if scap['hostname'].strip() != '' else scap['ip'],
                            'CKL Hosts': ckl['hostname'] if ckl['hostname'].strip() != '' else ckl['ip'],
                            'Vulnerability': sreq['reqTitle'],
                            'SCAP Version': int(str(scap['version'])),
                            'SCAP Release': int(str(scap['release'])),
                            'CKL Version': int(str(ckl['version'])),
                            'CKL Release': int(str(ckl['release'])),

                            'SCAP grpId': sreq['grpId'],
                            'SCAP vulnId': sreq['vulnId'],
                            'SCAP ruleId': sreq['ruleId'],

                            'CKL grpId': creq['grpId'],
                            'CKL vulnId': creq['vulnId'],
                            'CKL ruleId': creq['ruleId'],

                            'SCAP Status': Utils.status(sreq['status'], 'HUMAN'),
                            'CKL Status': Utils.status(creq['status'], 'HUMAN'),
                            'SCAP Finding Details': sreq['findingDetails'],
                            'SCAP File': os.path.basename(scap['fileName']),
                            'CKL File': os.path.basename(ckl['fileName']),
                            'Comments': creq['comments']
                        })

        #executed in scap, not in ckl
        for scap in filter(lambda x: x['type'] == 'SCAP', self.scan_results):
            for sreq in filter(lambda x: x['status'] != 'C', scap['requirements']):
                ckl_count = 0
                for ckl in filter(lambda x: x['type'] == 'CKL', self.scan_results):
                    for creq in filter(lambda x: x['vulnId'] == sreq['vulnId'] and x['status'] != sreq['status'], ckl['requirements']):
                        ckl_count += 1
                if ckl_count == 0:
                    report.append({
                        'Title': scap['title'].replace(self.strings['STIG'], 'STIG'),
                        'SCAP Hosts': scap['hostname'] if scap['hostname'].strip() != '' else scap['ip'],
                        'CKL Hosts': '',
                        'Vulnerability': sreq['reqTitle'],
                        'SCAP Version': int(str(scap['version'])),
                        'SCAP Release': int(str(scap['release'])),
                        'CKL Version': '',
                        'CKL Release': '',

                        'SCAP grpId': sreq['grpId'],
                        'SCAP vulnId': sreq['vulnId'],
                        'SCAP ruleId': sreq['ruleId'],

                        'CKL grpId': '',
                        'CKL vulnId': '',
                        'CKL ruleId': '',

                        'SCAP Status': Utils.status(sreq['status'], 'HUMAN'),
                        'CKL Status': 'Not Executed',
                        'SCAP Finding Details': sreq['findingDetails'],
                        'SCAP File': os.path.basename(scap['fileName']),
                        'CKL File': '',
                        'Comments': ''
                    })


        report = sorted(report, key=lambda s: (str(s['Title']).lower().strip(), str(s['SCAP Version']).lower().strip(), str(s['SCAP Release']).lower().strip(), str(s['SCAP ruleId']).lower().strip()))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1


    def rpt_test_plan(self):
        """ Generates Test Plan """
        logging.info('Building Test Plan Report')
        worksheet = self.workbook.add_worksheet('Test Plan')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Test Plan' Tab")

        widths = [75,10,50,50,35]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS' and len(x['hosts']) > 0, self.scan_results):
            report.append({
                'Title': scan_file['title'],
                'Version': scan_file['version'],
                'Hosts': ", ".join(
                    sorted(list(set(map(lambda h: h['hostname'] if h['hostname'].strip() != '' else h['ip'], scan_file['hosts']))))
                ),
                'Scan File Name': os.path.basename(scan_file['fileName']),
                'Dates': (parser.parse(scan_file['scanDate'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        for scan_file in filter(lambda x: x['type'] == 'SCAP', self.scan_results):
            report.append({
                'Title': f"SCAP - {scan_file['title']}",
                'Version': f"V{int(str(scan_file['version']))}R{int(str(scan_file['release']))}",
                'Hosts': scan_file['hostname'] if scan_file['hostname'].strip() != '' else scan_file['ip'],
                'Scan File Name': os.path.basename(scan_file['fileName']),
                'Dates': (parser.parse(scan_file['scanDate'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        for scan_file in filter(lambda x: x['type'] == 'CKL', self.scan_results):
            report.append({
                'Title': f"CKL - {scan_file['title']}",
                'Version': f"V{int(str(scan_file['version']))}R{int(str(scan_file['release']))}",
                'Hosts': scan_file['hostname'] if scan_file['hostname'].strip() != '' else scan_file['ip'],
                'Scan File Name': os.path.basename(scan_file['fileName']),
                'Dates': (parser.parse(scan_file['scanDate'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        report = sorted(report, key=lambda s: (str(s['Title']).lower().strip(), str(s['Version']).lower().strip(), str(s['Hosts']).lower().strip()))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1


    def rpt_poam56(self):
        """ Generates POAM """
        logging.info('Building POAM')
        worksheet = self.workbook.add_worksheet('POAM')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'POAM' Tab")
        
        widths = [1,40,15,25,25,15,30,15,30,45,20,30,25,40,40,40,25,25,40,25,25,40,25,40,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []
        for status in ['Ongoing', 'Not Applicable', 'Not Reviewed', 'Error', 'Completed']:
            print(f"    {status}")
            #get unique list of all acas plugins that match each statusacas_plugins
            acas_plugins = []
            for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                for host in scan_file['hosts']:
                    for req in host['requirements']:
                        if Utils.status(req['status'], 'HUMAN') == Utils.status(status, 'HUMAN'):
                            if(
                                datetime.datetime.strptime(req['publicationDate'],'%Y/%m/%d')  <
                                datetime.datetime.today() - datetime.timedelta(days=self.poam_conf['exclude_plugins'] )
                            ):
                                acas_plugins.append(req['pluginId'])
                                
            acas_plugins_by_status = sorted(list(set(acas_plugins)))

            #get all the hosts that for each plugin by status
            acas_plugin_hosts = {}
            for plugin in acas_plugins_by_status:
                acas_plugin_hosts[plugin] = []
                for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                    for host in scan_file['hosts']:
                        for req in filter(lambda x: x['pluginId'] == plugin and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), host['requirements']):
                            acas_plugin_hosts[plugin].append(host['hostname'] if host['hostname'] != '' else host['ip'])

            #loop through all plugins in this status
            for plugin in acas_plugins_by_status:
                for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                    for host in scan_file['hosts']:
                        for req in filter(lambda x: x['pluginId'] == plugin, host['requirements']):
                            if not list(filter(lambda x: str(x['Security Checks']).strip() == f"{req['pluginId']}" and str(x['Raw Severity']).strip() == Utils.risk_val(req['severity'], 'MIN'), report)):
                                # pylint: disable=C0330
                                
                                scd = ""
                                if self.poam_conf['scd']:
                                    if self.poam_conf['lower_risk']:
                                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                                    else:
                                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )
                                
                                req_data = {
                                    'A': '',
                                    'Control Vulnerability Description': f"Title: {req['reqTitle']}\n\nFamily: {req['grpId']}\n\nDescription:\n{req['description']}",
                                    'Security Control Number (NC/NA controls only)': self.data_mapping['acas_control'][req['grpId']] if req['grpId'] in self.data_mapping['acas_control'] else '',
                                    'Office/Org': f"{self.contact_info['command']}\n{self.contact_info['name']}\n{self.contact_info['phone']}\n{self.contact_info['email']}\n".strip(),
                                    'Security Checks': f"{req['pluginId']}",
                                    'Resources Required': f"{req['resources']}",
                                    'Scheduled Completion Date': scd,
                                    
                                    'Milestone with Completion Dates': "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
    s=str(scd).split('-'),
    m=(['Winter', 'Spring', 'Summer', 'Autumn'][(int(str(scd).split('-')[1])//3)]),
) if self.poam_conf['scd'] else '',
                                    'Milestone Changes': '',
                                    'Source Identifying Control Vulnerability': f"{scan_file['title']}",
                                    'Status': f"{ Utils.status(req['status'], 'HUMAN') }",
                                    'Comments':  f"{', '.join(req['cci'])}\n\n{req['comments']}",
                                    'Raw Severity': Utils.risk_val(req['severity'], 'MIN'),
                                    'Devices Affected': ", ".join(sorted(list(set(acas_plugin_hosts[req['pluginId']])))),
                                    'Mitigations': '',
                                    'Predisposing Conditions': '',
                                    'Severity': Utils.risk_val(req['severity'], 'POAM'),
                                    'Relevance of Threat': 'High',
                                    'Threat Description': req['description'],
                                    'Likelihood': Utils.risk_val(req['severity'], 'POAM'),
                                    'Impact': Utils.risk_val(req['severity'], 'POAM'),
                                    'Impact Description': '',
                                    'Residual Risk Level': Utils.risk_val(req['severity'], 'POAM'),
                                    'Recommendations': req['solution'],
                                    'Resulting Residual Risk after Proposed Mitigations': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.poam_conf['lower_risk'] else Utils.risk_val(req['severity'], 'POAM'),
                                }
                                report.append(req_data)
                                # pylint: enable=C0330

            #get all parsed disa vulns
            disa_rules = []
            scap_req = []
            ckl_req = []
            for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                for req in filter(lambda x: Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                    disa_rules.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))
                    if scan_file['type'] == 'SCAP':
                        scap_req.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))
                    if scan_file['type'] == 'CKL':
                        ckl_req.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))

            disa_plugins_by_status = sorted(list(set(disa_rules)))

            #get all the hosts that are impacted by each vuln by status
            disa_rule_hosts = {}
            for rule in disa_plugins_by_status:
                disa_rule_hosts[rule] = []
                for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                    for req in filter(lambda x: x['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') == rule and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                        host = scan_file['hostname'] if scan_file['hostname'] != '' else scan_file['ip']
                        if host.strip() != '':
                            disa_rule_hosts[rule].append(host)

            #loop through all gathered vulns
            for rule in disa_plugins_by_status:
                for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                    for req in filter(lambda x: x['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') == rule and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                        #determine if this is ckl, scap or ckl/scap
                        prefix = []
                        if req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') in scap_req:
                            prefix.append('SCAP')
                        if req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') in ckl_req:
                            prefix.append('CKL')

                        prefix = sorted(prefix)
                        prefix = "/".join(prefix)
                        if not list(filter(lambda x: str(x['Security Checks']).strip() == f"{req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')}", report)):
                            scd = ""
                            if self.poam_conf['scd']:
                                if self.poam_conf['lower_risk']:
                                    scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                                else:
                                    scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )
                                        
                            req_data = {
                                'A': '',
                                'Control Vulnerability Description': f"Title: {req['reqTitle']}\nFamily: {req['grpId']}\nDescription:\n{req['description']}",
                                'Security Control Number (NC/NA controls only)': self.data_mapping['ap_mapping'][req['cci']] if req['cci'] in self.data_mapping['ap_mapping'] else req['rmfControls'],
                                'Office/Org': f"{self.contact_info['command']}\n{self.contact_info['name']}\n{self.contact_info['phone']}\n{self.contact_info['email']}\n".strip(),
                                'Security Checks': f"{req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')}",
                                'Resources Required': f"{req['resources']}",
                                'Scheduled Completion Date': scd,
                                'Milestone with Completion Dates': "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
    s=str(scd).split('-'),
    m=(['Winter', 'Spring', 'Summer', 'Autumn'][(int(str(scd).split('-')[1])//3)]),
) if self.poam_conf['scd'] else '',
                                'Milestone Changes': '',
                                'Source Identifying Control Vulnerability': f"{prefix} - {scan_file['title']}",
                                'Status': f"{Utils.status(req['status'], 'HUMAN')}",
                                'Comments':  f"{req['cci']}\n\n{req['comments']}".strip(),
                                'Raw Severity': Utils.risk_val(req['severity'], 'MIN'),
                                'Devices Affected': ", ".join(sorted(list(set(disa_rule_hosts[req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')])))),
                                'Mitigations': '',
                                'Predisposing Conditions': req['findingDetails'],
                                'Severity': Utils.risk_val(req['severity'], 'POAM'),
                                'Relevance of Threat': 'High',
                                'Threat Description': req['description'],
                                'Likelihood': Utils.risk_val(req['severity'], 'POAM'),
                                'Impact': Utils.risk_val(req['severity'], 'POAM'),
                                'Impact Description': '',
                                'Residual Risk Level': Utils.risk_val(req['severity'], 'POAM'),
                                'Recommendations': req['solution'],
                                'Resulting Residual Risk after Proposed Mitigations': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.poam_conf['lower_risk'] else Utils.risk_val(req['severity'], 'POAM'),
                            }
                            report.append(req_data)

        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'justify', 'valign':'bottom'})

        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 8})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, result[value], date_fmt)
                    else:
                        worksheet.write(row, col, result[value], cell_format)
                    col += 1
                row += 1

    def rpt_rar(self):
        """ Generates RAR """
        logging.info('Building RAR')
        worksheet = self.workbook.add_worksheet('RAR')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'RAR' Tab")
            
        widths = [15,15,45,30,30,45,20,15,30,30,15,15,30,30,15,15,15,15,30,30,45,30]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []
        for status in ['Ongoing', 'Not Applicable', 'Not Reviewed', 'Error', 'Completed']:
            print(f"    {status}")
            #get unique list of all acas plugins that match each statusacas_plugins
            acas_plugins = []
            for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                for host in scan_file['hosts']:
                    for req in host['requirements']:
                        if Utils.status(req['status'], 'HUMAN') == Utils.status(status, 'HUMAN'):
                            if(
                                datetime.datetime.strptime(req['publicationDate'],'%Y/%m/%d')  <
                                datetime.datetime.today() - datetime.timedelta(days=self.poam_conf['exclude_plugins'] )
                            ):
                                acas_plugins.append(req['pluginId'])
            acas_plugins_by_status = sorted(list(set(acas_plugins)))

            #get all the hosts that for each plugin by status
            acas_plugin_hosts = {}
            for plugin in acas_plugins_by_status:
                acas_plugin_hosts[plugin] = []
                for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                    for host in scan_file['hosts']:
                        for req in filter(lambda x: x['pluginId'] == plugin and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), host['requirements']):
                            acas_plugin_hosts[plugin].append(host['hostname'] if host['hostname'] != '' else host['ip'])

            #loop through all plugins in this status
            for plugin in acas_plugins_by_status:
                for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
                    for host in scan_file['hosts']:
                        for req in filter(lambda x: x['pluginId'] == plugin, host['requirements']):
                            if not list(filter(lambda x: str(x['Vulnerability ID(16a.3)']).strip() == f"{req['pluginId']}", report)):
                                
                                rmfControls = self.data_mapping['acas_control'][req['grpId']] if req['grpId'] in self.data_mapping['acas_control'] else ''
                                
                                objectives = []
                                for rmf_cia in self.data_mapping['rmf_cia']:
                                    if rmfControls.strip() != '' and rmf_cia['Ctl'] == rmfControls:
                                        if rmf_cia['CL'] == 'X' or rmf_cia['CM'] == 'X' or rmf_cia['CH'] == 'X':
                                            objectives.append('C')
                                        if rmf_cia['IL'] == 'X' or rmf_cia['IM'] == 'X' or rmf_cia['IH'] == 'X':
                                            objectives.append('I')
                                        if rmf_cia['AL'] == 'X' or rmf_cia['AM'] == 'X' or rmf_cia['AH'] == 'X':
                                            objectives.append('A')
                                    
                                objectives = list(set(objectives))
                                objectives = ", ".join( objectives )
                                
                                # pylint: disable=C0330
                                req_data = {
                                    'Non-Compliant Security Controls (16a)': rmfControls,
									'Affected CCI (16a.1)': f"{ ', '.join(req['cci']) }",
									'Source of Discovery(16a.2)': f"{scan_file['title']}",
									'Vulnerability ID(16a.3)': f"{req['pluginId']}",
									'Vulnerability Description (16.b)': req['reqTitle'],
									'Devices Affected (16b.1)': ", ".join(sorted(list(set(acas_plugin_hosts[req['pluginId']])))),
									'Security Objectives (C-I-A) (16c)': objectives,
									'Raw Test Result (16d)': Utils.risk_val(req['severity'], 'CAT'),
									'Predisposing Condition(s) (16d.1)': '',
									'Technical Mitigation(s) (16d.2)': '',
									'Severity or Pervasiveness (VL-VH) (16d.3)': Utils.risk_val(req['severity'], 'VL-VH'),
									'Relevance of Threat (VL-VH) (16e)': 'High',
									'Threat Description (16e.1)': req['description'],
									'Likelihood (Cells 16d.3 & 16e) (VL-VH) (16f)': Utils.risk_val(req['severity'], 'VL-VH'),
									'Impact (VL-VH) (16g)': Utils.risk_val(req['severity'], 'VL-VH'),
									'Impact Description (16h)': '',
									'Risk (Cells 16f & 16g) (VL-VH) (16i)': Utils.risk_val(req['severity'], 'VL-VH'),
									'Proposed Mitigations (From POA&M) (16j)': '',
									'Residual Risk (After Proposed Mitigations) (16k)': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.poam_conf['lower_risk'] else Utils.risk_val(req['severity'], 'VL-VH'),
									'Recommendations (16l)': req['solution'],
									'Comments': f"CCI: {', '.join(req['cci'])}\nGroup ID: {req['grpId']}\nVuln ID:\nRule ID:\nPlugin ID: {req['pluginId']}\n\n{req['comments']}"
                                }
                                report.append(req_data)
                                # pylint: enable=C0330

            #get all parsed disa vulns
            disa_rules = []
            scap_req = []
            ckl_req = []
            for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                for req in filter(lambda x: Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                    disa_rules.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))
                    if scan_file['type'] == 'SCAP':
                        scap_req.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))
                    if scan_file['type'] == 'CKL':
                        ckl_req.append(req['ruleId'].replace('xccdf_mil.disa.stig_rule_', ''))

            disa_plugins_by_status = sorted(list(set(disa_rules)))

            #get all the hosts that are impacted by each vuln by status
            disa_rule_hosts = {}
            for rule in disa_plugins_by_status:
                disa_rule_hosts[rule] = []
                for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                    for req in filter(lambda x: x['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') == rule and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                        host = scan_file['hostname'] if scan_file['hostname'] != '' else scan_file['ip']
                        if host.strip() != '':
                            disa_rule_hosts[rule].append(host)

            #loop through all gathered vulns
            for rule in disa_plugins_by_status:
                for scan_file in filter(lambda x: x['type'] == 'CKL' or x['type'] == 'SCAP', self.scan_results):
                    for req in filter(lambda x: x['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') == rule and Utils.status(x['status'], 'HUMAN') == Utils.status(status, 'HUMAN'), scan_file['requirements']):
                    
                        objectives = []
                        for rmf_cia in self.data_mapping['rmf_cia']:
                            if req['rmfControls'].strip() != '' and rmf_cia['Ctl'] == req['rmfControls']:
                                if rmf_cia['CL'] == 'X' or rmf_cia['CM'] == 'X' or rmf_cia['CH'] == 'X':
                                    objectives.append('C')
                                if rmf_cia['IL'] == 'X' or rmf_cia['IM'] == 'X' or rmf_cia['IH'] == 'X':
                                    objectives.append('I')
                                if rmf_cia['AL'] == 'X' or rmf_cia['AM'] == 'X' or rmf_cia['AH'] == 'X':
                                    objectives.append('A')
                            
                        objectives = list(set(objectives))
                        objectives = ", ".join( objectives )
                        
                        #determine if this is ckl, scap or ckl/scap
                        prefix = []
                        if req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') in scap_req:
                            prefix.append('SCAP')
                        if req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '') in ckl_req:
                            prefix.append('CKL')

                        prefix = sorted(prefix)
                        prefix = "/".join(prefix)
                        if not list(filter(lambda x: str(x['Vulnerability ID(16a.3)']).strip() == f"{req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')}", report)):
                            req_data = {
                                'Non-Compliant Security Controls (16a)': self.data_mapping['ap_mapping'][req['cci']] if req['cci'] in self.data_mapping['ap_mapping'] else req['rmfControls'],
                                'Affected CCI (16a.1)': f"{ req['cci'] }",
                                'Source of Discovery(16a.2)': f"{prefix} - {scan_file['title']}",
                                'Vulnerability ID(16a.3)': f"{req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')}",
                                'Vulnerability Description (16.b)': req['reqTitle'],
                                'Devices Affected (16b.1)': ", ".join(sorted(list(set(disa_rule_hosts[req['ruleId'].replace('xccdf_mil.disa.stig_rule_', '')])))),
                                'Security Objectives (C-I-A) (16c)': objectives,
                                'Raw Test Result (16d)': Utils.risk_val(req['severity'], 'CAT'),
                                'Predisposing Condition(s) (16d.1)': req['findingDetails'],
                                'Technical Mitigation(s) (16d.2)': '',
                                'Severity or Pervasiveness (VL-VH) (16d.3)': Utils.risk_val(req['severity'], 'VL-VH'),
                                'Relevance of Threat (VL-VH) (16e)': 'High',
                                'Threat Description (16e.1)': req['description'],
                                'Likelihood (Cells 16d.3 & 16e) (VL-VH) (16f)': Utils.risk_val(req['severity'], 'VL-VH'),
                                'Impact (VL-VH) (16g)': Utils.risk_val(req['severity'], 'VL-VH'),
                                'Impact Description (16h)': '',
                                'Risk (Cells 16f & 16g) (VL-VH) (16i)': Utils.risk_val(req['severity'], 'VL-VH'),
                                'Proposed Mitigations (From POA&M) (16j)': '',
                                'Residual Risk (After Proposed Mitigations) (16k)': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.poam_conf['lower_risk'] else Utils.risk_val(req['severity'], 'VL-VH'),
                                'Recommendations (16l)': req['solution'],
                                'Comments': """
CCI: {cci}
Group ID: {grpId}
Vuln ID: {vulnId}
Rule ID: {ruleId}
Plugin ID: {pluginId}

{comments}""".format(
    cci=str(', '.join(req['cci'])),
    grpId=req['grpId'],
    vulnId='',
    ruleId='',
    pluginId=req['pluginId'],
    comments=req['comments']
)
                            }
                            report.append(req_data)

        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align' : 'justify', 'valign' : 'vcenter'})
        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy'})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, result[value], date_fmt)
                    else:
                        worksheet.write(row, col, result[value], cell_format)
                    col += 1
                row += 1




    def rpt_scan_info(self):
        """ Generates Scan Info Tab """
        logging.info('Building Automated Scan Info Tab')
        worksheet = self.workbook.add_worksheet('Automated Scan Info')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Automated Scan Info' Tab")
        
        widths = [20,100,25,25,25,50,75,25,25,50,25,25,25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []

        for scan_file in filter(lambda x: x['type'] == 'SCAP', self.scan_results):
            info_details = {
                'Scan File Type': 'SCAP',
                'Scan File': os.path.basename(scan_file['fileName']),
                'Plugin feed version': 'V' + str(int(str(scan_file['version']))) + 'R' + str(int(str(scan_file['release']))),
                'Scanner edition used': scan_file['scannerEdition'],
                'Scan Type': 'Normal',
                'Scan policy used': scan_file['policy'],
                'Port Range' : '',
                'Hostname' : scan_file['hostname'] if scan_file['hostname'].strip() != '' else scan_file['ip'],
                'Credentialed checks': Utils.parse_bool(str(scan_file['credentialed'])),
                'Scan User': scan_file['scanUser'],
                'Scan Start Date': scan_file['scanDate'],
                'Scan duration': str(reduce(lambda x, y: x*60+y, [int(i) for i in (str(scan_file['duration'])).split(':')])) + ' sec',
                'Scan To Feed Difference' : ''
            }
            report.append(info_details)

        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in host['requirements']:
                    if int(req['pluginId']) == 19506:
                        scan_data = {}
                        for line in req['comments'].split("\n"):
                            if line.strip() != '':
                                k, value = line.split(':', 1)
                                scan_data[str(k).strip()] = str(value).strip()

                        info_details = {
                            'Scan File Type': 'ACAS',
                            'Scan File': os.path.basename(scan_file['fileName']),
                            'Plugin feed version': scan_data['Plugin feed version'],
                            'Scanner edition used': scan_data['Nessus version'],
                            'Scan Type': scan_data['Scan type'],
                            'Scan policy used': scan_data['Scan policy used'],
                            'Port Range' : scan_data['Port range'] if 'Port range' in scan_data else '',
                            'Hostname' : host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'Credentialed checks': Utils.parse_bool(str(host['credentialed'])),
                            'Scan User': host['scanUser'],
                            'Scan Start Date': scan_data['Scan Start Date'],
                            'Scan duration': str(scan_data['Scan duration']),
                            'Scan To Feed Difference' : (
                                datetime.datetime.strptime(scan_file['scanDate'], '%a %b %d %H:%M:%S %Y') - 
                                datetime.datetime.strptime(scan_data['Plugin feed version'], '%Y%m%d%H%M')
                            ).days
                        }
                        report.append(info_details)

        report = sorted(
            report,
            key=lambda s: (str(s['Scan Type']).lower().strip(), str(s['Scan File']).lower().strip())
        )
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})
        bad_feed = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'bg_color': '#FFC7CE'})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                row_format = wrap_text
                if( 
                    'Scan To Feed Difference' in result and 
                    str(result['Scan To Feed Difference']).strip() != '' and
                    int(result['Scan To Feed Difference']) > 5
                ):
                    row_format = bad_feed
                for value in result:
                    worksheet.write(row, col, result[value], row_format)
                    col += 1
                row += 1

    def rpt_soft_linux(self):
        """ Generates Linux Software Tab """
        logging.info('Generating Linux Software Tab')
        
        worksheet = self.workbook.add_worksheet('Software - Linux')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Software - Linux' Tab")
        
        widths = [75, 25, 25, 25, 75]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        software = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in filter(lambda r: int(r['pluginId']) == 22869, host['requirements']):
                    for line in filter(lambda l: l.strip() != '', req['comments'].split("\n")):
                        if 'list of packages installed' not in line:
                            if line.count(':') < 3:
                                pkg_regex = re.search(r'(.*)-(.*)-(.*)\.(.*_.*)\|(.*)', str(line), re.DOTALL)
                                if pkg_regex is None:
                                    pkg_regex = re.search(r'(.*)-(.*)-(.*)\.(.*)\|(.*)', str(line), re.DOTALL)

                                if pkg_regex is None:
                                    pkg_regex = re.search(r'(.*)-(.*)-(.*)\|(.*)', str(line), re.DOTALL)

                                if pkg_regex is None:
                                    pkg_regex = re.search(r'(.*)-(.*)\|(.*)', str(line), re.DOTALL)

                                pkg_info = {
                                    'name': str(pkg_regex[1]).strip() if pkg_regex is not None else "UNKNOWN",
                                    'version': str(pkg_regex[2]).strip() if pkg_regex is not None else "UNKNOWN",
                                    'release': str(pkg_regex[3]).strip() if pkg_regex is not None else "UNKNOWN",
                                    'arch': str(pkg_regex[4]).strip() if pkg_regex is not None else "UNKNOWN",
                                }
                                if re.search(self.strings['IGN_SOFT'], pkg_info['name']) is None:
                                    if(not list(filter(lambda x: x['name'] == pkg_info['name'], software)) and not list(filter(lambda x: x['version'] == pkg_info['version'], software))):

                                        software.append({
                                            'name': str(pkg_info['name']).strip(),
                                            'version': str(pkg_info['version']).strip(),
                                            'release': str(pkg_info['release']).strip(),
                                            'arch': str(pkg_info['arch']).strip(),
                                            'hosts': [
                                                {
                                                    'hostname': host['hostname'] if host['hostname'].strip() != '' else '',
                                                    'ip': host['ip'] if host['ip'].strip() != '' else '',
                                                }
                                            ]
                                        })
                                    else:
                                        for soft in software:
                                            if(soft['name'] == str(pkg_info['name']).strip() and soft['version'] == str(pkg_info['version']).strip()):
                                                soft['hosts'].append({
                                                    'hostname': host['hostname'] if host['hostname'].strip() != '' else '',
                                                    'ip': host['ip'] if host['ip'].strip() != '' else '',
                                                })

        report = []
        for software in filter(lambda s: s['name'].strip() != '', software):
            hosts = []
            for host in software['hosts']:
                hosts.append(host['hostname'] if host['hostname'].strip() != '' else host['ip'])

            report.append({
                'Name': str(software['name']).strip(),
                'Version': str(software['version']).strip(),
                'Release': str(software['release']).strip(),
                'Architecture': str(software['arch']).strip(),
                'Hosts': ", ".join(sorted(list(set(hosts))))
            })

        report = sorted(report, key=lambda s: (str(s['Name']).lower().strip(), str(s['Version']).lower().strip()))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})


        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_soft_windows(self):
        """ Generates Windows Software Tab """
        logging.info('Building Windows Software Tab')
        worksheet = self.workbook.add_worksheet('Software - Windows')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Software - Windows' Tab")
            
        widths = [75, 25, 75]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        software = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in filter(lambda r: int(r['pluginId']) == 20811, host['requirements']):
                    for line in filter(lambda l: l.strip() != '', req['comments'].split("\n")):
                        if 'The following updates are installed' not in line:
                            matches = (re.search(r'(?P<name>.*)\[version', str(line), re.DOTALL))
                            name = matches['name'] if matches is not None else "UNKNOWN"

                            matches = re.search(r'\[version (?P<version>[a-z0-9.]+)\]', str(line), re.DOTALL)
                            version = matches['version'] if matches is not None else "UNKNOWN"

                            matches = re.search(r'\[installed on (?P<installed>.*)\]', str(line), re.DOTALL)
                            installed = matches['installed'] if matches is not None else "UNKNOWN"

                            if(name and re.search(self.strings['IGN_SOFT'], name) is None):
                                if(not list(filter(lambda x: x['name'] == name, software)) and not list(filter(lambda x: x['version'] == version, software))):
                                    software.append({
                                        'name': str(name).strip(),
                                        'version': str(version).strip(),
                                        'hosts':[
                                            {
                                                'installed': installed,
                                                'hostname': host['hostname'] if host['hostname'].strip() != '' else '',
                                                'ip': host['ip'] if host['ip'].strip() != '' else '',
                                            }
                                        ]
                                    })
                                else:
                                    for soft in software:
                                        if(soft['name'] == str(name).strip() and soft['version'] == str(version).strip()):
                                            soft['hosts'].append({
                                                'installed': installed,
                                                'hostname': host['hostname'] if host['hostname'].strip() != '' else '',
                                                'ip': host['ip'] if host['ip'].strip() != '' else '',
                                            })

        report = []
        for soft in filter(lambda x: x['name'] != '', software):
            hosts = []
            for host in soft['hosts']:
                hosts.append(host['hostname'] if host['hostname'].strip() != '' else host['ip'])

            report.append({
                'Name': str(soft['name']).strip(),
                'Version': str(soft['version']).strip(),
                'Hosts': ", ".join(sorted(list(set(hosts))))
            })

        report = sorted(report, key=lambda s: (s['Name'].lower().strip(), s['Version']))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_ppsm(self):
        """ Generates PPSM Report """
        logging.info('Building PPSM Tab')
        worksheet = self.workbook.add_worksheet('PPSM')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'PPSM' Tab")
        
        widths = [25, 25, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        ports = []

        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in filter(lambda r: int(r['pluginId']) == 11219 or int(r['pluginId']) == 14272, host['requirements']):
                    if not list(filter(lambda x: x['Port'] == req['port'], ports)):
                        ports.append({
                            'Port': req['port'],
                            'Protocol': req['protocol'],
                            'Service': req['service'],
                            'Purpose': '',
                            'Usage': ''
                        })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if ports:
            col = 0
            for column_header in ports[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in ports:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
                
    def rpt_cci(self):
        """ Generates CCI Report """
        logging.info('Building CCI Tab')
        worksheet = self.workbook.add_worksheet('CCI Data')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'CCI Data' Tab")
            
        widths = [25,25,25,25,25, 25,25,125,125]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        ccis = []

        for cci in self.data_mapping['rmf_cci']:
            ccis.append({
                'Control' : cci['control'],
                'Title' : cci['title'],
                'Family' : cci['subject_area'],
                'Impact' : cci['impact'],
                'Priority' : cci['priority'],
                'CCI' : cci['cci'],
                'Definition' : cci['definition'],
                'Description' : cci['description'],
            })
        
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if ccis:
            col = 0
            for column_header in ccis[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in ccis:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1
                
                
    def rpt_acas_uniq_vuln(self):
        """ Generates ACAS Unique Vuln tab """
        logging.info('Building ACAS Unique Vuln Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique Vuln')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'ACAS Unique Vuln' Tab")
        
        widths = [25, 75, 50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in host['requirements']:
                    if not list(filter(lambda x: x['pluginId'] == req['pluginId'], plugins)):
                        plugins.append(req)
                    if int(req['pluginId']) not in plugin_count:
                        plugin_count[int(req['pluginId'])] = 1
                    else:
                        plugin_count[int(req['pluginId'])] += 1

        plugins = sorted(plugins, key=lambda plugin: plugin['pluginId'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin': plugin['pluginId'],
                'Plugin Name': plugin['reqTitle'],
                'Family': plugin['grpId'],
                'Raw Severity': Utils.risk_val(plugin['severity'], 'NUM'),
                'Total': plugin_count[int(plugin['pluginId'])]
            })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if plugins_rpt:
            col = 0
            for column_header in plugins_rpt[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in plugins_rpt:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_acas_uniq_iava(self):
        """ Generates ACAS Unique IAVA Tab """
        logging.info('Building ACAS Unique IAVA Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique IAVA')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'ACAS Unique IAVA' Tab")
        
        widths = [25, 25, 50, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in filter(lambda r: str(r['iava']).strip() != '', host['requirements']):
                    if not list(filter(lambda x: x['pluginId'] == req['pluginId'], plugins)):
                        plugins.append(req)
                    if int(req['pluginId']) not in plugin_count:
                        plugin_count[int(req['pluginId'])] = 1
                    else:
                        plugin_count[int(req['pluginId'])] += 1

        plugins = sorted(plugins, key=lambda plugin: plugin['pluginId'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin': plugin['pluginId'],
                'IAVM': plugin['iava'],
                'Plugin Name': plugin['reqTitle'],
                'Family': plugin['grpId'],
                'Severity': Utils.risk_val(plugin['severity'], 'CAT'),
                'Total': plugin_count[int(plugin['pluginId'])]
            })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if plugins_rpt:
            col = 0
            for column_header in plugins_rpt[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in plugins_rpt:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_missing_patches(self):
        """ Generates Missing Patches tab """
        logging.info('Building Missing Patches tab')
        worksheet = self.workbook.add_worksheet('Missing Patches')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Missing Patches' Tab")
        
        
        widths = [35, 50, 50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        patches = []

        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for req in filter(lambda r: int(r['pluginId']) == 66334, host['requirements']):
                    for patch in re.findall(r'\+ Action to take : (.+)+', req['comments']):
                        patches.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })
                    for patch in re.findall(r'- (.+)+', req['comments']):
                        patches.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if patches:
            col = 0
            for column_header in patches[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in patches:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_summary(self):
        """ Generates Scan Summary Tab """
        logging.info('Building Summary Tab')
        worksheet = self.workbook.add_worksheet('Summary')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Summary' Tab")
        
        widths = [10,30,20,50,50,10,10,10,10,10,10,25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
        
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        summary_results = []

        for scan_file in self.scan_results:
            if scan_file['type'] == 'SCAP':
                summary_results.append({
                    'Type': 'SCAP',
                    'Hostname': scan_file['hostname'] if scan_file['hostname'].strip() != '' else '',
                    'IP': scan_file['ip'],
                    'OS': scan_file['os'],
                    'Scan File Name': os.path.basename(scan_file['fileName']),
                    'CAT I': scan_file['catI'],
                    'CAT II': scan_file['catII'],
                    'CAT III': scan_file['catIII'],
                    'CAT IV': scan_file['catIV'],
                    'Total': scan_file['total'],
                    'Score': scan_file['score'],
                    'Credentialed': scan_file['credentialed'],
                })
            elif scan_file['type'] == 'CKL':
                summary_results.append({
                    'Type': 'CKL',
                    'Hostname': scan_file['hostname'] if scan_file['hostname'].strip() != '' else '',
                    'IP': scan_file['ip'],
                    'OS': scan_file['os'],
                    'Scan File Name': os.path.basename(scan_file['fileName']),
                    'CAT I': scan_file['catI'],
                    'CAT II': scan_file['catII'],
                    'CAT III': scan_file['catIII'],
                    'CAT IV': scan_file['catIV'],
                    'Total': scan_file['total'],
                    'Score': scan_file['score'],
                    'Credentialed': scan_file['credentialed'],
                })
            elif scan_file['type'] == 'ACAS':
                for host in scan_file['hosts']:
                    summary_results.append({
                        'Type': 'ACAS',
                        'Hostname': host['hostname'] if host['hostname'].strip() != '' else '',
                        'IP': host['ip'],
                        'OS': host['os'],
                        'Scan File Name': os.path.basename(scan_file['fileName']),
                        'CAT I': host['catI'],
                        'CAT II': host['catII'],
                        'CAT III': host['catIII'],
                        'CAT IV': host['catIV'],
                        'Total': host['total'],
                        'Score': host['score'],
                        'Credentialed': host['credentialed'],
                    })

        summary_results = sorted(
            summary_results,
            key=lambda s: (str(s['Type']).lower().strip(), str(s['Hostname']).lower().strip())
        )
        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if summary_results:
            col = 0
            for k in summary_results[0]:
                worksheet.write(row, col, k, bold)
                col += 1
            row += 1

            for result in summary_results:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_raw_data(self):
        """ Generates RAW Data Tab """
        logging.info('Building Raw Data Tab')
        worksheet = self.workbook.add_worksheet('Raw Data')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Raw Data' Tab")

        worksheet.set_column('A:A', 15)
        worksheet.set_column('B:B', 40)
        worksheet.set_column('C:C', 40)
        worksheet.set_column('D:D', 30)
        worksheet.set_column('E:E', 10)
        worksheet.set_column('F:F', 10)
        worksheet.set_column('G:G', 10)
        worksheet.set_column('H:H', 10)
        
        worksheet.set_column('I:I', 15)
        worksheet.set_column('J:J', 45)
        worksheet.set_column('K:K', 30)
        worksheet.set_column('L:L', 25)
        worksheet.set_column('M:M', 25)
        worksheet.set_column('N:N', 15)
        worksheet.set_column('O:O', 20)
        worksheet.set_column('P:P', 20)
        worksheet.set_column('Q:Q', 20)
        worksheet.set_column('R:R', 20)
        worksheet.set_column('S:S', 75)
        worksheet.set_column('T:T', 15)
        worksheet.set_column('U:U', 15)
        worksheet.set_column('V:V', 75)
        worksheet.set_column('W:W', 75)
        worksheet.set_column('X:X', 75)
        worksheet.set_column('Y:Y', 25)
        worksheet.set_column('Z:Z', 20)
        worksheet.set_column('AA:AA', 25)
        worksheet.set_column('AB:AB', 75)
        worksheet.autofilter(0, 0, 0, 27)

        raw_results = []
        for scan_file in self.scan_results:
            if scan_file['type'] == 'SCAP':
                for req in scan_file['requirements']:
                    raw_results.append({
                        'Scan Type': scan_file['type'].upper(),
                        'Scan Title': scan_file['title'].replace(self.strings['STIG'], ''),
                        'Filename': os.path.basename(scan_file['fileName']),
                        'Scan Date': scan_file['scanDate'],
                        'Version': int(scan_file['version'].strip(string.ascii_letters)),
                        'Release': int(scan_file['release'].strip(string.ascii_letters)),
                        'Publication Date' : '',
                        'Modification Date' : '',
                        'Credentialed': scan_file['credentialed'],
                        'Hostname': scan_file['hostname'] if scan_file['hostname'].strip() != '' else scan_file['ip'],
                        'grpId': req['grpId'],
                        'vulnId': req['vulnId'],
                        'ruleId': req['ruleId'],
                        'pluginId': req['pluginId'],
                        'IA Controls': req['iaControls'],
                        'RMF Controls': req['rmfControls'],
                        'Assessments': req['assessments'],
                        'CCI': req['cci'],
                        'Title': req['reqTitle'],
                        'Severity': Utils.risk_val(str(req['severity']), 'CAT'),
                        'Status': Utils.status(req['status'], 'HUMAN'),
                        'Finding Details': req['findingDetails'][0:32760],
                        'Description': req['description'][0:32760],
                        'Solution': req['solution'][0:32760],
                        'fixId': req['fixId'],
                        'References': req['references'][0:32760],
                        'Resources': req['resources'],
                        'Comments': req['comments'][0:32760],
                    })
            elif scan_file['type'] == 'CKL':
                for req in scan_file['requirements']:
                    raw_results.append({
                        'Scan Type': scan_file['type'].upper(),
                        'Scan Title': scan_file['title'].replace(self.strings['STIG'], ''),
                        'Filename': os.path.basename(scan_file['fileName']),
                        'Scan Date': scan_file['scanDate'],
                        'Version': int(scan_file['version'].strip(string.ascii_letters)),
                        'Release': int(scan_file['release'].strip(string.ascii_letters)),
                        'Publication Date' : '',
                        'Modification Date' : '',
                        'Credentialed': scan_file['credentialed'],
                        'Hostname': scan_file['hostname'] if scan_file['hostname'].strip() != '' else scan_file['ip'],
                        'grpId': req['grpId'],
                        'vulnId': req['vulnId'],
                        'ruleId': req['ruleId'],
                        'pluginId': req['pluginId'],
                        'IA Controls': req['iaControls'],
                        'RMF Controls': req['rmfControls'],
                        'Assessments': req['assessments'],
                        'CCI': req['cci'],
                        'Title': req['reqTitle'],
                        'Severity': Utils.risk_val(str(req['severity']), 'CAT'),
                        'Status': Utils.status(req['status'], 'HUMAN'),
                        'Finding Details': req['findingDetails'][0:32760],
                        'Description': req['description'][0:32760],
                        'Solution': req['solution'][0:32760],
                        'fixId': req['fixId'],
                        'References': req['references'][0:32760],
                        'Resources': req['resources'],
                        'Comments': req['comments'][0:32760],
                    })
            elif scan_file['type'] == 'ACAS':
                for host in scan_file['hosts']:
                    for req in host['requirements']:
                        raw_results.append({
                            'Scan Type': scan_file['type'].upper(),
                            'Scan Title': scan_file['title'],
                            'Filename': os.path.basename(scan_file['fileName']),
                            'Scan Date': scan_file['scanDate'],
                            'Version': scan_file['version'],
                            'Release': '',
                            'Publication Date' : req['publicationDate'],
                            'Modification Date' : req['modificationDate'],
                            'Credentialed': host['credentialed'],
                            'Hostname': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'grpId': req['grpId'],
                            'vulnId': '',
                            'ruleId': '',
                            'pluginId': req['pluginId'],
                            'IA Controls': '',
                            'RMF Controls': '',
                            'Assessments': '',
                            'CCI': '',
                            'Title': req['reqTitle'],
                            'Severity': Utils.risk_val(str(req['severity']), 'CAT'),
                            'Status': Utils.status(req['status'], 'HUMAN'),
                            'Finding Details': req['findingDetails'][0:32760],
                            'Description': req['description'][0:32760],
                            'Solution': req['solution'][0:32760],
                            'fixId': req['fixId'],
                            'References': req['references'][0:32760],
                            'Resources': req['resources'],
                            'Comments': '',
                        })

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if raw_results:
            col = 0
            for column_header in raw_results[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in raw_results:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_operating_systems(self):
        """ Generates OS Tab """
        logging.info('Building OS Tab')
        worksheet = self.workbook.add_worksheet('Operating Systems')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Operating Systems' Tab")
            
        widths = [50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
      
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        os_list = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                if not any(host['os'] in x['os'] for x in os_list):
                    os_list.append({
                        'os': host['os'],
                        'count': 1,
                        'method': 'Active',
                    })
                else:
                    for operating_system in os_list:
                        if operating_system['os'] == host['os']:
                            operating_system['count'] += 1

        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})
        if os_list:
            os_list = sorted(os_list, key=lambda k: k['os'])
            row = 1
            bold = self.workbook.add_format({'bold': True})
            worksheet.write(0, 0, 'Operating System', bold)
            worksheet.write(0, 1, 'Count', bold)
            worksheet.write(0, 2, 'Detection Method', bold)
            for result in os_list:
                worksheet.write(row, 0, result['os'], wrap_text)
                worksheet.write(row, 1, result['count'], wrap_text)
                worksheet.write(row, 2, result['method'], wrap_text)
                row += 1

    def rpt_local_users(self):
        """ Generates Local Users tab """
        logging.info('Building Local Users Tab')
        worksheet = self.workbook.add_worksheet('Local Users')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Local Users' Tab")
            
        widths = [50,50,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        users = []
        for scan_file in filter(lambda x: x['type'] == 'ACAS', self.scan_results):
            for host in scan_file['hosts']:
                for requirement in filter(lambda lambda_requirement: int(lambda_requirement['pluginId']) == 10860 or int(lambda_requirement['pluginId']) == 95928, host['requirements']):
                    if int(requirement['pluginId']) == 10860:
                        for user in re.findall(r'- ([a-zA-Z0-9]+)+', requirement['comments']):
                            users.append({
                                'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                                'OS': host['os'],
                                'User': user
                            })
                    if int(requirement['pluginId']) == 95928:
                        for user in re.findall(r'User\s+:\s+([a-zA-Z0-9]+)+', requirement['comments']):
                            users.append({
                                'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                                'OS': host['os'],
                                'User': user
                            })

        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})
        users = sorted(users, key=lambda k: k['Host'])
        if users:
            row = 1
            bold = self.workbook.add_format({'bold': True})
            worksheet.write(0, 0, 'Host', bold)
            worksheet.write(0, 1, 'Operating System', bold)
            worksheet.write(0, 2, 'User', bold)
            for result in users:
                worksheet.write(row, 0, result['Host'], wrap_text)
                worksheet.write(row, 1, result['OS'], wrap_text)
                worksheet.write(row, 2, result['User'], wrap_text)
                row += 1
