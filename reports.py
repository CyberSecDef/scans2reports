""" reports module of scans to poam"""
# pylint: disable=C0301
import re
import pprint
import os.path
import string
import datetime
import logging
import jmespath
from PyQt5 import QtCore, QtGui, QtWidgets
from functools import reduce
from dateutil import parser

from threading import Thread
from queue import Queue

import xlsxwriter
import psutil
from utils import Utils

import time

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
        'IGN_SOFT' : r'/drivers|drv|driver|lib|library|framework|patch|update|runtime|chipset|redistributable|kb[0-9]+'
    }
    application_path = ""

    def __init__(self, application_path, scan_results, data_mapping, contact_info, skip_reports, poam_conf, scans_to_reports=None):
        """ constructor """
        self.application_path = application_path
        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f'{self.application_path}/scans2reports.log', level=logging.INFO, format=FORMAT)
        logging.info('Building Reports Object')
        self.scan_results = scan_results

        report_name = "{}/results/{}".format(
            os.path.dirname(os.path.realpath(__file__)),
            datetime.datetime.now().strftime("scans2reports-%Y%m%d_%H%M%S.xlsx")
        )

        self.workbook = xlsxwriter.Workbook(report_name)
        self.data_mapping = data_mapping
        self.contact_info = contact_info
        self.skip_reports = skip_reports
        self.poam_conf = poam_conf
        self.scans_to_reports = scans_to_reports

    def close_workbook(self):
        """ Close the excel file """
        logging.info('Closing Workbook')
        self.workbook.close()

    def rpt_scap_ckl_issues(self):
        """ SCAP - CKL Inconsistencies tab """
        if 'rpt_scap_ckl_issues' in self.skip_reports:
            return None
            
        logging.info('Building SCAP-CKL Inconsistencies report')
        worksheet = self.workbook.add_worksheet('SCAP-CKL Inconsistencies')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'SCAP-CKL Inconsistencies' Tab")

        widths = [40, 40, 15, 15, 15, 15, 35, 35, 25, 25, 25, 25, 20, 20, 75, 75, 75, 150]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)
        report = []

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )
        scaps = jmespath.search(
            "results[?type=='SCAP'].{ scan_title: title, version: version, release: release, filename: fileName, requirements: requirements[] | [*].{ req_title: reqTitle, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, comments: comments } }",
            { 'results' : self.scan_results}
        )
        ckls = jmespath.search(
            "results[?type=='CKL'].{ scan_title: title, version: version, release: release, filename: fileName, requirements: requirements[] | [*].{ req_title: reqTitle, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, comments: comments } }",
            { 'results' : self.scan_results}
        )
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        mismatch = []

        print("        {} - Finding Non-Executed CKL requirements".format( datetime.datetime.now() - start_time ))
        executed_ckls = list(set(jmespath.search("results[].requirements[].vulnId[]", { 'results' : ckls} )))

        for scap in scaps:
            start_time2 = datetime.datetime.now()
            for req in scap['requirements']:
                if req['vulnId'] not in executed_ckls:
                    c = {
                        'Scan Title'          : scap['scan_title'].replace(self.strings['STIG'], 'STIG'),
                        'Req Title'           : req['req_title'],
                        'SCAP Version'        : int(str(scap['version'])),
                        'SCAP Release'        : int(str(scap['release'])),
                        'CKL Version'         : '',
                        'CKL Release'         : '',
                        'SCAP GrpId'          : req['grpId'],
                        'CKL GrpId'           : '',
                        'SCAP RuleId'         : req['ruleId'],
                        'CKL RuleId'          : '',
                        'SCAP VulnId'         : req['vulnId'],
                        'CKL VulnId'          : '',
                        'SCAP Status'         : Utils.status(req['status'], 'HUMAN'),
                        'CKL Status'          : 'Not Executed',
                        'SCAP Filename'       : os.path.basename(scap['filename']),
                        'CKL Filename'        : '',
                        'CKL Finding Details' : '',
                        'CKL Comments'        : ''
                    }
                    mismatch.append(c)
        print( "        {} - Finished Non-Executed CKL search".format(datetime.datetime.now() - start_time ) )
        
        print( "        {} - Compiling CKL/SCAP status mismatches".format(datetime.datetime.now() - start_time ) )
        disa_scans = jmespath.search(
            """results[?type == 'CKL' || type == 'SCAP'].{
                type: type,
                scan_title: title,
                filename: fileName, 
                version: version, 
                release: release, 
                requirements: requirements[*].{
                    req_title: reqTitle,
                    grp_id: grpId,
                    rule_id: ruleId,
                    vuln_id: vulnId,
                    status: status,
                    comments: comments,
                    finding_details: findingDetails
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        findings = []
        for scan in disa_scans:
            for req in scan['requirements']:
                findings.append({
                    'scan_title'      : scan['scan_title'],
                    'type'            : scan['type'],
                    'filename'        : scan['filename'],
                    'version'         : scan['version'],
                    'release'         : scan['release'],
                    'req_title'       : req['req_title'],
                    'grp_id'          : req['grp_id'],
                    'rule_id'         : req['rule_id'],
                    'vuln_id'         : req['vuln_id'],
                    'status'          : req['status'],
                    'finding_details' : req['finding_details'],
                    'comments'        : req['comments']
                })
        print("        {} - Analyzing {} scan results".format(datetime.datetime.now() - start_time, len(findings) ))
        
        open_scap_findings = list(set( jmespath.search("results[?type == 'SCAP' && (status == 'O' || status == 'E' )].vuln_id" , { 'results' : findings }) ))
        closed_ckl_findings = list(set( jmespath.search("results[?type == 'CKL' && status != 'O'].vuln_id" , { 'results' : findings }) ))
        mismatched_scans = sorted( list( set(open_scap_findings) & set(closed_ckl_findings) ) )
        
        print("        {} - Found {} mismatched scan results".format(datetime.datetime.now() - start_time, len(mismatched_scans) ))
        
        index = 0
        total = len(mismatched_scans)
        for mismatched_scan in mismatched_scans:
            index += 1
            if index % 100 == 0:
                print("        {} - {} percent complete".format(datetime.datetime.now() - start_time,  round( index / total *100  ,2) ))
            
            for scap in jmespath.search("results[?type == 'SCAP' && (status == 'O' || status == 'E' ) && vuln_id == '" + mismatched_scan + "']", { 'results' : findings } ):
                for ckl in jmespath.search("results[?type == 'CKL' && status != 'O' && vuln_id == '" + mismatched_scan + "']", { 'results' : findings } ):
                    c = {
                        'Scan Title'          : scap['scan_title'].replace(self.strings['STIG'], 'STIG'),
                        'Req Title'           : scap['req_title'],
                        'SCAP Version'        : int(str(scap['version'])),
                        'SCAP Release'        : int(str(scap['release'])),
                        'CKL Version'         : int(str(ckl['version'])),
                        'CKL Release'         : int(str(ckl['release'])),
                        'SCAP GrpId'          : scap['grp_id'],
                        'CKL GrpId'           : ckl['grp_id'],
                        'SCAP RuleId'         : scap['rule_id'],
                        'CKL RuleId'          : ckl['rule_id'],
                        'SCAP VulnId'         : scap['vuln_id'],
                        'CKL VulnId'          : ckl['vuln_id'],
                        'SCAP Status'         : Utils.status(scap['status'], 'HUMAN'),
                        'CKL Status'          : Utils.status(ckl['status'], 'HUMAN'),
                        'SCAP Filename'       : os.path.basename(scap['filename']),
                        'CKL Filename'        : os.path.basename(ckl['filename']),
                        'CKL Finding Details' : ckl['finding_details'],
                        'CKL Comments'        : ckl['comments']
                    }
                    mismatch.append(c)
        
        print( "        {} - Finished mismatch search".format(datetime.datetime.now() - start_time ) )
        print( "        Generating Tab")
        report = sorted(mismatch, key=lambda s: (str(
            s['Scan Title']).lower().strip(),
            str(s['SCAP Status']).lower().strip(),
            str(s['SCAP VulnId']).lower().strip(),
            str(s['SCAP RuleId']).lower().strip(),
            str(s['Req Title']).lower().strip(),
        ))
        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'justify', 'valign':'top'})

        if report:
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], cell_format)
                    col += 1
                row += 1

    def rpt_test_plan(self):
        """ Generates Test Plan """
        if 'rpt_test_plan' in self.skip_reports:
            return None
            
        logging.info('Building Test Plan Report')
        worksheet = self.workbook.add_worksheet('Test Plan')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Test Plan' Tab")

        widths = [75,20,50,50,35]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []

        acas_files = jmespath.search(
            """results[?type == 'ACAS'].{
                type: type,
                version: version,
                feed: feed,
                filename: fileName,
                scan_date: scanDate,
                hosts: hosts[] | [*].[hostname][]
            }""",
            { 'results' : self.scan_results}
        )

        for scan_file in acas_files:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : 'ACAS: Assured Compliance Assessment Solution / Nessus Scanner',
                'Version'        : str(scan_file['version']) + " - " + str(scan_file['feed']),
                'Hosts'          : ", ".join( scan_file['hosts']),
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        scap_files = jmespath.search(
            """results[?type == 'SCAP'].{
                title: title,
                type: type,
                version: version,
                release: release,
                filename: fileName,
                scan_date: scanDate,
                hostname: hostname
            }""",
            { 'results' : self.scan_results}
        )

        for scan_file in scap_files:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : f"{scan_file['type']}: {scan_file['title']}",
                'Version'        : "V" + str(scan_file['version']) + "R" + str(scan_file['release']),
                'Hosts'          : scan_file['hostname'],
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
            })

        ckl_files = jmespath.search(
            """results[?type == 'CKL'].{
                title: title,
                type: type,
                version: version,
                release: release,
                filename: fileName,
                scan_date: scanDate,
                hostname: hostname
            }""",
            { 'results' : self.scan_results}
        )

        for scan_file in ckl_files:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            report.append({
                'Title'          : f"{scan_file['type']}: {scan_file['title']}",
                'Version'        : "V" + str(scan_file['version']) + "R" + str(scan_file['release']),
                'Hosts'          : scan_file['hostname'],
                'Scan File Name' : os.path.basename(scan_file['filename']),
                'Dates'          : (parser.parse(scan_file['scan_date'])).strftime("%m/%d/%Y %H:%M:%S"),
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

    def rpt_poam(self):
        """ Generates POAM """
        if 'rpt_poam' in self.skip_reports:
            return None
        
        logging.info('Building POAM')
        worksheet = self.workbook.add_worksheet('POAM')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'POAM' Tab")
            QtGui.QGuiApplication.processEvents()

        widths = [1,40,15,25,25,25,30,15,30,45,20,30,25,75,40,40,25,25,40,25,25,40,25,40,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        q = Queue(maxsize=0)
        poam_results = {'O'  : {}, 'NA' : {}, 'NR' : {}, 'E'  : {}, 'C'  : {}}

        def get_scan(queue, poam_results, scan_results):
            while not queue.empty():
                work = queue.get()

                status = work[0]
                type = work[1]
                if type == 'disa':
                    disa_scans = jmespath.search(
                        "results[?type=='SCAP' || type=='CKL'].{ scan_title: title, policy: policy, scannerEdition: scannerEdition, scan_description: description, type: type, version: version, release: release, hostname: hostname, filename: fileName, requirements: requirements[] | [?status=='" + status + "'].{ req_title: reqTitle, cci: cci, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, resources: resources, severity: severity, solution: solution, comments: comments, description: description } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['ruleId']) not in poam_results[status]:
                                poam_results[status][str(req['ruleId'])] = {
                                    'scan_title'      : scan['scan_title'],
                                    'grp_id'          : req['grpId'],
                                    'vuln_id'         : req['vulnId'],
                                    'rule_id'         : req['ruleId'],
                                    'plugin_id'       : req['pluginId'],
                                    'cci'             : req['cci'],
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['ruleId']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scannerEdition'],
                                'hostname'        : scan['hostname'],
                                'version'         : scan['version'],
                                'release'         : scan['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scannerEdition: '', scan_description: '', type: type, version: version, release: feed, filename: fileName, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [*].{ cci: cci, req_title: reqTitle, description: description, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, resources: resources, severity: severity, solution: solution, comments: comments } } }",
                        { 'results' : scan_results}
                    )

                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                if str(req['pluginId']) not in poam_results[status]:
                                    poam_results[status][str(req['pluginId'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grpId'],
                                        'vuln_id'         : req['vulnId'],
                                        'rule_id'         : req['ruleId'],
                                        'plugin_id'       : req['pluginId'],
                                        'cci'             : req['cci'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'results'         : [],
                                    }
                                poam_results[status][ str(req['pluginId']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scannerEdition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_theads = int(psutil.cpu_count()) * 2
        for i in range(num_theads):
            worker = Thread(target=get_scan, args=(q, poam_results, self.scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]

                rmfControls = self.data_mapping['acas_control'][req['grp_id']] if req['grp_id'] in self.data_mapping['acas_control'] else ''
                if rmfControls == '':
                    rmfControls = self.data_mapping['ap_mapping'][req['cci']] if req['cci'] in self.data_mapping['ap_mapping'] else ''


                hosts = []
                types = []
                comments = []
                finding_details = []
                for host in req['results']:
                    hosts.append(f"{host['hostname']} [{host['type']} - Ver: {host['version']}, Rel/Feed: {host['release']} ]")
                    types.append(f"{host['type']}")
                    comments.append(f"{host['comments']}")
                    finding_details.append(f"{host['finding_details']}")

                hosts = "\n".join(hosts)
                types = list(set(types))
                prefix = "/".join(types)
                comments = "\n\n".join( list(set([c for c in comments if c])) )
                finding_details = "\n\n".join( list(set([f for f in finding_details if f])) )

                # pylint: disable=C0330
                scd = ""
                if self.poam_conf['scd']:
                    if self.poam_conf['lower_risk']:
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                    else:
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )

                    req_data = {
                        'A'                                                 : '',
                        'Control Vulnerability Description'                 : f"Title: {req['req_title']}\n\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                        'Security Control Number (NC/NA controls only)'     : rmfControls,
                        'Office/Org'                                        : f"{self.contact_info['command']}\n{self.contact_info['name']}\n{self.contact_info['phone']}\n{self.contact_info['email']}\n".strip(),
                        'Security Checks'                                   : f"{req['plugin_id']}{req['rule_id']}",
                        'Resources Required'                                : f"{req['resources']}",
                        'Scheduled Completion Date'                         : scd,
                        'Milestone with Completion Dates'                   : "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
s=str(scd).split('-'),
m=(['Winter', 'Spring', 'Summer', 'Autumn'][(int(str(scd).split('-')[1])//3)]),
) if self.poam_conf['scd'] else '',
                        'Milestone Changes'                                 : '',
                        'Source Identifying Control Vulnerability'          : f"{prefix} {req['scan_title']}",
                        'Status'                                            : f"{ Utils.status(req['status'], 'HUMAN') }",
                        'Comments'                                          : f"{ req['cci']}\n\n{comments}",
                        'Raw Severity'                                      : Utils.risk_val(req['severity'], 'MIN'),
                        'Devices Affected'                                  : hosts,
                        'Mitigations'                                       : '',
                        'Predisposing Conditions'                           : finding_details,
                        'Severity'                                          : Utils.risk_val(req['severity'], 'POAM'),
                        'Relevance of Threat'                               : 'High',
                        'Threat Description'                                : req['description'],
                        'Likelihood'                                        : Utils.risk_val(req['severity'], 'POAM'),
                        'Impact'                                            : Utils.risk_val(req['severity'], 'POAM'),
                        'Impact Description'                                : '',
                        'Residual Risk Level'                               : Utils.risk_val(req['severity'], 'POAM'),
                        'Recommendations'                                   : req['solution'],
                        'Resulting Residual Risk after Proposed Mitigations': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.poam_conf['lower_risk'] else Utils.risk_val(req['severity'], 'POAM'),
                    }
                    report.append(req_data)
                    # pylint: enable=C0330

        start_time = datetime.datetime.now()
        print( "        {} - Generating POAM".format(datetime.datetime.now() - start_time) )
        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'left', 'valign':'top'})
        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 8, 'align': 'justify', 'valign':'top'})

        if report:
            report = sorted(report, key=lambda s: (
                str(s['Status']).lower().strip(),
                str(s['Source Identifying Control Vulnerability']).lower().strip(),
                str(s['Security Checks']).lower().strip()
            ))
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, str(result[value]).strip(), date_fmt)
                    else:
                        worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    col += 1
                row += 1
        print( "        {} - Finished generating POAM".format(datetime.datetime.now() - start_time) )




    def rpt_rar(self):
        """ Generates RAR """
        if 'rpt_rar' in self.skip_reports:
            return None
            
        logging.info('Building RAR')
        worksheet = self.workbook.add_worksheet('RAR')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'RAR' Tab")
            QtGui.QGuiApplication.processEvents()

        widths = [15,15,45,30,30,45,20,15,30,30,15,15,30,30,15,15,15,15,30,30,45,30]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        q = Queue(maxsize=0)
        poam_results = {'O'  : {}, 'NA' : {}, 'NR' : {}, 'E'  : {}, 'C'  : {}}

        def get_scan(queue, poam_results, scan_results):
            while not queue.empty():
                work = queue.get()

                status = work[0]
                type = work[1]
                if type == 'disa':
                    disa_scans = jmespath.search(
                        "results[?type=='SCAP' || type=='CKL'].{ scan_title: title, policy: policy, scannerEdition: scannerEdition, scan_description: description, type: type, version: version, release: release, hostname: hostname, filename: fileName, requirements: requirements[] | [?status=='" + status + "'].{ req_title: reqTitle, cci: cci, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, resources: resources, severity: severity, solution: solution, comments: comments, description: description } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['ruleId']) not in poam_results[status]:
                                poam_results[status][str(req['ruleId'])] = {
                                    'scan_title'      : scan['scan_title'],
                                    'grp_id'          : req['grpId'],
                                    'vuln_id'         : req['vulnId'],
                                    'rule_id'         : req['ruleId'],
                                    'plugin_id'       : req['pluginId'],
                                    'cci'             : req['cci'],
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['ruleId']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scannerEdition'],
                                'hostname'        : scan['hostname'],
                                'version'         : scan['version'],
                                'release'         : scan['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scannerEdition: '', scan_description: '', type: type, version: version, release: feed, filename: fileName, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [*].{ cci: cci, req_title: reqTitle, description: description, grpId: grpId, vulnId: vulnId, ruleId: ruleId, pluginId: pluginId, status: status, finding_details: findingDetails, resources: resources, severity: severity, solution: solution, comments: comments } } }",
                        { 'results' : scan_results}
                    )

                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                if str(req['pluginId']) not in poam_results[status]:
                                    poam_results[status][str(req['pluginId'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grpId'],
                                        'vuln_id'         : req['vulnId'],
                                        'rule_id'         : req['ruleId'],
                                        'plugin_id'       : req['pluginId'],
                                        'cci'             : req['cci'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'results'         : [],
                                    }
                                poam_results[status][ str(req['pluginId']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scannerEdition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_theads = int(psutil.cpu_count()) * 2
        for i in range(num_theads):
            worker = Thread(target=get_scan, args=(q, poam_results, self.scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]
                # print(req)
                hosts = []
                types = []
                comments = []
                finding_details = []
                for host in req['results']:
                    hosts.append(f"{host['hostname']} [{host['type']} - Ver: {host['version']}, Rel/Feed: {host['release']} ]")
                    types.append(f"{host['type']}")
                    comments.append(f"{host['comments']}")
                    finding_details.append(f"{host['finding_details']}")

                hosts = "\n".join(hosts)
                types = list(set(types))
                prefix = "/".join(types)
                comments = "\n\n".join( list(set([c for c in comments if c])) )
                finding_details = "\n\n".join( list(set([f for f in finding_details if f])) )

                rmfControls = self.data_mapping['acas_control'][req['grp_id']] if req['grp_id'] in self.data_mapping['acas_control'] else ''
                if rmfControls == '':
                    rmfControls = self.data_mapping['ap_mapping'][req['cci']] if req['cci'] in self.data_mapping['ap_mapping'] else ''

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
                    'Affected CCI (16a.1)': req['cci'] if isinstance(req['cci'], str) else '',
                    'Source of Discovery(16a.2)': f"Title: {req['scan_title']}",
                    'Vulnerability ID(16a.3)': f"{req['plugin_id']}{req['rule_id']}",
                    'Vulnerability Description (16.b)': f"Title: {req['req_title']}\n\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Devices Affected (16b.1)': hosts,
                    'Security Objectives (C-I-A) (16c)': objectives,
                    'Raw Test Result (16d)': Utils.risk_val(req['severity'], 'CAT'),
                    'Predisposing Condition(s) (16d.1)': finding_details,
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
                    'Comments': f"Group ID: {req['grp_id']}\nVuln ID: {req['vuln_id']}\nRule ID: {req['rule_id']}\nPlugin ID: {req['plugin_id']}\n\n{comments}"
                }
                report.append(req_data)

        row = 0
        bold = self.workbook.add_format({'bold': True})
        cell_format = self.workbook.add_format({'font_size':8, 'text_wrap': True, 'align': 'left', 'valign':'top'})
        date_fmt = self.workbook.add_format({'num_format':'mm/dd/yyyy', 'font_size': 8, 'align': 'justify', 'valign':'top'})

        if report:
            report = sorted(report, key=lambda s: (
                str(s['Source of Discovery(16a.2)']).lower().strip(),
                str(s['Vulnerability ID(16a.3)']).lower().strip(),
            ))
            col = 0
            for column_header in report[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in report:
                col = 0
                for value in result:
                    if col == 6:
                        worksheet.write(row, col, str(result[value]).strip(), date_fmt)
                    else:
                        worksheet.write(row, col, str(result[value]).strip(), cell_format)
                    col += 1
                row += 1
        print( "        {} - Finished generating RAR".format(datetime.datetime.now() - start_time) )


    def rpt_automated_scan_info(self):
        """ Generates Scan Info Tab """
        if 'rpt_automated_scan_info' in self.skip_reports:
            return None
            
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

        scap_scans = jmespath.search(
            "results[?type=='SCAP'].{policy: policy, scannerEdition: scannerEdition, scan_date: scanDate, duration: duration, credentialed: credentialed, scan_user: scanUser, type: type, version: version, release: release, hostname: hostname, filename: fileName }",
            { 'results' : self.scan_results}
        )
        for scan_file in scap_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            report.append( {
                'Scan File Type': scan_file['type'],
                'Scan File': os.path.basename(scan_file['filename']),
                'Plugin feed version': 'V' + str(int(str(scan_file['version']))) + 'R' + str(int(str(scan_file['release']))),
                'Scanner edition used': scan_file['scannerEdition'],
                'Scan Type': 'Normal',
                'Scan policy used': scan_file['policy'],
                'Port Range' : '',
                'Hostname' : scan_file['hostname'],
                'Credentialed checks': Utils.parse_bool(str(scan_file['credentialed'])),
                'Scan User': scan_file['scan_user'],
                'Scan Start Date': scan_file['scan_date'],
                'Scan duration': str(reduce(lambda x, y: x*60+y, [int(i) for i in (str(scan_file['duration'])).split(':')])) + ' sec',
                'Scan To Feed Difference' : ''
            } )

        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ policy: policy, type: type, version: version, release: feed, filename: fileName, hosts: hosts[] | [*].{ hostname: hostname, credentialed: credentialed, scan_user: scanUser, host_date: host_date, requirements: requirements[?pluginId == `19506`] | [*].{pluginId: pluginId, resources: resources,  comments: comments } } }",
            { 'results' : self.scan_results}
        )

        for scan_file in acas_scans:
            for host in scan_file['hosts']:

                if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
                for req in host['requirements']:
                    if int(req['pluginId']) == 19506:
                        scan_data = {}
                        for line in req['comments'].split("\n"):
                            if line.strip() != '':
                                k, value = line.split(':', 1)
                                scan_data[str(k).strip()] = str(value).strip()

                        info_details = {
                            'Scan File Type': scan_file['type'],
                            'Scan File': os.path.basename(scan_file['filename']),
                            'Plugin feed version': scan_data['Plugin feed version'],
                            'Scanner edition used': scan_data['Nessus version'],
                            'Scan Type': scan_data['Scan type'],
                            'Scan policy used': scan_data['Scan policy used'],
                            'Port Range' : scan_data['Port range'] if 'Port range' in scan_data else '',
                            'Hostname' : host['hostname'],
                            'Credentialed checks': Utils.parse_bool(str(host['credentialed'])),
                            'Scan User': host['scan_user'],
                            'Scan Start Date': host['host_date'],
                            'Scan duration': str(scan_data['Scan duration']),
                            'Scan To Feed Difference' : (
                                datetime.datetime.strptime(host['host_date'], '%a %b %d %H:%M:%S %Y') -
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

    def rpt_software_linux(self):
        """ Generates Linux Software Tab """
        if 'rpt_software_linux' in self.skip_reports:
            return None
        
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
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?pluginId == `22869`]  | [*].{ 
                        plugin_id: pluginId,
                        comments: comments
                    }
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
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

    def rpt_software_windows(self):
        """ Generates Windows Software Tab """
        if 'rpt_software_windows' in self.skip_reports:
            return None
            
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
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?pluginId == `20811`]  | [*].{ 
                        plugin_id: pluginId,
                        comments: comments
                    }
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
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

    def rpt_asset_traceability(self):
        """Generates the Asset Traceability list"""
        if 'rpt_asset_traceability' in self.skip_reports:
            return None
        
        logging.info('Building Asset Traceability Tab')

        worksheet = self.workbook.add_worksheet('Asset Traceability')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Asset Traceability' Tab")

        widths = [
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25
            ]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        hardware = []
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                filename: fileName,
                version: version,
                feed: feed,
                policy: policy,
                scan_date: scanDate,
                
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os:os,
                    port_range: port_range,
                    scan_user: scanUser,
                    credentialed: credentialed
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                if Utils.is_ip(str(host['hostname'])):
                    fqdn_val = (str(host['hostname']))
                elif '.' in str(host['hostname']):
                    fqdn_val = (str(host['hostname']).split('.')[0])
                else:
                    fqdn_val = (str(host['hostname']))

                hardware.append({
                    'Machine Name (Required)'                : fqdn_val,
                    'IP'                                     : host['ip'],
                    'OS'                                     : host['os'],

                    'ACAS Scan Files'                        : os.path.basename(scan['filename']),
                    'ACAS Scanner Versions'                  : scan['version'],
                    'ACAS Scan Policy'                       : scan['policy'],
                    'ACAS Port Range 0-65535'                : 'True' if str(host['port_range']).strip() == '0-65535' or str(host['port_range']).strip() == 'all ports' else 'False',
                    'ACAS Scan Users'                        : host['scan_user'],
                    'ACAS Credentialed Checks'               : host['credentialed'],
                    'ACAS Feed Version'                      : scan['feed'],
                    'ACAS Scan Start Date'                   : scan['scan_date'],
                    'ACAS Days Between Plugin Feed And Scan' : (
                        datetime.datetime.strptime(scan['scan_date'], '%a %b %d %H:%M:%S %Y') -
                        datetime.datetime.strptime(scan['feed'], '%Y%m%d%H%M')
                    ).days,
                    'STIG CKL File'                      : '',
                    'STIG CKL Version/Release'               : '',
                    'STIG CKL Credentialed Checks'           : '',
                    'STIG CKL Total Not Reviewed'            : '',

                    'SCAP Benchmark File'                    : '',
                    'SCAP Scanner Versions'                  : '',
                    'SCAP Benchmark Version/Release'         : '',
                    'SCAP Benchmark Policy'                  : '',
                    'SCAP Scan Users'                        : '',
                    'SCAP Credentialed Checks'               : '',
                    'SCAP Benchmark Errors'                  : '',
                })

        scap_scans = jmespath.search(
            """results[?type=='SCAP'].{
                filename: fileName,
                version: version,
                release: release,
                policy: policy,
                scan_date: scanDate,
                scanner_edition: scannerEdition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scanUser,
                credentialed: credentialed,
                error: requirements[]  | [?status == 'E'].[comments, severity, status]
            }""",
            { 'results' : self.scan_results}
        )

        for scan in scap_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            hardware.append({
                'Machine Name (Required)'                : fqdn_val,
                'IP'                                     : scan['ip'],
                'OS'                                     : scan['os'],

                'ACAS Scan Files'                        : '',
                'ACAS Scanner Versions'                  : '',
                'ACAS Scan Policy'                       : '',
                'ACAS Port Range 0-65535'                : '',
                'ACAS Scan Users'                        : '',
                'ACAS Credentialed Checks'               : '',
                'ACAS Feed Version'                      : '',
                'ACAS Scan Start Date'                   : '',
                'ACAS Days Between Plugin Feed And Scan' : '',

                'STIG CKL File'                          : '',
                'STIG CKL Version/Release'               : '',
                'STIG CKL Credentialed Checks'           : '',
                'STIG CKL Total Not Reviewed'            : '',

                'SCAP Benchmark File'                    : os.path.basename(scan['filename']),
                'SCAP Scanner Versions'                  : scan['scanner_edition'],
                'SCAP Benchmark Version/Release'         : f"V{scan['version']}R{scan['release']}",
                'SCAP Benchmark Policy'                  : scan['policy'],
                'SCAP Scan Users'                        : scan['scan_user'],
                'SCAP Credentialed Checks'               : scan['credentialed'],
                'SCAP Benchmark Errors'                  : len(scan['error'])
            })

        ckl_scans = jmespath.search(
            """results[?type=='CKL'].{
                filename: fileName,
                version: version,
                release: release,
                policy: policy,
                scan_date: scanDate,
                scanner_edition: scannerEdition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scanUser,
                credentialed: credentialed,
                not_reviewed: requirements[]  | [?status == 'NR'].[comments, severity, status]
            }""",
            { 'results' : self.scan_results}
        )

        for scan in ckl_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            hardware.append({
                'Machine Name (Required)'                : fqdn_val,
                'IP'                                     : scan['ip'],
                'OS'                                     : scan['os'],

                'ACAS Scan Files'                        : '',
                'ACAS Scanner Versions'                  : '',
                'ACAS Scan Policy'                       : '',
                'ACAS Port Range 0-65535'                : '',
                'ACAS Scan Users'                        : '',
                'ACAS Credentialed Checks'               : '',
                'ACAS Feed Version'                      : '',
                'ACAS Scan Start Date'                   : '',
                'ACAS Days Between Plugin Feed And Scan' : '',

                'STIG CKL File'                          : os.path.basename(scan['filename']),
                'STIG CKL Version/Release'               : f"V{scan['version']}R{scan['release']}",
                'STIG CKL Credentialed Checks'           : 'True',
                'STIG CKL Total Not Reviewed'            : len(scan['not_reviewed']),

                'SCAP Benchmark File'                    : '',
                'SCAP Scanner Versions'                  : '',
                'SCAP Benchmark Version/Release'         : '',
                'SCAP Benchmark Policy'                  : '',
                'SCAP Scan Users'                        : '',
                'SCAP Credentialed Checks'               : '',
                'SCAP Benchmark Errors'                  : '',
            })

        hardware = sorted(hardware, key=lambda hardware: hardware['Machine Name (Required)'])
        hardware_count = 0

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if hardware:
            col = 0
            for column_header in hardware[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in hardware:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_hardware(self):
        """Generates the hardware list"""
        if 'rpt_hardware' in self.skip_reports:
            return None
            
        logging.info('Building Hardware Tab')

        worksheet = self.workbook.add_worksheet('Hardware')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Hardware' Tab")

        widths = [25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        hardware = []
        hosts = []
        
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].hosts[] | [*].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os  }",
            { 'results' : self.scan_results}
        )
        
        for host in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(host['hostname'])):
                fqdn_val = (str(host['hostname']))
            elif '.' in str(host['hostname']):
                fqdn_val = (str(host['hostname']).split('.')[0])
            else:
                fqdn_val = (str(host['hostname']))

            if fqdn_val not in hosts:
                hosts.append(fqdn_val)
                hardware.append({
                    '#'                                  : '',
                    'Component Type'                     : host['device_type'],
                    'Machine Name (Required)'            : fqdn_val,
                    'IP Address'                         : host['ip'],
                    'Virtual Asset?'                     : '',

                    'Manufacturer'                       : host['manufacturer'],
                    'Model Number'                       : host['model'],
                    'Serial Number'                      : host['serial'],
                    'OS/iOS/FW Version'                  : host['os'],
                    'Location (P/C/S & Building)'        : '',
                    'Approval Status'                    : '',
                    'Critical Information System Asset?' : ''
                })
        
        scap_scans = jmespath.search(
            "results[?type=='SCAP' || type == 'CKL'].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os  }",
            { 'results' : self.scan_results}
        )
        
        for scan in scap_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            
            if Utils.is_ip(str(scan['hostname'])):
                fqdn_val = (str(scan['hostname']))
            elif '.' in str(scan['hostname']):
                fqdn_val = (str(scan['hostname']).split('.')[0])
            else:
                fqdn_val = (str(scan['hostname']))

            if fqdn_val not in hosts:
                hosts.append(fqdn_val)
                hardware.append({
                    '#'                                  : '',
                    'Component Type'                     : scan['device_type'] if 'device_type' in scan and scan['device_type'].strip() != '' else 'Unknown',
                    'Machine Name (Required)'            : fqdn_val,
                    'IP Address'                         : scan['ip'],
                    'Virtual Asset?'                     : '',

                    'Manufacturer'                       : scan['manufacturer'],
                    'Model Number'                       : scan['model'],
                    'Serial Number'                      : scan['serial'],
                    'OS/iOS/FW Version'                  : scan['os'],
                    'Location (P/C/S & Building)'        : '',
                    'Approval Status'                    : '',
                    'Critical Information System Asset?' : ''
                })
        
        hardware = sorted(hardware, key=lambda hardware: hardware['Machine Name (Required)'])
        hardware_count = 0
        for asset in hardware:
            hardware_count += 1
            asset['#'] = hardware_count

        row = 0
        bold = self.workbook.add_format({'bold': True})
        wrap_text = self.workbook.add_format({'font_size':8, 'text_wrap': True})

        if hardware:
            col = 0
            for column_header in hardware[0]:
                worksheet.write(row, col, column_header, bold)
                col += 1
            row += 1

            for result in hardware:
                col = 0
                for value in result:
                    worksheet.write(row, col, result[value], wrap_text)
                    col += 1
                row += 1

    def rpt_ppsm(self):
        """ Generates PPSM Report """
        if 'rpt_ppsm' in self.skip_reports:
            return None
        
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
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[?pluginId == `11219` || pluginId == `14272`]  | [*].{ 
                        plugin_id: pluginId,
                        port: port,
                        protocol: protocol,
                        service: service,
                        severity: severity
                    }
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
                for req in host['requirements']:
                    if not list(filter(lambda x: x['Port'] == req['port'], ports)):
                        ports.append({
                            'Port': req['port'],
                            'Protocol': req['protocol'],
                            'Service': req['service'],
                            'Purpose': '',
                            'Usage': '',
                            'Severity': req['severity']
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
        if 'rpt_cci' in self.skip_reports:
            return None
            
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
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
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
        if 'rpt_acas_uniq_vuln' in self.skip_reports:
            return None
            
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
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [*].{ 
                        plugin_id: pluginId,
                        title: reqTitle,
                        grp_id: grpId,
                        severity: severity
                    }
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
                    
                for req in host['requirements']:
                    if not list(filter(lambda x: x['plugin_id'] == req['plugin_id'], plugins)):
                        plugins.append(req)
                    if int(req['plugin_id']) not in plugin_count:
                        plugin_count[int(req['plugin_id'])] = 1
                    else:
                        plugin_count[int(req['plugin_id'])] += 1
                    
        plugins = sorted(plugins, key=lambda plugin: plugin['plugin_id'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin'         : plugin['plugin_id'],
                'Plugin Name'    : plugin['title'],
                'Family'         : plugin['grp_id'],
                'Raw Severity'   : Utils.risk_val(plugin['severity'], 'CAT'),
                'Total'          : plugin_count[int(plugin['plugin_id'])]
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
        if 'rpt_acas_uniq_iava' in self.skip_reports:
            return None
        
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
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [?iava != ''].{ 
                        plugin_id: pluginId,
                        iava: iava,
                        title: reqTitle,
                        grp_id: grpId,
                        severity: severity
                    }
                }
            }""",
            { 'results' : self.scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.scans_to_reports:
                    QtGui.QGuiApplication.processEvents()
                    
                for req in host['requirements']:
                    if not list(filter(lambda x: x['plugin_id'] == req['plugin_id'], plugins)):
                        plugins.append(req)
                    if int(req['plugin_id']) not in plugin_count:
                        plugin_count[int(req['plugin_id'])] = 1
                    else:
                        plugin_count[int(req['plugin_id'])] += 1
                    
        plugins = sorted(plugins, key=lambda plugin: plugin['plugin_id'])
        for plugin in plugins:
            plugins_rpt.append({
                'Plugin'     : plugin['plugin_id'],
                'IAVM'       : plugin['iava'],
                'Plugin Name': plugin['title'],
                'Family'     : plugin['grp_id'],
                'Severity'   : Utils.risk_val(plugin['severity'], 'CAT'),
                'Total'      : plugin_count[int(plugin['plugin_id'])]
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
        if 'rpt_missing_patches' in self.skip_reports:
            return None
            
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

        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,

                    requirements: requirements[]  | [?pluginId == `66334`].{ comments: comments}
                }
            }""",
            { 'results' : self.scan_results}
        )

        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                for req in host['requirements']:
                    for patch in re.findall(r'\+ Action to take : (.+)+', req['comments']):
                        patches.append({
                            'Hostname': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })
                    for patch in re.findall(r'- (.+)+', req['comments']):
                        patches.append({
                            'Hostname': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'Action': patch
                        })

        patches = sorted(
            patches,
            key=lambda s: (str(s['Hostname']).lower().strip(), str(s['Action']).lower().strip())
        )
        
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
        if 'rpt_summary' in self.skip_reports:
            return None
            
        logging.info('Building Summary Tab')
        worksheet = self.workbook.add_worksheet('Summary')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Summary' Tab")

        widths = [10,30,20,50,50,20,20,20,10,10,10,10,10,10,25,20]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        summary_results = []

        disa_scans = jmespath.search(
            """results[?type=='CKL' || type=='SCAP'].{
                type: type,
                hostname: hostname,
                ip: ip,
                os: os,
                filename: fileName,
                credentialed: credentialed
                scan_date: scanDate,
                version: version,
                release: release,
                cati: requirements[]   | [?status != 'C' && severity > `2`].[comments, severity, status],
                catii: requirements[]  | [?status != 'C' && severity == `2`].[comments, severity, status],
                catiii: requirements[] | [?status != 'C' && severity == `1`].[comments, severity, status],
                cativ: requirements[]  | [?status != 'C' && severity == `0`].[comments, severity, status],
                blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && findingDetails == '')].[comments, severity, status]
            }""",
            { 'results' : self.scan_results}
        )

        for scan in disa_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()

            summary_results.append({
                'Type': scan['type'],
                'Hostname': scan['hostname'],
                'IP': scan['ip'],
                'OS': scan['os'],
                'Scan File Name': os.path.basename(scan['filename']),

                'Scan Date': scan['scan_date'],
                'Version': scan['version'],
                'Release': scan['release'],

                'CAT I': len(scan['cati']),
                'CAT II': len(scan['catii']),
                'CAT III': len(scan['catiii']),
                'CAT IV': len(scan['cativ']),
                'Total': len(scan['cati']) + len(scan['catii']) + len(scan['catiii']) + len(scan['cativ']),
                'Score': 10*len(scan['cati']) + 3*len(scan['catii']) + len(scan['catiii']),
                'Credentialed': scan['credentialed'],
                'Blank Comments' : len(scan['blank_comments'])
            })

        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                type: type,
                filename: fileName,
                scan_date: scanDate,
                version: version,
                feed: feed,
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,
                    credentialed: credentialed,

                    cati:   requirements[] | [?status != 'C' && severity > `2`].{ plugin_id: pluginId, severity: severity, status: status},
                    catii:  requirements[] | [?status != 'C' && severity == `2`].{ plugin_id: pluginId, severity: severity, status: status},
                    catiii: requirements[] | [?status != 'C' && severity == `1`].{ plugin_id: pluginId, severity: severity, status: status},
                    cativ:  requirements[] | [?status != 'C' && severity == `0`].{ plugin_id: pluginId, severity: severity, status: status},

                    blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && findingDetails == '')].{ plugin_id: pluginId, severity: severity, status: status}
                }
            }""",
            { 'results' : self.scan_results}
        )

        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                summary_results.append({
                    'Type': scan['type'],
                    'Hostname': host['hostname'],
                    'IP': host['ip'],
                    'OS': host['os'],
                    'Scan File Name': os.path.basename(scan['filename']),

                    'Scan Date': scan['scan_date'],
                    'Version': scan['version'],
                    'Release': scan['feed'],

                    'CAT I': len(host['cati']),
                    'CAT II': len(host['catii']),
                    'CAT III': len(host['catiii']),
                    'CAT IV': len(host['cativ']),
                    'Total': len(host['cati']) + len(host['catii']) + len(host['catiii']) + len(host['cativ']),
                    'Score': 10*len(host['cati']) + 3*len(host['catii']) + len(host['catiii']),
                    'Credentialed': host['credentialed'],
                    'Blank Comments' : len(host['blank_comments']),
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
        if 'rpt_raw_data' in self.skip_reports:
            return None
            
        logging.info('Building Raw Data Tab')
        worksheet = self.workbook.add_worksheet('Raw Data')
        if self.scans_to_reports:
            self.scans_to_reports.statusBar().showMessage("Generating 'Raw Data' Tab")

        worksheet.set_column('A:A', 15)
        worksheet.set_column('B:B', 40)
        worksheet.set_column('C:C', 40)
        worksheet.set_column('D:D', 30)
        worksheet.set_column('E:E', 10)
        worksheet.set_column('F:F', 15)
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
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ type: type, title: title, filename: fileName, scan_date: scanDate, version: version, feed: feed, hosts: hosts[] | [*].{ hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ publication_date: publicationDate, modification_date : modificationDate, comments: comments, grp_id: grpId, plugin_id: pluginId, req_title: reqTitle, severity: severity, status: status, finding_details: findingDetails, description: description, solution: solution, fix_id: fixId, references: references, resources: resources } } }",
            { 'results' : self.scan_results}
        )

        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:

                    raw_results.append({
                            'Scan Type'         : scan['type'].upper(),
                            'Scan Title'        : scan['title'],
                            'Filename'          : os.path.basename(scan['filename']),
                            'Scan Date'         : scan['scan_date'],
                            'Version'           : scan['version'],
                            'Release'           : scan['feed'],

                            'Publication Date'  : req['publication_date'],
                            'Modification Date' : req['modification_date'],
                            'Credentialed'      : host['credentialed'],
                            'Hostname'          : host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'grpId'             : req['grp_id'],
                            'vulnId'            : '',
                            'ruleId'            : '',
                            'pluginId'          : req['plugin_id'],
                            'IA Controls'       : '',
                            'RMF Controls'      : '',
                            'Assessments'       : '',
                            'CCI'               : '',
                            'Title'             : req['req_title'],
                            'Severity'          : Utils.risk_val(str(req['severity']), 'CAT'),
                            'Status'            : Utils.status(req['status'], 'HUMAN'),
                            'Finding Details'   : req['finding_details'][0:32760],
                            'Description'       : req['description'][0:32760],
                            'Solution'          : req['solution'][0:32760],
                            'fixId'             : req['fix_id'],
                            'References'        : req['references'][0:32760],
                            'Resources'         : req['resources'],
                            'Comments'          : '',
                        })

        disa_scans = jmespath.search(
            "results[?type=='CKL' || type=='SCAP'].{ type: type, title: title, filename: fileName, scan_date: scanDate, version: version, release: release, hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ comments: comments, grp_id: grpId, plugin_id: pluginId, req_title: reqTitle, severity: severity, status: status, finding_details: findingDetails, description: description, solution: solution, fix_id: fixId, references: references, resources: resources, cci: cci, assessments: assessments, rmf_controls: rmfControls, ia_controls: iaControls, rule_id: ruleId, vuln_id: vulnId } }",
            { 'results' : self.scan_results}
        )

        for scan in disa_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for req in scan['requirements']:
                raw_results.append({
                        'Scan Type'         : scan['type'].upper(),
                        'Scan Title'        : scan['title'].replace(self.strings['STIG'], ''),
                        'Filename'          : os.path.basename(scan['filename']),
                        'Scan Date'         : scan['scan_date'],
                        'Version'           : int(scan['version'].strip(string.ascii_letters)),
                        'Release'           : int(scan['release'].strip(string.ascii_letters)),
                        'Publication Date'  : '',
                        'Modification Date' : '',
                        'Credentialed'      : scan['credentialed'],
                        'Hostname'          : scan['hostname'] if scan['hostname'].strip() != '' else scan['ip'],
                        'grpId'             : req['grp_id'],
                        'vulnId'            : req['vuln_id'],
                        'ruleId'            : req['rule_id'],
                        'pluginId'          : req['plugin_id'],
                        'IA Controls'       : req['ia_controls'],
                        'RMF Controls'      : req['rmf_controls'],
                        'Assessments'       : req['assessments'],
                        'CCI'               : req['cci'],
                        'Title'             : req['req_title'],
                        'Severity'          : Utils.risk_val(str(req['severity']), 'CAT'),
                        'Status'            : Utils.status(req['status'], 'HUMAN'),
                        'Finding Details'   : req['finding_details'][0:32760],
                        'Description'       : req['description'][0:32760],
                        'Solution'          : req['solution'][0:32760],
                        'fixId'             : req['fix_id'],
                        'References'        : req['references'][0:32760],
                        'Resources'         : req['resources'],
                        'Comments'          : req['comments'][0:32760],
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
        if 'rpt_operating_systems' in self.skip_reports:
            return None
            
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
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ os: os } }",
            { 'results' : self.scan_results}
        )
        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
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
        if 'rpt_local_users' in self.skip_reports:
            return None
            
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
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?pluginId == `10860`] | [*].comments } }",
            { 'results' : self.scan_results}
        )

        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'- ([a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })

        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?pluginId == `95928`] | [*].comments } }",
            { 'results' : self.scan_results}
        )

        for scan in acas_scans:
            if self.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'User\s+:\s+([a-zA-Z0-9]+)+', req):
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
