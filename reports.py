""" reports module of scans to poam"""
# pylint: disable=C0301
import re
import sys
import pprint
import os.path
import string
import datetime
import logging
import jmespath
import pickle

from scar_pickles import SCARPickles

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
    
    strings = {
        'STIG' : 'Security Technical Implementation Guide',
        'IGN_SOFT' : r'/drivers|drv|driver|lib|library|framework|patch|update|runtime|chipset|redistributable|kb[0-9]+'
    }

    def __init__(self, main_window=None):
        """ constructor """
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        
        self.scar_conf = SCARPickles.loader( os.path.join(application_path, "data", "scar_configs.pkl") )
        self.scar_data = SCARPickles.loader( os.path.join(application_path, "data", "scar_data.pkl") )
        
        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{self.scar_conf.get('application_path')}/scans2reports.log", level=logging.INFO, format=FORMAT)
        logging.info('Building Reports Object')
        
        report_name = "{}/results/{}".format(
            os.path.dirname(os.path.realpath(__file__)),
            datetime.datetime.now().strftime("scans2reports-%Y%m%d_%H%M%S.xlsx")
        )

        self.workbook = xlsxwriter.Workbook(report_name)
        self.main_window = main_window

    def close_workbook(self):
        """ Close the excel file """
        logging.info('Closing Workbook')
        self.workbook.close()

    def rpt_scap_ckl_issues(self):
        """ SCAP - CKL Inconsistencies tab """
        if 'rpt_scap_ckl_issues' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building SCAP-CKL Inconsistencies report')
        worksheet = self.workbook.add_worksheet('SCAP-CKL Inconsistencies')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'SCAP-CKL Inconsistencies' Tab")

        widths = [40, 40, 15, 15, 15, 15, 35, 35, 25, 25, 25, 25, 20, 20, 75, 75, 75, 150]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)
        report = []

        start_time = datetime.datetime.now()
        print( "        {} - Compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
    
        scaps = jmespath.search(
            "results[?type=='SCAP'].{ scan_title: title, version: version, release: release, filename: filename, requirements: requirements[] | [*].{ req_title: req_title, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, comments: comments } }",
            { 'results' : scan_results}
        )
        ckls = jmespath.search(
            "results[?type=='CKL'].{ scan_title: title, version: version, release: release, filename: filename, requirements: requirements[] | [*].{ req_title: req_title, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, comments: comments } }",
            { 'results' : scan_results}
        )
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        mismatch = []

        print("        {} - Finding Non-Executed CKL requirements".format( datetime.datetime.now() - start_time ))
        executed_ckls = list(set(jmespath.search("results[].requirements[].vuln_id[]", { 'results' : ckls} )))

        for scap in scaps:
            start_time2 = datetime.datetime.now()
            for req in scap['requirements']:
                if req['vuln_id'] not in executed_ckls:
                    c = {
                        'Scan Title'          : scap['scan_title'].replace(self.strings['STIG'], 'STIG'),
                        'Req Title'           : req['req_title'],
                        'SCAP Version'        : int(str(scap['version'])),
                        'SCAP Release'        : int(str(scap['release'])),
                        'CKL Version'         : '',
                        'CKL Release'         : '',
                        'SCAP Grp_Id'          : req['grp_id'],
                        'CKL Grp_Id'           : '',
                        'SCAP Rule_Id'         : req['rule_id'],
                        'CKL Rule_Id'          : '',
                        'SCAP Vuln_Id'         : req['vuln_id'],
                        'CKL Vuln_Id'          : '',
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
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        disa_scans = jmespath.search(
            """results[?type == 'CKL' || type == 'SCAP'].{
                type: type,
                scan_title: title,
                filename: filename, 
                version: version, 
                release: release, 
                requirements: requirements[*].{
                    req_title: req_title,
                    grp_id: grp_id,
                    rule_id: rule_id,
                    vuln_id: vuln_id,
                    status: status,
                    comments: comments,
                    finding_details: finding_details
                }
            }""",
            { 'results' : scan_results}
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
                        'SCAP Grp_Id'         : scap['grp_id'],
                        'CKL Grp_Id'          : ckl['grp_id'],
                        'SCAP Rule_Id'         : scap['rule_id'],
                        'CKL Rule_Id'          : ckl['rule_id'],
                        'SCAP Vuln_Id'         : scap['vuln_id'],
                        'CKL Vuln_Id'          : ckl['vuln_id'],
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
            str(s['SCAP Vuln_Id']).lower().strip(),
            str(s['SCAP Rule_Id']).lower().strip(),
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
        if 'rpt_test_plan' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Test Plan Report')
        worksheet = self.workbook.add_worksheet('Test Plan')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Test Plan' Tab")

        widths = [75,20,50,50,35]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        report = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_files = jmespath.search(
            """results[?type == 'ACAS'].{
                type: type,
                version: version,
                feed: feed,
                filename: filename,
                scan_date: scan_date,
                hosts: hosts[] | [*].[hostname][]
            }""",
            { 'results' : scan_results}
        )

        for scan_file in acas_files:
            if self.main_window:
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
                filename: filename,
                scan_date: scan_date,
                hostname: hostname
            }""",
            { 'results' : scan_results}
        )

        for scan_file in scap_files:
            if self.main_window:
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
                filename: filename,
                scan_date: scan_date,
                hostname: hostname
            }""",
            { 'results' : scan_results}
        )

        for scan_file in ckl_files:
            if self.main_window:
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
        if 'rpt_poam' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building POAM')
        worksheet = self.workbook.add_worksheet('POAM')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'POAM' Tab")
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
                        "results[?type=='SCAP' || type=='CKL'].{ scan_title: title, policy: policy, scanner_edition: scanner_edition, scan_description: description, type: type, version: version, release: release, hostname: hostname, filename: filename, requirements: requirements[] | [?status=='" + status + "'].{ req_title: req_title, cci: cci, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, description: description } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['rule_id']) not in poam_results[status]:
                                poam_results[status][str(req['rule_id'])] = {
                                    'scan_title'      : scan['scan_title'],
                                    'grp_id'          : req['grp_id'],
                                    'vuln_id'         : req['vuln_id'],
                                    'rule_id'         : req['rule_id'],
                                    'plugin_id'       : req['plugin_id'],
                                    'cci'             : req['cci'],
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['rule_id']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scanner_edition'],
                                'hostname'        : scan['hostname'],
                                'version'         : scan['version'],
                                'release'         : scan['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scanner_edition: '', scan_description: '', type: type, version: version, release: feed, filename: filename, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [?status=='" + status + "'].{ cci: cci, req_title: req_title, description: description, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, publication_date: publication_date, modification_date: modification_date } } }",
                        { 'results' : scan_results}
                    )

                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                if str(req['plugin_id']) not in poam_results[status]:
                                    poam_results[status][str(req['plugin_id'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grp_id'],
                                        'vuln_id'         : req['vuln_id'],
                                        'rule_id'         : req['rule_id'],
                                        'plugin_id'       : req['plugin_id'],
                                        'cci'             : req['cci'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'publication_date'  : req['publication_date'],
                                        'modification_date' : req['modification_date'],
                                        'results'         : [],
                                    }
                                poam_results[status][ str(req['plugin_id']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scanner_edition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_threads = int(psutil.cpu_count()) * 2
        for i in range(num_threads):
            worker = Thread(target=get_scan, args=(q, poam_results, scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )


        selected_mitigations = {}
        if self.scar_data.get('mitigations') is not None and len(self.scar_data.get('mitigations')) >0 and 'mitigations' in self.scar_data.get('mitigations').keys():
            for mit in self.scar_data.get('mitigations')['mitigations']:
                if mit['plugin_id'] is not None and mit['plugin_id'].strip() != '':
                    selected_mitigations[ str(mit['plugin_id']) ] = mit['mitigation']
                if mit['vuln_id'] is not None and mit['vuln_id'].strip() != '':
                    selected_mitigations[ str(mit['vuln_id']) ] = mit['mitigation']
                if mit['rule_id'] is not None and mit['rule_id'].strip() != '':
                    selected_mitigations[ str(mit['rule_id']) ] = mit['mitigation']
                        
        report = []
        for stat in ['O', 'NA', 'NR', 'E', 'C']:
            for finding in poam_results[stat]:
                req = poam_results[stat][finding]
                
                rmf_controls = self.scar_data.get('data_mapping')['acas_control'][req['grp_id']] if req['grp_id'] in self.scar_data.get('data_mapping')['acas_control'] else ''
                if rmf_controls == '':
                    rmf_controls = self.scar_data.get('data_mapping')['ap_mapping'][req['cci']] if req['cci'] in self.scar_data.get('data_mapping')['ap_mapping'] else ''

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
                if self.scar_data.get('scd'):
                    if self.scar_data.get('lower_risk'):
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM')) - 1), 1, 3 )] )
                    else:
                        scd = datetime.date.today() + datetime.timedelta( ([1095, 365, 90, 30])[Utils.clamp( (int(Utils.risk_val(req['severity'], 'NUM'))), 1, 3 )] )
                else:
                    scd = ''

                predisposing_conditions = self.scar_data.get('predisposing_conditions')
                
                mitigation_statement = ''
                if str(req['plugin_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                if str(req['vuln_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                if str(req['rule_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['rule_id']) ]
                
                if self.scar_data.get('test_results') is not None:
                    #test results parsed
                    
                    if req['cci'].strip() != '':
                        #cci is present
                        
                        if self.scar_data.get('test_results') == 'add':
                            #add option selected, proceed as normal
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            
                        elif self.scar_data.get('test_results') == 'close':
                            #close option selected, inheritted or CCI's not in package will be closed.
                            #non-inheritted controls that are present will proceed as normal
                            
                            if  req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys():
                                #the current cci is not in the implementation plan, map to close
                                comments = f"{ req['cci']}\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being marked as 'Completed' by default. \n\n{comments}"
                                rmf_controls = rmf_controls
                                status = f"{ Utils.status('C', 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"{ req['cci']}\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being marked as completed by default. \n\n{comments}"
                                    rmf_controls = rmf_controls
                                    status = f"{ Utils.status('C', 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        elif self.scar_data.get('test_results') == 'convert':
                            #convert option selected, inheritted or CCI's not in package will be converted to CM-6.5
                            #non-inheritted controls that are present will proceed as normal
                            if  req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys():
                                #the current cci is not in the implementation plan, map to CM-6.5
                                comments = f"CCI-000366\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being mapped to CCI-000366 CM-6.5.\n\n{comments}"
                                req['cci'] = 'CCI-000366'
                                rmf_controls = "CM-6.5"
                                status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"CCI-000366\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being mapped to CCI-000366 CM-6.5. \n\n{comments}"
                                    req['cci'] = 'CCI-000366'
                                    rmf_controls = "CM-6.5"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        else:
                            #fallthrough catch.  This should never be reached
                            
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    else:
                        #no cci present, convert to CM-6.5
                        rmf_controls = 'CM-6.5'
                        req['cci'] = 'CCI-000366'
                        comments = f"{req['cci']}\n\nThe control mapping for this requirement is unavailable so it is being mapped to CCI-000366 CM-6.5 by default. \n\n{comments}"
                        status = f"{ Utils.status(req['status'], 'HUMAN') }"

                else:
                    #test results not submitted, process as usual
                    rmf_controls = rmf_controls
                    comments = f"{ req['cci']}\n\n{comments}"
                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    
                if self.scar_data.get('include_finding_details'):
                    comments = f"{comments}\n\nFinding Details:\n{finding_details}"
                
                req_data = {
                    'A'                                                 : '',
                    'Control Vulnerability Description'                 : f"Title: {req['req_title']}\n\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Security Control Number (NC/NA controls only)'     : rmf_controls,
                    'Office/Org'                                        : f"{self.scar_data.get('command')}\n{self.scar_data.get('name')}\n{self.scar_data.get('phone')}\n{self.scar_data.get('email')}\n".strip(),
                    'Security Checks'                                   : f"{req['plugin_id']}{req['rule_id']}\n{req['vuln_id']}",
                    'Resources Required'                                : f"{req['resources']}",
                    'Scheduled Completion Date'                         : scd,
                    'Milestone with Completion Dates'                   : "{m} {s[0]} updates {s[1]}/{s[2]}/{s[0]}".format(
s=str(scd).split('-'),
m=(['Winter', 'Spring', 'Summer', 'Autumn'][(int(str(scd).split('-')[1])//3)]),
) if self.scar_data.get('scd') else '',
                    'Milestone Changes'                                 : '',
                    'Source Identifying Control Vulnerability'          : f"{prefix} {req['scan_title']}",
                    'Status'                                            : status,
                    'Comments'                                          : comments,
                    'Raw Severity'                                      : Utils.risk_val(req['severity'], 'MIN'),
                    'Devices Affected'                                  : hosts,
                    'Mitigations'                                       : mitigation_statement,
                    'Predisposing Conditions'                           : predisposing_conditions,
                    'Severity'                                          : Utils.risk_val(req['severity'], 'POAM'),
                    'Relevance of Threat'                               : 'High',
                    'Threat Description'                                : req['description'],
                    'Likelihood'                                        : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact'                                            : Utils.risk_val(req['severity'], 'POAM'),
                    'Impact Description'                                : '',
                    'Residual Risk Level'                               : Utils.risk_val(req['severity'], 'POAM'),
                    'Recommendations'                                   : req['solution'],
                    'Resulting Residual Risk after Proposed Mitigations': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.scar_data.get('lower_risk') else Utils.risk_val(req['severity'], 'POAM'),
                }


                if 'publication_date' not in req:
                    report.append(req_data)
                elif req['publication_date'] is None:
                    report.append(req_data)
                elif( str(req['publication_date']).strip() == '' ):
                    report.append(req_data)
                elif( datetime.datetime.strptime(req['publication_date'],'%Y/%m/%d')  < datetime.datetime.today() - datetime.timedelta(days=self.scar_data.get('exclude_plugins') ) ):
                    report.append(req_data)

                            
                    
                # pylint: enable=C0330
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
        if 'rpt_rar' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building RAR')
        worksheet = self.workbook.add_worksheet('RAR')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'RAR' Tab")
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
                        "results[?type=='SCAP' || type=='CKL'].{ scan_title: title, policy: policy, scanner_edition: scanner_edition, scan_description: description, type: type, version: version, release: release, hostname: hostname, filename: filename, requirements: requirements[] | [?status=='" + status + "'].{ req_title: req_title, cci: cci, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, description: description } }",
                        { 'results' : scan_results}
                    )
                    for scan in disa_scans:
                        for req in scan['requirements']:
                            if str(req['rule_id']) not in poam_results[status]:
                                poam_results[status][str(req['rule_id'])] = {
                                    'scan_title'      : scan['scan_title'],
                                    'grp_id'          : req['grp_id'],
                                    'vuln_id'         : req['vuln_id'],
                                    'rule_id'         : req['rule_id'],
                                    'plugin_id'       : req['plugin_id'],
                                    'cci'             : req['cci'],
                                    'req_title'       : req['req_title'],
                                    'description'     : req['description'],
                                    'resources'       : req['resources'],
                                    'severity'        : req['severity'],
                                    'solution'        : req['solution'],
                                    'status'          : req['status'],
                                    'results'         : [],
                                }

                            poam_results[status][ str(req['rule_id']) ]['results'].append({
                                'scan_file'       : os.path.basename( scan['filename'] ),
                                'type'            : scan['type'],
                                'finding_details' : req['finding_details'],
                                'comments'        : req['comments'],
                                'policy'          : scan['policy'],
                                'scanner_edition' : scan['scanner_edition'],
                                'hostname'        : scan['hostname'],
                                'version'         : scan['version'],
                                'release'         : scan['release'],
                            })

                elif type == 'acas':
                    acas_scans = jmespath.search(
                        "results[?type=='ACAS'].{ scan_title: title, policy: policy, scanner_edition: '', scan_description: '', type: type, version: version, release: feed, filename: filename, hosts: hosts[] | [*].{ hostname: hostname, requirements: requirements[] | [?status == '" + status + "'].{ cci: cci, req_title: req_title, description: description, grp_id: grp_id, vuln_id: vuln_id, rule_id: rule_id, plugin_id: plugin_id, status: status, finding_details: finding_details, resources: resources, severity: severity, solution: solution, comments: comments, publication_date: publication_date, modification_date: modification_date } } }",
                        { 'results' : scan_results}
                    )

                    for scan in acas_scans:
                        for host in scan['hosts']:
                            for req in host['requirements']:
                                if str(req['plugin_id']) not in poam_results[status]:
                                    poam_results[status][str(req['plugin_id'])] = {
                                        'scan_title'      : scan['scan_title'],
                                        'grp_id'          : req['grp_id'],
                                        'vuln_id'         : req['vuln_id'],
                                        'rule_id'         : req['rule_id'],
                                        'plugin_id'       : req['plugin_id'],
                                        'cci'             : req['cci'],
                                        'req_title'       : req['req_title'],
                                        'description'     : req['description'],
                                        'resources'       : req['resources'],
                                        'severity'        : req['severity'],
                                        'solution'        : req['solution'],
                                        'status'          : req['status'],
                                        'publication_date'  : req['publication_date'],
                                        'modification_date' : req['modification_date'],
                                        'results'         : [],
                                    }
                                poam_results[status][ str(req['plugin_id']) ]['results'].append({
                                    'scan_file'       : os.path.basename( scan['filename'] ),
                                    'type'            : scan['type'],
                                    'finding_details' : req['finding_details'],
                                    'comments'        : req['comments'],
                                    'policy'          : scan['policy'],
                                    'scanner_edition' : scan['scanner_edition'],
                                    'hostname'        : host['hostname'],
                                    'version'         : scan['version'],
                                    'release'         : scan['release'],
                                })
                queue.task_done()

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        for status in ['O', 'NA', 'NR', 'E', 'C']:
            q.put((status, 'acas'))
            q.put((status, 'disa'))

        num_threads = int(psutil.cpu_count()) * 2
        for i in range(num_threads):
            worker = Thread(target=get_scan, args=(q, poam_results, scan_results))
            worker.setDaemon(True)
            worker.start()

        while q.qsize() > 0:
            QtGui.QGuiApplication.processEvents()

        q.join()
        print( "        {} - Finished compiling SCAP and CKL results".format(datetime.datetime.now() - start_time ) )

        selected_mitigations = {}
        if self.scar_data.get('mitigations') is not None and len( self.scar_data.get('mitigations') ) >0 and 'mitigations' in self.scar_data.get('mitigations').keys():
            for mit in self.scar_data.get('mitigations')['mitigations']:
                if mit['plugin_id'] is not None and mit['plugin_id'].strip() != '':
                    selected_mitigations[ str(mit['plugin_id']) ] = mit['mitigation']
                if mit['vuln_id'] is not None and mit['vuln_id'].strip() != '':
                    selected_mitigations[ str(mit['vuln_id']) ] = mit['mitigation']
                if mit['rule_id'] is not None and mit['rule_id'].strip() != '':
                    selected_mitigations[ str(mit['rule_id']) ] = mit['mitigation']
                    
                    
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
                finding_details = "Finding Details:\n" + "\n\n".join( list(set([f for f in finding_details if f])) )

                rmf_controls = self.scar_data.get('data_mapping')['acas_control'][req['grp_id']] if req['grp_id'] in self.scar_data.get('data_mapping')['acas_control'] else ''
                if rmf_controls == '':
                    rmf_controls = self.scar_data.get('data_mapping')['ap_mapping'][req['cci']] if req['cci'] in self.scar_data.get('data_mapping')['ap_mapping'] else ''

                objectives = []
                for rmf_cia in self.scar_data.get('data_mapping')['rmf_cia']:
                    if rmf_controls.strip() != '' and rmf_cia['Ctl'] == rmf_controls:
                        if rmf_cia['CL'] == 'X' or rmf_cia['CM'] == 'X' or rmf_cia['CH'] == 'X':
                            objectives.append('C')
                        if rmf_cia['IL'] == 'X' or rmf_cia['IM'] == 'X' or rmf_cia['IH'] == 'X':
                            objectives.append('I')
                        if rmf_cia['AL'] == 'X' or rmf_cia['AM'] == 'X' or rmf_cia['AH'] == 'X':
                            objectives.append('A')

                objectives = list(set(objectives))
                objectives = ", ".join( objectives )

                mitigation_statement = ''
                if str(req['plugin_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['plugin_id']) ]
                if str(req['vuln_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['vuln_id']) ]
                if str(req['rule_id']) in selected_mitigations.keys():
                    mitigation_statement = selected_mitigations[ str(req['rule_id']) ]


                if self.scar_data.get('test_results') is not None:
                    #test results parsed
                    
                    if req['cci'].strip() != '':
                        #cci is present
                        
                        if self.scar_data.get('test_results') == 'add':
                            #add option selected, proceed as normal
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            
                        elif self.scar_data.get('test_results') == 'close':
                            #close option selected, inheritted or CCI's not in package will be closed.
                            #non-inheritted controls that are present will proceed as normal
                            
                            if  req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys():
                                #the current cci is not in the implementation plan, map to close
                                comments = f"{ req['cci']}\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being marked as 'Completed' by default. \n\n{comments}"
                                rmf_controls = rmf_controls
                                status = f"{ Utils.status('C', 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"{ req['cci']}\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being marked as completed by default. \n\n{comments}"
                                    rmf_controls = rmf_controls
                                    status = f"{ Utils.status('C', 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        elif self.scar_data.get('test_results') == 'convert':
                            #convert option selected, inheritted or CCI's not in package will be converted to CM-6.5
                            #non-inheritted controls that are present will proceed as normal
                            if  req['cci'].strip().replace('CCI-','').zfill(6) not in self.scar_data.get('test_result_data').keys():
                                #the current cci is not in the implementation plan, map to CM-6.5
                                comments = f"CCI-000366\n\nThis vulnerability is mapped to { req['cci']} {rmf_controls}, however this CCI/AP is not part of the package baseline.  Therefore this requirement is being mapped to CCI-000366 CM-6.5.\n\n{comments}"
                                req['cci'] = 'CCI-000366'
                                rmf_controls = "CM-6.5"
                                status = f"{ Utils.status(req['status'], 'HUMAN') }"
                            else:
                                #the current cci is part of the implementation plan
                            
                                if(
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['implementation'] == 'Inherited' or 
                                    self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited'] != 'Local'
                                ):
                                    #the current cci is marked as inheritted.  Close the requirement
                                    comments = f"CCI-000366\n\nThis vulnerability was originally mapped to { req['cci']} {rmf_controls}, however this CCI/AP is inheritted from {self.scar_data.get('test_result_data')[ req['cci'].strip().replace('CCI-','').zfill(6) ]['inherited']}.  Therefore it is being mapped to CCI-000366 CM-6.5. \n\n{comments}"
                                    req['cci'] = 'CCI-000366'
                                    rmf_controls = "CM-6.5"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                                else:
                                    #the current cci is not marked as inherited.  Process as usual.
                                    rmf_controls = rmf_controls
                                    comments = f"{ req['cci']}\n\n{comments}"
                                    status = f"{ Utils.status(req['status'], 'HUMAN') }"
                        else:
                            #fallthrough catch.  This should never be reached
                            
                            rmf_controls = rmf_controls
                            comments = f"{ req['cci']}\n\n{comments}"
                            status = f"{ Utils.status(req['status'], 'HUMAN') }"
                    else:
                        #no cci present, convert to CM-6.5
                        rmf_controls = 'CM-6.5'
                        req['cci'] = 'CCI-000366'
                        comments = f"{req['cci']}\n\nThe control mapping for this requirement is unavailable so it is being mapped to CCI-000366 CM-6.5 by default. \n\n{comments}"
                        status = f"{ Utils.status(req['status'], 'HUMAN') }"

                else:
                    #test results not submitted, process as usual
                    rmf_controls = rmf_controls
                    comments = f"{ req['cci']}\n\n{comments}"
                    status = f"{ Utils.status(req['status'], 'HUMAN') }"


                # pylint: disable=C0330
                req_data = {
                    'Non-Compliant Security Controls (16a)': rmf_controls,
                    'Affected CCI (16a.1)': req['cci'] if isinstance(req['cci'], str) else '',
                    'Source of Discovery(16a.2)': f"Title: {req['scan_title']}",
                    'Vulnerability ID(16a.3)': f"{req['plugin_id']}{req['rule_id']}",
                    'Vulnerability Description (16.b)': f"Title: {req['req_title']}\n\nFamily: {req['grp_id']}\n\nDescription:\n{req['description']}",
                    'Devices Affected (16b.1)': hosts,
                    'Security Objectives (C-I-A) (16c)': objectives,
                    'Raw Test Result (16d)': Utils.risk_val(req['severity'], 'CAT'),
                    'Predisposing Condition(s) (16d.1)': str( self.scar_data.get('predisposing_conditions') ),
                    'Technical Mitigation(s) (16d.2)': '',
                    'Severity or Pervasiveness (VL-VH) (16d.3)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Relevance of Threat (VL-VH) (16e)': 'High',
                    'Threat Description (16e.1)': req['description'],
                    'Likelihood (Cells 16d.3 & 16e) (VL-VH) (16f)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Impact (VL-VH) (16g)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Impact Description (16h)': '',
                    'Risk (Cells 16f & 16g) (VL-VH) (16i)': Utils.risk_val(req['severity'], 'VL-VH'),
                    'Proposed Mitigations (From POA&M) (16j)': mitigation_statement,
                    'Residual Risk (After Proposed Mitigations) (16k)': Utils.risk_val(str(Utils.clamp((int(Utils.risk_val(req['severity'], 'NUM')) - 1), 0, 3)), 'POAM') if self.scar_data.get('lower_risk') else Utils.risk_val(req['severity'], 'VL-VH'),
                    'Recommendations (16l)': req['solution'],
                    'Comments': f"Status: { status }\n\nGroup ID: {req['grp_id']}\nVuln ID: {req['vuln_id']}\nRule ID: {req['rule_id']}\nPlugin ID: {req['plugin_id']}\n\n{comments}\n\n{finding_details}"
                }
                
                if 'publication_date' not in req:
                    report.append(req_data)
                elif req['publication_date'] is None:
                    report.append(req_data)
                elif( str(req['publication_date']).strip() == '' ):
                    report.append(req_data)
                elif( datetime.datetime.strptime(req['publication_date'],'%Y/%m/%d')  < datetime.datetime.today() - datetime.timedelta(days=self.scar_data.get('exclude_plugins') ) ):
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

    def rpt_software_linux(self):
        """ Generates Linux Software Tab """
        if 'rpt_software_linux' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Generating Linux Software Tab')

        worksheet = self.workbook.add_worksheet('Software - Linux')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Software - Linux' Tab")

        widths = [75, 25, 25, 25, 75]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        software = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?plugin_id == `22869`]  | [*].{ 
                        plugin_id: plugin_id,
                        comments: comments
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            if self.main_window:
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
        if 'rpt_software_windows' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Windows Software Tab')
        worksheet = self.workbook.add_worksheet('Software - Windows')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Software - Windows' Tab")

        widths = [75, 25, 75]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        software = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    requirements: requirements[?plugin_id == `20811`]  | [*].{ 
                        plugin_id: plugin_id,
                        comments: comments
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            if self.main_window:
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
        if 'rpt_asset_traceability' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building Asset Traceability Tab')

        worksheet = self.workbook.add_worksheet('Asset Traceability')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Asset Traceability' Tab")

        widths = [
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25, 25,
            25, 25, 25, 25
            ]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        hardware = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                filename: filename,
                version: version,
                feed: feed,
                policy: policy,
                scan_date: scan_date,
                
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os:os,
                    port_range: port_range,
                    scan_user: scan_user,
                    credentialed: credentialed,
                    scan_details: requirements[?plugin_id == `19506`] | [0].comments
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                if Utils.is_ip(str(host['hostname'])):
                    fqdn_val = (str(host['hostname']))
                elif '.' in str(host['hostname']):
                    fqdn_val = (str(host['hostname']).split('.')[0])
                else:
                    fqdn_val = (str(host['hostname']))
                    
                scan_date = datetime.datetime.strptime(scan['scan_date'], '%a %b %d %H:%M:%S %Y')
                feed = datetime.datetime.strptime(scan['feed'], '%Y%m%d%H%M')
                
                for line in host['scan_details'].split('\n'):
                    if 'Plugin feed version' in line:
                        k,v = line.split(':', 1)
                        try:
                            feed = datetime.datetime.strptime(str(v).strip(), '%Y%m%d%H%M')
                        except:
                            pass
                            
                    if 'Scan Start Date' in line:
                        k,v = line.split(':', 1)
                        try:
                            scan_date = datetime.datetime.strptime( str(v).strip() , '%Y/%m/%d %H:%M %Z')
                        except:
                            pass
                    
                # print(scan_date, feed)

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
                    
                    'ACAS Feed Version'                      : feed.strftime('%Y%m%d%H%M'),
                    'ACAS Scan Start Date'                   : scan_date.strftime('%Y/%m/%d %H:%M %Z'),
                    'ACAS Days Between Plugin Feed And Scan' : (scan_date - feed).days,
                    
                    'STIG CKL File'                      : '',
                    'STIG CKL Version/Release'               : '',
                    'STIG CKL Blank Comments/Findings'       : '',
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
                filename: filename,
                version: version,
                release: release,
                policy: policy,
                scan_date: scan_date,
                scanner_edition: scanner_edition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scan_user,
                credentialed: credentialed,
                error: requirements[]  | [?status == 'E'].[comments, severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in scap_scans:
            if self.main_window:
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
                'STIG CKL Blank Comments/Findings'       : '',
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
                filename: filename,
                version: version,
                release: release,
                policy: policy,
                scan_date: scan_date,
                scanner_edition: scanner_edition,
                hostname: hostname,
                ip: ip,
                os:os,
                scan_user: scan_user,
                credentialed: credentialed,
                blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && finding_details == '')].[comments, severity, status],
                not_reviewed: requirements[]  | [?status == 'NR'].[comments, severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in ckl_scans:
            if self.main_window:
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
                'STIG CKL Blank Comments/Findings'       : len(scan['blank_comments']),
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
        if 'rpt_hardware' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Hardware Tab')

        worksheet = self.workbook.add_worksheet('Hardware')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Hardware' Tab")

        widths = [25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        hardware = []
        hosts = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].hosts[] | [*].{ hostname: hostname, ip: ip, device_type: device_type, manufacturer: manufacturer, model: model, serial: serial, os: os  }",
            { 'results' : scan_results}
        )
        
        for host in acas_scans:
            if self.main_window:
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
            { 'results' : scan_results}
        )
        
        for scan in scap_scans:
            if self.main_window:
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
        if 'rpt_ppsm' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building PPSM Tab')
        worksheet = self.workbook.add_worksheet('PPSM')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'PPSM' Tab")

        widths = [25, 25, 25, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        ports = []
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[?plugin_id == `11219` || plugin_id == `14272`]  | [*].{ 
                        plugin_id: plugin_id,
                        port: port,
                        protocol: protocol,
                        service: service,
                        severity: severity
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
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
        if 'rpt_cci' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building CCI Tab')
        worksheet = self.workbook.add_worksheet('CCI Data')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'CCI Data' Tab")

        widths = [25,25,25,25,25, 25,25,125,125]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        ccis = []

        for cci in self.scar_data.get('data_mapping')['rmf_cci']:
            if self.main_window:
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
        if 'rpt_acas_uniq_vuln' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building ACAS Unique Vuln Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique Vuln')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'ACAS Unique Vuln' Tab")

        widths = [25, 75, 50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [?severity != `0`].{ 
                        plugin_id: plugin_id,
                        title: req_title,
                        grp_id: grp_id,
                        severity: severity
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
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
        if 'rpt_acas_uniq_iava' in self.scar_conf.get('skip_reports'):
            return None
        
        logging.info('Building ACAS Unique IAVA Tab')
        worksheet = self.workbook.add_worksheet('ACAS Unique IAVA')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'ACAS Unique IAVA' Tab")

        widths = [25, 25, 50, 25, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        plugins = []
        plugin_count = {}
        plugins_rpt = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    requirements: requirements[]  | [?iava != '' && severity != `0`].{ 
                        plugin_id: plugin_id,
                        iava: iava,
                        title: req_title,
                        grp_id: grp_id,
                        severity: severity
                    }
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            for host in scan['hosts']:
                if self.main_window:
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
        if 'rpt_missing_patches' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Missing Patches tab')
        worksheet = self.workbook.add_worksheet('Missing Patches')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Missing Patches' Tab")

        widths = [35, 50, 50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        patches = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,

                    requirements: requirements[]  | [?plugin_id == `66334`].{ comments: comments}
                }
            }""",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
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
        if 'rpt_summary' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Summary Tab')
        worksheet = self.workbook.add_worksheet('Summary')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Summary' Tab")

        widths = [
            10,30,20,50,100,
            20,20,20,20,20,
            50,50,20,25,
            10,10,10,10,10,10
        ]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        summary_results = []

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
        disa_scans = jmespath.search(
            """results[?type=='CKL' || type=='SCAP'].{
                type: type,
                
                hostname: hostname,
                ip: ip,
                os: os,
                
                filename: filename,
                scan_date: scan_date,
                duration: duration,
                
                version: version,
                release: release,
                policy: policy,
                
                
                credentialed: credentialed
                scan_user: scan_user,
                
                cati: requirements[]   | [?status != 'C' && severity > `2`].[severity, status],
                catii: requirements[]  | [?status != 'C' && severity == `2`].[severity, status],
                catiii: requirements[] | [?status != 'C' && severity == `1`].[severity, status],
                cativ: requirements[]  | [?status != 'C' && severity == `0`].[severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in disa_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            summary_results.append({
                'Type': scan['type'],
                
                'Hostname': scan['hostname'],
                'IP': scan['ip'],
                'OS': scan['os'],
                
                'Scan File Name': os.path.basename(scan['filename']),
                'Scan Date': scan['scan_date'],
                'Scan Duration': str(reduce(lambda x, y: x*60+y, [int(i) for i in (str(scan['duration'])).split(':')])) + ' sec',
                'Scan To Feed Difference': '',
                'Version': scan['version'],
                'Release': scan['release'],
                'Scan Policy': scan['policy'],
                'Port Range': '',
                
                'Credentialed': scan['credentialed'],
                'Scan User': scan['scan_user'],

                'CAT I': len(scan['cati']),
                'CAT II': len(scan['catii']),
                'CAT III': len(scan['catiii']),
                'CAT IV': len(scan['cativ']),
                'Total': len(scan['cati']) + len(scan['catii']) + len(scan['catiii']) + len(scan['cativ']),
                'Score': 10*len(scan['cati']) + 3*len(scan['catii']) + len(scan['catiii']),
            })

        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                type: type,
                filename: filename,
                scan_date: scan_date,
                version: version,
                feed: feed,
                policy: policy,
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,
                    credentialed: credentialed,
                    scan_user: scan_user,
                    duration: duration,
                    port_range: port_range,
                    
                    cati:   requirements[] | [?status != 'C' && severity > `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catii:  requirements[] | [?status != 'C' && severity == `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catiii: requirements[] | [?status != 'C' && severity == `1`].{ plugin_id: plugin_id, severity: severity, status: status},
                    cativ:  requirements[] | [?status != 'C' && severity == `0`].{ plugin_id: plugin_id, severity: severity, status: status}
                }
            }""",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()

            for host in scan['hosts']:
                summary_results.append({
                    'Type': scan['type'],
                    
                    'Hostname': host['hostname'],
                    'IP': host['ip'],
                    'OS': host['os'],
                    
                    'Scan File Name': os.path.basename(scan['filename']),
                    'Scan Date': scan['scan_date'],
                    'Scan Duration': host['duration'],
                    'Scan To Feed Difference': (
                                datetime.datetime.strptime(scan['scan_date'], '%a %b %d %H:%M:%S %Y') -
                                datetime.datetime.strptime(scan['feed'], '%Y%m%d%H%M')
                            ).days,
                            
                    'Version': scan['version'],
                    'Release': scan['feed'],
                    'Scan Policy': scan['policy'],
                    'Port Range': host['port_range'],

                    'Credentialed': host['credentialed'],
                    'Scan User': host['scan_user'],

                    'CAT I': len(host['cati']),
                    'CAT II': len(host['catii']),
                    'CAT III': len(host['catiii']),
                    'CAT IV': len(host['cativ']),
                    'Total': len(host['cati']) + len(host['catii']) + len(host['catiii']) + len(host['cativ']),
                    'Score': 10*len(host['cati']) + 3*len(host['catii']) + len(host['catiii']),
                    
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
        if 'rpt_raw_data' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Raw Data Tab')
        worksheet = self.workbook.add_worksheet('Raw Data')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Raw Data' Tab")

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

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        raw_results = []
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ type: type, title: title, filename: filename, scan_date: scan_date, version: version, feed: feed, hosts: hosts[] | [*].{ hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ publication_date: publication_date, modification_date : modification_date, comments: comments, grp_id: grp_id, plugin_id: plugin_id, req_title: req_title, severity: severity, status: status, finding_details: finding_details, description: description, solution: solution, fix_id: fix_id, references: references, resources: resources } } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
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
                            'grp_id'             : req['grp_id'],
                            'vuln_id'            : '',
                            'rule_id'            : '',
                            'plugin_id'          : req['plugin_id'],
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
                            'fix_id'             : req['fix_id'],
                            'References'        : req['references'][0:32760],
                            'Resources'         : req['resources'],
                            'Comments'          : '',
                        })

        disa_scans = jmespath.search(
            "results[?type=='CKL' || type=='SCAP'].{ type: type, title: title, filename: filename, scan_date: scan_date, version: version, release: release, hostname: hostname, ip : ip, credentialed: credentialed, requirements: requirements[] | [*].{ comments: comments, grp_id: grp_id, plugin_id: plugin_id, req_title: req_title, severity: severity, status: status, finding_details: finding_details, description: description, solution: solution, fix_id: fix_id, references: references, resources: resources, cci: cci, assessments: assessments, rmf_controls: rmf_controls, ia_controls: ia_controls, rule_id: rule_id, vuln_id: vuln_id } }",
            { 'results' : scan_results}
        )

        for scan in disa_scans:
            if self.main_window:
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
                        'grp_id'             : req['grp_id'],
                        'vuln_id'            : req['vuln_id'],
                        'rule_id'            : req['rule_id'],
                        'plugin_id'          : req['plugin_id'],
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
                        'fix_id'             : req['fix_id'],
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
        if 'rpt_operating_systems' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building OS Tab')
        worksheet = self.workbook.add_worksheet('Operating Systems')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Operating Systems' Tab")

        widths = [50, 25, 25]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        os_list = []
        
        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
            
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ os: os } }",
            { 'results' : scan_results}
        )
        for scan in acas_scans:
            if self.main_window:
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
        if 'rpt_local_users' in self.scar_conf.get('skip_reports'):
            return None
            
        logging.info('Building Local Users Tab')
        worksheet = self.workbook.add_worksheet('Local Users')
        if self.main_window:
            self.main_window.statusBar().showMessage("Generating 'Local Users' Tab")

        widths = [50,50,50]
        ascii = string.ascii_uppercase
        for index, w in enumerate(widths):
            worksheet.set_column("{}:{}".format( ascii[index], ascii[index]), w)

        worksheet.autofilter(0, 0, 0, int(len(widths))-1)

        with open(os.path.join(self.scar_conf.get('application_path'), "data", "scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)
            
        users = []
        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `10860`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'- ([_a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })


        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `126527`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
                QtGui.QGuiApplication.processEvents()
            for host in scan['hosts']:
                for req in host['requirements']:
                    for user in re.findall(r'- ([_a-zA-Z0-9]+)+', req):
                        users.append({
                            'Host': host['hostname'] if host['hostname'].strip() != '' else host['ip'],
                            'OS': host['os'],
                            'User': user
                        })


        acas_scans = jmespath.search(
            "results[?type=='ACAS'].{ hosts: hosts[] | [*].{ hostname: hostname, os: os, requirements: requirements[?plugin_id == `95928`] | [*].comments } }",
            { 'results' : scan_results}
        )

        for scan in acas_scans:
            if self.main_window:
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
