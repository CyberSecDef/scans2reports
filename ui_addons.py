from PyQt5 import QtCore, QtGui, QtWidgets
import os.path
import re
import sys

import os
import platform
import subprocess

import time
import pprint
import dumper
import logging
import psutil
import jmespath
import pickle
from functools import partial
from utils import Utils
from scan_utils import ScanUtils
from scar_enums import TestResultOptions

class QNumericTableWidgetItem (QtWidgets.QTableWidgetItem):
    def __init__ (self, value):
        super(QNumericTableWidgetItem, self).__init__(value)

    def __lt__ (self, other):
        if (isinstance(other, QNumericTableWidgetItem)):
            selfDataValue  = float(re.sub(r'[^0-9\-\.]', '', str(self.text())))
            otherDataValue = float(re.sub(r'[^0-9\-\.]', '', str(other.text())))
            return selfDataValue < otherDataValue
        else:
            return QtWidgets.QTableWidgetItem.__lt__(self, other)

    def __rt__ (self, other):
        if (isinstance(other, QNumericTableWidgetItem)):
            selfDataValue  = float(re.sub(r'[ $]', '', str(self.text())))
            otherDataValue = float(re.sub(r'[ $]', '', str(other.text())))
            return selfDataValue > otherDataValue
        else:
            return QtWidgets.QTableWidgetItem.__lt__(self, other)

class UiAddons():
    main_form = None
    main_app = None
    tbl_selected_scans_sort_col = 0
    tbl_selected_scans_sort_order = 0
    tbl_scan_summary_sort_col = 0
    tbl_scan_summary_sort_order = 0

    def __init__(self,main_app, main_form):
        self.main_form = main_form
        self.main_app = main_app
        self.main_form.tbl_selected_scans.horizontalHeader().setSortIndicatorShown(True)
        self.main_form.tbl_scan_summary.horizontalHeader().setSortIndicatorShown(True)
        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename='{self.main_app.application_path}/scans2reports.log', level=logging.INFO, format=FORMAT)

    def update_form_values(self):
        self.main_form.spnExcludeDays.setValue( self.main_app.scar_conf.get('exclude_plugins') )
        
        self.main_form.chkSkipInfo.setChecked( self.main_app.scar_conf.get('skip_info') )
        self.main_form.chk_lower_risk.setChecked( self.main_app.scar_conf.get('lower_risk') )
        self.main_form.chk_prefill_scd.setChecked( self.main_app.scar_conf.get('scd') )
        self.main_form.chkIncludeFindingDetails.setChecked( self.main_app.scar_conf.get('include_finding_details') )
            
        if self.main_app.scar_conf.get('test_results') == 'add':
            self.main_form.cboTestResultFunc.setCurrentIndex(0)
        elif self.main_app.scar_conf.get('test_results') == 'close':
            self.main_form.cboTestResultFunc.setCurrentIndex(1)
        elif self.main_app.scar_conf.get('test_results') == 'convert':
            self.main_form.cboTestResultFunc.setCurrentIndex(2)
        
        if self.main_app.scar_conf.get('mitigation_statements') == 'blank':
            self.main_form.cboMitigationStatements.setCurrentIndex(0)
        elif self.main_app.scar_conf.get('mitigation_statements') == 'poam':
            self.main_form.cboMitigationStatements.setCurrentIndex(1)
        elif self.main_app.scar_conf.get('mitigation_statements') == 'ckl':
            self.main_form.cboMitigationStatements.setCurrentIndex(2)
        elif self.main_app.scar_conf.get('mitigation_statements') == 'both':
            self.main_form.cboMitigationStatements.setCurrentIndex(3)
        
        if self.main_app.scar_conf.get('threads') == 1:
            self.main_form.cboProcIntensity.setCurrentIndex(1)
        elif self.main_app.scar_conf.get('threads') == 2:
            self.main_form.cboProcIntensity.setCurrentIndex(0)
        else:
            self.main_form.cboProcIntensity.setCurrentIndex(2)
        
        self.main_form.txtPredisposingCondition.setPlainText( self.main_app.scar_conf.get('predisposing_conditions') )


    def btn_select_scan_files_on_click(self):
        logging.info('Select Scan Files Clicked')
        options = QtWidgets.QFileDialog.Options()
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"QFileDialog.getOpenFileNames()", "","All Files (*);;", options=options)
        if files:
            filepaths = []
            for row in range(self.main_form.tbl_selected_scans.rowCount()):
                cell_widget = self.main_form.tbl_selected_scans.item(row, 1)
                if cell_widget:
                    filepaths.append(cell_widget.data(QtCore.Qt.UserRole))

            for file in files:
                filepath = str(file)
                extension = os.path.splitext(filepath)[1].lower()

                if filepath not in filepaths:
                    if extension in ['.ckl', '.xml', '.nessus', '.csv', '.xlsx']:
                        logging.info('Adding file to queue: %s', filepath)
                        self.main_form.tbl_selected_scans.insertRow(0)

                        item = QtWidgets.QTableWidgetItem( os.path.basename( filepath ))
                        item.setData(QtCore.Qt.UserRole, filepath)
                        self.main_form.tbl_selected_scans.setItem(0, 1, item)

                        self.main_form.tbl_selected_scans.setItem(0, 2, QtWidgets.QTableWidgetItem( time.strftime( '%Y-%m-%d %H:%M:%S', time.gmtime( os.path.getmtime( filepath ))) ) )
                        self.main_form.tbl_selected_scans.setItem(0, 3, QNumericTableWidgetItem( QtWidgets.QTableWidgetItem( str( os.path.getsize( filepath ))) ) )
                        self.main_form.tbl_selected_scans.setItem(0, 4, QtWidgets.QTableWidgetItem( extension ))

                        self.main_form.tbl_selected_scans.resizeColumnsToContents()
                        self.main_form.tbl_selected_scans.horizontalHeader().setStretchLastSection(True)

    def btn_parse_scan_files_on_click(self):
        self.main_form.btn_parse_scan_files.setEnabled(False)
        self.main_app.main_window.statusBar().showMessage('Parsing Files... Please Wait')
        QtGui.QGuiApplication.processEvents() 
        
        self.main_app.scar_data.set('command', self.main_form.txt_command.text() )
        self.main_app.scar_data.set('name', self.main_form.txt_poc.text() )
        self.main_app.scar_data.set('phone', self.main_form.txt_phone.text() )
        self.main_app.scar_data.set('email', self.main_form.txt_email.text() )
        
        self.main_app.scar_conf.set('predisposing_conditions', self.main_form.txtPredisposingCondition.toPlainText())
        self.main_app.scar_conf.set('include_finding_details', self.main_form.chkIncludeFindingDetails.isChecked())
        self.main_app.scar_conf.set('skip_info', self.main_form.chkSkipInfo.isChecked())
        self.main_app.scar_conf.set('scd', self.main_form.chk_prefill_scd.isChecked())
        self.main_app.scar_conf.set('lower_risk', self.main_form.chk_lower_risk.isChecked())
        self.main_app.scar_conf.set('exclude_plugins', self.main_form.spnExcludeDays.value())
        self.main_app.scar_conf.set('test_results',  {
                'Add All Findings' : 'add',
                'Mark as Closed' : 'close',
                'Convert to CM-6.5' : 'convert'
            }[self.main_form.cboTestResultFunc.currentText()] )
            
        self.main_app.scar_conf.set('mitigation_statements',  {
                'Leave Blank' : 'blank',
                'Existing POAM or Answerfile CSV' : 'poam',
                'CKL Comments' : 'ckl',
                'POAM/CSV, then CKL (Prefer Existing POAM/CSV)' : 'both'
            }[self.main_form.cboMitigationStatements.currentText()] )
            
        self.main_app.scar_conf.set('num_threads', 1)
        self.main_app.scar_conf.set('threads', 1)
        if self.main_form.cboProcIntensity.currentText() == 'Light Load':
            self.main_app.scar_conf.set('num_threads', int(psutil.cpu_count() // 2) + 1)
            self.main_app.scar_conf.set('threads', 1)
        elif self.main_form.cboProcIntensity.currentText() == 'Normal Load':
            self.main_app.scar_conf.set('num_threads', int(psutil.cpu_count()) - 2 + 1)
            self.main_app.scar_conf.set('threads', 2)
        else:
            self.main_app.scar_conf.set('num_threads', int(psutil.cpu_count() * 2) - 1)
            self.main_app.scar_conf.set('threads', 3)
            
        if self.main_app.scar_conf.get('num_threads') <= 0:
            self.main_app.scar_conf.set('num_threads', 1)
            self.main_app.scar_conf.set('threads', 1)
                
        logging.info('Parse Scan Files Clicked')
        self.main_form.tbl_scan_summary.setRowCount(0)

        filepaths = []
        for row in range(self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 1)
            if cell_widget:
                filepaths.append(cell_widget.data(QtCore.Qt.UserRole))
                if 'xccdf' in cell_widget.data(QtCore.Qt.UserRole).lower() and '.xml' in cell_widget.data(QtCore.Qt.UserRole).lower():
                    self.main_form.chk_rar.setChecked(True)                
                    self.main_form.chk_operating_systems.setChecked(True)
                    self.main_form.chk_cci.setChecked(True)
                    self.main_form.chk_poam.setChecked(True)
                    self.main_form.chk_hardware.setChecked(True)
                    self.main_form.chk_asset_traceability.setChecked(True)
                    self.main_form.chk_raw_data.setChecked(True)
                    self.main_form.chk_summary.setChecked(True)
                    self.main_form.chk_test_plan.setChecked(True)
                
                if  '.ckl' in cell_widget.data(QtCore.Qt.UserRole).lower():
                    self.main_form.chk_rar.setChecked(True)                
                    self.main_form.chk_cci.setChecked(True)
                    self.main_form.chk_poam.setChecked(True)
                    self.main_form.chk_hardware.setChecked(True)
                    self.main_form.chk_asset_traceability.setChecked(True)
                    self.main_form.chk_raw_data.setChecked(True)
                    self.main_form.chk_summary.setChecked(True)
                    self.main_form.chk_test_plan.setChecked(True)
                    
                if  '.nessus' in cell_widget.data(QtCore.Qt.UserRole).lower():
                    self.main_form.chk_rar.setChecked(True)                
                    self.main_form.chk_operating_systems.setChecked(True)
                    self.main_form.chk_cci.setChecked(True)
                    self.main_form.chk_local_users.setChecked(True)
                    self.main_form.chk_software_windows.setChecked(True)
                    self.main_form.chk_poam.setChecked(True)
                    self.main_form.chk_missing_patches.setChecked(True)
                    self.main_form.chk_hardware.setChecked(True)
                    self.main_form.chk_acas_unique_vuln.setChecked(True)
                    self.main_form.chk_acas_unique_iavm.setChecked(True)
                    self.main_form.chk_ppsm.setChecked(True)
                    self.main_form.chk_asset_traceability.setChecked(True)
                    self.main_form.chk_software_linux.setChecked(True)
                    self.main_form.chk_raw_data.setChecked(True)
                    self.main_form.chk_summary.setChecked(True)
                    self.main_form.chk_test_plan.setChecked(True)
                
        self.main_app.scan_files = filepaths
        self.main_app.scan_results = [{} for x in self.main_app.scan_files]
        
        self.main_app.parse_scan_files()
        
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
        with open(os.path.join(application_path, "data/scan_results.pkl"), "rb") as f:
            scan_results = pickle.load(f)

        total_files = len(scan_results)
        self.main_form.tbl_scan_summary.setRowCount(1000)
        currentRow = 0
        
        acas_scans = jmespath.search(
            """results[?type=='ACAS'].{
                type: type,
                filename: filename,
                scan_date: scan_date,
                version: version,
                feed: feed,
                hosts: hosts[] | [*].{
                    hostname: hostname,
                    ip: ip,
                    os: os,
                    credentialed: credentialed,

                    cati:   requirements[] | [?status != 'C' && severity > `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catii:  requirements[] | [?status != 'C' && severity == `2`].{ plugin_id: plugin_id, severity: severity, status: status},
                    catiii: requirements[] | [?status != 'C' && severity == `1`].{ plugin_id: plugin_id, severity: severity, status: status},
                    cativ:  requirements[] | [?status != 'C' && severity == `0`].{ plugin_id: plugin_id, severity: severity, status: status},

                    blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && finding_details == '')].{ plugin_id: plugin_id, severity: severity, status: status}
                }
            }""",
            { 'results' : scan_results}
        )
        
        for scan in acas_scans:
            logging.info('Adding file to Processed List: %s', scan['filename'])
            for host in scan['hosts']:
                
                self.main_form.tbl_scan_summary.setItem(currentRow, 0, QtWidgets.QTableWidgetItem( scan['type'] ))
                self.main_form.tbl_scan_summary.setItem(currentRow, 1, QtWidgets.QTableWidgetItem( host['hostname'] ))
                self.main_form.tbl_scan_summary.setItem(currentRow, 2, QtWidgets.QTableWidgetItem( host['ip'] ))
                self.main_form.tbl_scan_summary.setItem(currentRow, 3, QtWidgets.QTableWidgetItem( host['os'] ))

                self.main_form.tbl_scan_summary.setItem(currentRow, 4, QtWidgets.QTableWidgetItem( os.path.basename( scan['filename'] )))

                self.main_form.tbl_scan_summary.setItem(currentRow, 5, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(host['cati'])) ) ) )
                self.main_form.tbl_scan_summary.setItem(currentRow, 6, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(host['catii'])) ) ) )
                self.main_form.tbl_scan_summary.setItem(currentRow, 7, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(host['catiii'])) ) ) )
                self.main_form.tbl_scan_summary.setItem(currentRow, 8, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(host['cativ'])) ) ) )

                self.main_form.tbl_scan_summary.setItem(currentRow, 9, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(int( len(host['cati']) + len(host['catii']) + len(host['catiii']) + len(host['cativ']) )) ) ) )
                self.main_form.tbl_scan_summary.setItem(currentRow, 10, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(int( 10*len(host['cati']) + 3*len(host['catii']) + len(host['catiii']) )) ) ) )
                self.main_form.tbl_scan_summary.setItem(currentRow, 11, QtWidgets.QTableWidgetItem( str(host['credentialed'] )))

                currentRow += 1
                if currentRow >= self.main_form.tbl_scan_summary.rowCount():
                    self.main_form.tbl_scan_summary.setRowCount(self.main_form.tbl_scan_summary.rowCount() + 1000)

        disa_scans = jmespath.search(
            """results[?type=='CKL' || type=='SCAP'].{
                type: type,
                hostname: hostname,
                ip: ip,
                os: os,
                filename: filename,
                credentialed: credentialed
                scan_date: scan_date,
                version: version,
                release: release,
                
                cati: requirements[]   | [?status != 'C' && severity > `2`].[comments, severity, status],
                catii: requirements[]  | [?status != 'C' && severity == `2`].[comments, severity, status],
                catiii: requirements[] | [?status != 'C' && severity == `1`].[comments, severity, status],
                cativ: requirements[]  | [?status != 'C' && severity == `0`].[comments, severity, status],
                
                blank_comments: requirements[]  | [?status != 'C' && ( comments == '' && finding_details == '')].[comments, severity, status]
            }""",
            { 'results' : scan_results}
        )

        for scan in disa_scans:
            logging.info('Adding file to Processed List: %s', scan['filename'])

            self.main_form.tbl_scan_summary.setItem(currentRow, 0, QtWidgets.QTableWidgetItem( scan['type'] ))
            self.main_form.tbl_scan_summary.setItem(currentRow, 1, QtWidgets.QTableWidgetItem( scan['hostname'] ))
            self.main_form.tbl_scan_summary.setItem(currentRow, 2, QtWidgets.QTableWidgetItem( scan['ip'] ))
            self.main_form.tbl_scan_summary.setItem(currentRow, 3, QtWidgets.QTableWidgetItem( scan['os'] ))

            self.main_form.tbl_scan_summary.setItem(currentRow, 4, QtWidgets.QTableWidgetItem( os.path.basename( scan['filename'] )))

            self.main_form.tbl_scan_summary.setItem(currentRow, 5, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(scan['cati'])) ) ) )
            self.main_form.tbl_scan_summary.setItem(currentRow, 6, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(scan['catii']))) ) )
            self.main_form.tbl_scan_summary.setItem(currentRow, 7, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(scan['catiii']))) ) )
            self.main_form.tbl_scan_summary.setItem(currentRow, 8, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(len(scan['cativ']))) ) )

            self.main_form.tbl_scan_summary.setItem(currentRow, 9, QtWidgets.QTableWidgetItem(  str(int( len(scan['cati']) + len(scan['catii']) + len(scan['catiii']) + len(scan['cativ']) ) ) ) ) 
            self.main_form.tbl_scan_summary.setItem(currentRow, 10, QtWidgets.QTableWidgetItem( str(int( 10*len(scan['cati']) + 3*len(scan['catii']) + len(scan['catiii']) ) ) ) )
            self.main_form.tbl_scan_summary.setItem(currentRow, 11, QtWidgets.QTableWidgetItem( str(scan['credentialed'] )))
            currentRow += 1
            if currentRow >= self.main_form.tbl_scan_summary.rowCount():
                    self.main_form.tbl_scan_summary.setRowCount(self.main_form.tbl_scan_summary.rowCount() + 1000)


        self.main_form.tbl_scan_summary.setRowCount(currentRow + 1)
        self.main_form.tbl_scan_summary.resizeColumnsToContents()
        self.main_form.tbl_scan_summary.horizontalHeader().setStretchLastSection(True)
        self.main_form.btn_parse_scan_files.setEnabled(True)

    def merge_nessus(self, host_count):
        logging.info('Merge Nessus Clicked')

        options = QtWidgets.QFileDialog.Options(  )
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"Select Multiple Nessus Files to Merge", "","Nessus Files (*.nessus);;", options=options)
        if files:
            ScanUtils.merge_nessus_files(files, host_count, self.main_app)

    def split_nessus(self):
        logging.info('Split Nessus Clicked')

        options = QtWidgets.QFileDialog.Options()
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"Select Nessus Files to Split", "","Nessus Files (*.nessus);;", options=options)
        if files:
            filepaths = []
            for file in files:
                logging.info('Splitting {}'.format(file))
                print('Splitting {}'.format(file))
                ScanUtils.split_nessus_file(file, self.main_app)

    def open_results(self):
        path = os.path.join( self.main_app.scar_conf.get('application_path') , "results")
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    
    
    def update_ckl(self):
        logging.info('Update CKL Clicked')

        options = QtWidgets.QFileDialog.Options()
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"Select Source .CKL File", "","STIG Checklist (*.ckl);;", options=options)
        if files:
            source = files[0]
            
        options = QtWidgets.QFileDialog.Options()
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"Select Destination .CKL File", "","STIG Checklist (*.ckl);;", options=options)
        if files:
            destination = files[0]
            
        if source is not None and destination is not None:
            ScanUtils.update_ckl(source, destination, self.main_app)
                
                
    def btn_execute_on_click(self):
        self.main_form.btn_execute.setEnabled(False)
        self.main_app.main_window.statusBar().showMessage('Generating Reports... Please Wait')
        QtGui.QGuiApplication.processEvents() 
        logging.info('Execute Clicked')
        self.main_app.scar_data.set('command', self.main_form.txt_command.text() )
        self.main_app.scar_data.set('name', self.main_form.txt_poc.text() )
        self.main_app.scar_data.set('phone', self.main_form.txt_phone.text() )
        self.main_app.scar_data.set('email', self.main_form.txt_email.text() )

        self.main_app.scar_conf.set('predisposing_conditions', self.main_form.txtPredisposingCondition.toPlainText())
        self.main_app.scar_conf.set('include_finding_details', self.main_form.chkIncludeFindingDetails.isChecked())
        self.main_app.scar_conf.set('skip_info', self.main_form.chkSkipInfo.isChecked())
        self.main_app.scar_conf.set('scd', self.main_form.chk_prefill_scd.isChecked())
        self.main_app.scar_conf.set('lower_risk', self.main_form.chk_lower_risk.isChecked())
        self.main_app.scar_conf.set('exclude_plugins', self.main_form.spnExcludeDays.value())
        self.main_app.scar_conf.set('test_results',  {
                'Add All Findings' : 'add',
                'Mark as Closed' : 'close',
                'Convert to CM-6.5' : 'convert'
            }[self.main_form.cboTestResultFunc.currentText()] )
            
        self.main_app.scar_conf.set('mitigation_statements',  {
                'Leave Blank' : 'blank',
                'Existing POAM or Answerfile CSV' : 'poam',
                'CKL Comments' : 'ckl',
                'POAM/CSV, then CKL (Prefer Existing POAM/CSV)' : 'both'
            }[self.main_form.cboMitigationStatements.currentText()] )
            
        if not self.main_form.chk_acas_unique_iavm.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_acas_uniq_iavm')

        if not self.main_form.chk_acas_unique_vuln.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_acas_uniq_vuln')

        if not self.main_form.chk_asset_traceability.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_asset_traceability')

        if not self.main_form.chk_cci.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_cci')

        if not self.main_form.chk_hardware.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_hardware')

        if not self.main_form.chk_local_users.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_local_users')

        if not self.main_form.chk_missing_patches.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_missing_patches')

        if not self.main_form.chk_operating_systems.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_operating_systems')

        if not self.main_form.chk_poam.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_poam')

        if not self.main_form.chk_ppsm.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_ppsm')

        if not self.main_form.chk_rar.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_rar')

        if not self.main_form.chk_raw_data.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_raw_data')

        if not self.main_form.chk_scap_ckl_issues.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_scap_ckl_issues')

        if not self.main_form.chk_software_linux.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_software_linux')

        if not self.main_form.chk_software_windows.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_software_windows')

        if not self.main_form.chk_summary.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_summary')

        if not self.main_form.chk_test_plan.isChecked():
            self.main_app.scar_conf.append('skip_reports','rpt_test_plan')

        self.main_app.generate_reports()
        self.main_form.btn_execute.setEnabled(True)

    def show_about(self):
        logging.info('About Shown')
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle("About Scans To Reports")
        msg.setText("Scans To Reports - Python Edition\nVersion 1.0\nCopyright (C) 2020 - Robert Weber\nhttps://cyber.trackr.live")
        x = msg.exec_()

    def show_help(self):
        logging.info('Help Shown')
        msg = QtWidgets.QMessageBox()
        msg.setWindowTitle("Scans To Reports - Help")
        msg.setText("""
The Scans To Report Generator parses selected scan results and generates an XLSX file for package management.
This XLSX file includes tabs for an eMASS compatible POAM, Open Findings, Missing Patches and several other key Cyber details.
To utilize the tool, follow the steps below:

1 - Fill out the 'Report Data Points' if applicable to the POAM you are generating.
2 - If the Scheduled Completion Date should be pre-filled, ensure the checkbox is checked.
3 - If the risk should automatically be lowered due to mitigations, ensure the lower risk checkbox is checked.
4 - Drop your selected scan files (ACAS, CKL and SCAP) on the blue area, or click the 'Select Scan Files' button.
5 - Once all your scans are selected, click on the green 'Parse Scan Files' button.
6 - Once all the scans are parsed, click on the red 'Generate Report' button.
7 - Once complete, your new file will be in the 'results' folder.
""")
        x = msg.exec_()


    def sort_tbl_selected_scans(self, val):
        if self.tbl_selected_scans_sort_col == val:
            if self.tbl_selected_scans_sort_order == 0:
                self.tbl_selected_scans_sort_order = 1
            else:
                self.tbl_selected_scans_sort_order = 0
        else:
            self.tbl_selected_scans_sort_col = val
            self.tbl_selected_scans_sort_order = 1
        self.main_form.tbl_selected_scans.sortByColumn(self.tbl_selected_scans_sort_col, self.tbl_selected_scans_sort_order)

    def sort_tbl_scan_summary(self, val):
        if self.tbl_scan_summary_sort_col == val:
            if self.tbl_scan_summary_sort_order == 0:
                self.tbl_scan_summary_sort_order = 1
            else:
                self.tbl_scan_summary_sort_order = 0
        else:
            self.tbl_scan_summary_sort_col = val
            self.tbl_scan_summary_sort_order = 1

        self.main_form.tbl_scan_summary.sortByColumn(self.tbl_scan_summary_sort_col, self.tbl_scan_summary_sort_order)

    def btn_clear_selected_scans_on_click(self):
        self.main_form.tbl_selected_scans.setRowCount(0)
        self.main_form.tbl_selected_scans.setRowCount(1)
        
        self.main_form.tbl_scan_summary.setRowCount(0)
        self.main_form.tbl_scan_summary.setRowCount(1)
        
        self.main_app.scan_files = []
        self.main_app.scan_results = []
        
        self.main_app.parse_scan_files()
        
        
    def btn_clear_scan_summary_on_click(self):
        
        self.main_form.tbl_scan_summary.setRowCount(0)
        self.main_form.tbl_scan_summary.setRowCount(1)
        
        self.main_app.scan_files = []
        self.main_app.scan_results = []
        
        self.main_app.parse_scan_files()
    
    def connect_events(self):
        logging.info('Connecting Events')
        self.main_form.btn_parse_scan_files.clicked.connect(self.btn_parse_scan_files_on_click)
        self.main_form.btnClearSelectedScans.clicked.connect(self.btn_clear_selected_scans_on_click)
        
        self.main_form.btn_execute.clicked.connect(self.btn_execute_on_click)
        self.main_form.btn_select_scan_files.clicked.connect(self.btn_select_scan_files_on_click)

        self.main_form.btnClearScanSummary.clicked.connect(self.btn_clear_scan_summary_on_click)


        self.main_form.tbl_selected_scans.horizontalHeader().sectionClicked.connect(self.sort_tbl_selected_scans)
        self.main_form.tbl_scan_summary.horizontalHeader().sectionClicked.connect(self.sort_tbl_scan_summary)


        self.main_form.action5_Hosts.triggered.connect( partial( self.merge_nessus, 5) )
        self.main_form.action10_Hosts.triggered.connect( partial(self.merge_nessus, 10) )
        self.main_form.action15_Hosts.triggered.connect( partial(self.merge_nessus, 15) )
        self.main_form.action25_Hosts.triggered.connect( partial(self.merge_nessus, 25) )
        self.main_form.action50_Hosts.triggered.connect( partial(self.merge_nessus, 50) )
        self.main_form.actionAll_Hosts.triggered.connect( partial(self.merge_nessus, 0) )

        self.main_form.actionSplit_Nessus.triggered.connect( self.split_nessus )        
        
        self.main_form.actionUpdate_CKL.triggered.connect( self.update_ckl )
        
        self.main_form.actionOpen_Results.triggered.connect( self.open_results )
        
        
        
        self.main_form.actionAbout.triggered.connect( self.show_about )
        self.main_form.actionHelp.triggered.connect( self.show_help )

        self.main_form.actionSelect.triggered.connect( self.btn_select_scan_files_on_click )
        self.main_form.actionParse_Scans.triggered.connect( self.btn_parse_scan_files_on_click )
        self.main_form.actionExecute.triggered.connect( self.btn_execute_on_click )
        self.main_form.actionExit.triggered.connect( QtCore.QCoreApplication.quit)

    def update_summary_headers(self):
        logging.info('Updating Summary Headers')
        self.main_form.tbl_scan_summary.setRowCount(1)
        self.main_form.tbl_scan_summary.setColumnCount(12)
        self.main_form.tbl_scan_summary.setHorizontalHeaderLabels(['Type', 'Hostname', 'IP','OS', 'Scan File Name', 'CAT I', 'CAT II', 'CAT III', 'CAT IV', 'Total', 'Score',' Credentialed'])
        self.main_form.tbl_scan_summary.resizeColumnsToContents()
        self.main_form.tbl_scan_summary.horizontalHeader().setStretchLastSection(True)


    def update_scan_headers(self):
        logging.info('Updating Scan Headers')
        self.main_form.tbl_selected_scans.setRowCount(1)
        self.main_form.tbl_selected_scans.setColumnCount(5)
        self.main_form.tbl_selected_scans.setHorizontalHeaderLabels(['Action', 'Name', 'Created', 'Size','File Type'])
        self.main_form.tbl_selected_scans.resizeColumnsToContents()
        self.main_form.tbl_selected_scans.horizontalHeader().setStretchLastSection(True)

class ScanSelect(QtWidgets.QTableWidget):

    def __init__(self, parent):
        super(ScanSelect, self).__init__(parent)
        self.destroy()

    def contextMenuEvent(self, event):
        dumper.dump(event)
        contextMenu = QtWidgets.QMenu(self)
        newAct = contextMenu.addAction("New")
        openAct = contextMenu.addAction("Open")
        quitAct = contextMenu.addAction("Quit")
        action = contextMenu.exec_(self.mapToGlobal(event.pos()))
        if action == quitAct:
            self.close()

class FileDrop(QtWidgets.QLabel):
    parent = None
    main_form = None

    def __init__(self, parent, main_form):
        super(FileDrop, self).__init__(parent)
        self.parent = parent
        self.main_form = main_form
        # self.setDragEnabled(True)

    def dragEnterEvent(self, event):
        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() == 'file':
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() == 'file':
            event.acceptProposedAction()

    def del_act(self, filepath):
        for row in range(self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 1)

    def remove_row(self):
        self.main_form.tbl_selected_scans.removeRow(self.main_form.tbl_selected_scans.currentRow())

    def dropEvent(self, event):
        filepaths = []
        # get existing file paths
        for row in range(0, self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 1)
            if cell_widget:
                filepaths.append(cell_widget.data(QtCore.Qt.UserRole))

        # add new files that aren't in list
        data = event.mimeData()
        if data:
            urls = data.urls()
            if urls and urls[0].scheme() == 'file':
                for url in urls:
                    filepath = str(url.path())[1:]
                    if filepath not in filepaths:
                        filepaths.append(filepath)

        # preset row count in table
        self.main_form.tbl_selected_scans.setRowCount(0)
        total_files = len(filepaths)
        self.main_form.tbl_selected_scans.setRowCount(total_files)

        current_row = 0
        for filepath in filepaths:
            extension = os.path.splitext(filepath)[1].lower()
            if extension in ['.ckl', '.xml', '.nessus', '.xlsx', '.csv']:
                btn = QtWidgets.QPushButton(self.main_form.tbl_selected_scans)
                btn.setText('Del')
                btn.clicked.connect(self.remove_row)
                self.main_form.tbl_selected_scans.setCellWidget(current_row, 0,  btn )

                item = QtWidgets.QTableWidgetItem( os.path.basename( filepath ))
                item.setData(QtCore.Qt.UserRole, filepath)
                self.main_form.tbl_selected_scans.setItem(current_row, 1, item)
                self.main_form.tbl_selected_scans.setItem(current_row, 2, QtWidgets.QTableWidgetItem( time.strftime( '%Y-%m-%d %H:%M:%S', time.gmtime( os.path.getmtime( filepath ))) ) )
                self.main_form.tbl_selected_scans.setItem(current_row, 3, QNumericTableWidgetItem( QtWidgets.QTableWidgetItem( str( os.path.getsize( filepath ))) ) )
                self.main_form.tbl_selected_scans.setItem(current_row, 4, QtWidgets.QTableWidgetItem( extension ))
                current_row += 1

        self.main_form.tbl_selected_scans.resizeColumnsToContents()
        self.main_form.tbl_selected_scans.horizontalHeader().setStretchLastSection(True)
