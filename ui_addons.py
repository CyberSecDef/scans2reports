from PyQt5 import QtCore, QtGui, QtWidgets
import os.path
import re
import time
import pprint
import dumper
import logging
from functools import partial
            
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
            print(selfDataValue, otherDataValue)
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
        FORMAT = "[%(asctime)s | %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
        logging.basicConfig(filename='scans2reports.log', level=logging.INFO, format=FORMAT)
        self.main_form = main_form
        self.main_app = main_app
        self.main_form.tbl_selected_scans.horizontalHeader().setSortIndicatorShown(True)
        self.main_form.tbl_scan_summary.horizontalHeader().setSortIndicatorShown(True)

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
                    if extension in ['.ckl', '.xml', '.nessus']:
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
        logging.info('Parse Scan Files Clicked')
        self.main_form.tbl_scan_summary.setRowCount(0)
        
        filepaths = []
        for row in range(self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 1)
            if cell_widget:
                filepaths.append(cell_widget.data(QtCore.Qt.UserRole))
        self.main_app.scan_files = filepaths
        self.main_app.scan_results = [{} for x in self.main_app.scan_files]
        self.main_app.parse_scan_files()
        
        # print( self.main_app.scan_results )
        for scan_result in self.main_app.scan_results:
            logging.info('Adding file to Processed List: %s', scan_result['fileName'])
            if scan_result['type'] == 'ACAS':
                for host in scan_result['hosts']:
                    self.main_form.tbl_scan_summary.insertRow(0)
                    
                    self.main_form.tbl_scan_summary.setItem(0, 0, QtWidgets.QTableWidgetItem( scan_result['type'] ))
                    self.main_form.tbl_scan_summary.setItem(0, 1, QtWidgets.QTableWidgetItem( host['hostname'] ))
                    self.main_form.tbl_scan_summary.setItem(0, 2, QtWidgets.QTableWidgetItem( host['ip'] ))
                    self.main_form.tbl_scan_summary.setItem(0, 3, QtWidgets.QTableWidgetItem( host['os'] ))
                    
                    self.main_form.tbl_scan_summary.setItem(0, 4, QtWidgets.QTableWidgetItem( os.path.basename( scan_result['fileName'] )))
                    
                    self.main_form.tbl_scan_summary.setItem(0, 5, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(host['catI']).strip() or 0 ) )) ) )
                    self.main_form.tbl_scan_summary.setItem(0, 6, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(host['catII']).strip() or 0 ) )) ) )
                    self.main_form.tbl_scan_summary.setItem(0, 7, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(host['catIII']).strip() or 0 ) )) ) )
                    self.main_form.tbl_scan_summary.setItem(0, 8, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(host['catIV']).strip() or 0 ) )) ) )
                    
                    self.main_form.tbl_scan_summary.setItem(0, 9, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(host['total'] ))) )
                    self.main_form.tbl_scan_summary.setItem(0, 10, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str(host['score'] ))) )
                    self.main_form.tbl_scan_summary.setItem(0, 11, QtWidgets.QTableWidgetItem( str(host['credentialed'] )))
                
                
                    self.main_form.tbl_scan_summary.resizeColumnsToContents()
                    self.main_form.tbl_scan_summary.horizontalHeader().setStretchLastSection(True)
                
            else:
                self.main_form.tbl_scan_summary.insertRow(0)
                
                self.main_form.tbl_scan_summary.setItem(0, 0, QtWidgets.QTableWidgetItem( scan_result['type'] ))
                self.main_form.tbl_scan_summary.setItem(0, 1, QtWidgets.QTableWidgetItem( scan_result['hostname'] ))
                self.main_form.tbl_scan_summary.setItem(0, 2, QtWidgets.QTableWidgetItem( scan_result['ip'] ))
                self.main_form.tbl_scan_summary.setItem(0, 3, QtWidgets.QTableWidgetItem( scan_result['os'] ))
                
                self.main_form.tbl_scan_summary.setItem(0, 4, QtWidgets.QTableWidgetItem( os.path.basename( scan_result['fileName'] )))
                
                self.main_form.tbl_scan_summary.setItem(0, 5, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(scan_result['catI']).strip() or 0 ) )) ) )
                self.main_form.tbl_scan_summary.setItem(0, 6, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(scan_result['catII']).strip() or 0 ) )) ) )
                self.main_form.tbl_scan_summary.setItem(0, 7, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(scan_result['catIII']).strip() or 0 ) )) ) )
                self.main_form.tbl_scan_summary.setItem(0, 8, QNumericTableWidgetItem(QtWidgets.QTableWidgetItem( str( int( str(scan_result['catIV']).strip() or 0 ) )) ) )
                
                self.main_form.tbl_scan_summary.setItem(0, 9, QtWidgets.QTableWidgetItem( str(scan_result['total'] )))
                self.main_form.tbl_scan_summary.setItem(0, 10, QtWidgets.QTableWidgetItem( str(scan_result['score'] )))
                self.main_form.tbl_scan_summary.setItem(0, 11, QtWidgets.QTableWidgetItem( str(scan_result['credentialed'] )))
                
                
                self.main_form.tbl_scan_summary.resizeColumnsToContents()
                self.main_form.tbl_scan_summary.horizontalHeader().setStretchLastSection(True)
    
    def merge_nessus(self):
        logging.info('Merge Nessus Clicked')
        
        options = QtWidgets.QFileDialog.Options(  )
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"QFileDialog.getOpenFileNames()", "","Nessus Files (*.nessus);;", options=options)
        if files:
            self.main_app.merge_nessus_files(files)
                
    def split_nessus(self):
        logging.info('Split Nessus Clicked')
        
        options = QtWidgets.QFileDialog.Options()
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(None,"QFileDialog.getOpenFileNames()", "","Nessus Files (*.nessus);;", options=options)
        if files:
            filepaths = []
            for file in files:
                logging.info('Splitting {}'.format(file))
                print('Splitting {}'.format(file))
                self.main_app.split_nessus_file(file)
                
        
    def btn_execute_on_click(self):
        logging.info('Execute Clicked')
        self.main_app.contact_info['command'] = self.main_form.txt_command.text()
        self.main_app.contact_info['name'] = self.main_form.txt_poc.text()
        self.main_app.contact_info['phone'] = self.main_form.txt_phone.text()
        self.main_app.contact_info['email'] = self.main_form.txt_email.text()
        
        self.main_app.poam_conf = { 
            'scd' : self.main_form.chk_prefill_scd.isChecked(), 
            'lower_risk' : self.main_form.chk_lower_risk.isChecked(),
            'exclude_plugins' : self.main_form.spnExcludeDays.value()
        }
        
        self.main_app.generate_reports()
        
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
        
        
    def connect_events(self):
        logging.info('Connecting Events')
        self.main_form.btn_parse_scan_files.clicked.connect(self.btn_parse_scan_files_on_click)
        self.main_form.btn_execute.clicked.connect(self.btn_execute_on_click)
        self.main_form.btn_select_scan_files.clicked.connect(self.btn_select_scan_files_on_click)

        self.main_form.tbl_selected_scans.horizontalHeader().sectionClicked.connect(self.sort_tbl_selected_scans)
        self.main_form.tbl_scan_summary.horizontalHeader().sectionClicked.connect(self.sort_tbl_scan_summary)


        self.main_form.actionMerge_Nessus.triggered.connect( self.merge_nessus )
        self.main_form.actionSplit_Nessus.triggered.connect( self.split_nessus )

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
        pass

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
        print(filepath)
        for row in range(self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 1)
            if cell_widget and filepath == cell_widget.data(QtCore.Qt.UserRole):
                print(cell_widget.data(QtCore.Qt.UserRole) )
                
    def remove_row(self):
        self.main_form.tbl_selected_scans.removeRow(self.main_form.tbl_selected_scans.currentRow())

    def dropEvent(self, event):
        filepaths = []
        for row in range(self.main_form.tbl_selected_scans.rowCount()):
            cell_widget = self.main_form.tbl_selected_scans.item(row, 0)
            if cell_widget:
                filepaths.append(cell_widget.data(QtCore.Qt.UserRole))

        data = event.mimeData()
        urls = data.urls()
        if urls and urls[0].scheme() == 'file':
            for url in urls:
                filepath = str(url.path())[1:]
                extension = os.path.splitext(filepath)[1].lower()
                
                if filepath not in filepaths:
                    if extension in ['.ckl', '.xml', '.nessus']:
                        self.main_form.tbl_selected_scans.insertRow(0)
                        
                        btn = QtWidgets.QPushButton(self.main_form.tbl_selected_scans)
                        btn.setText('Del')
                        btn.clicked.connect(self.remove_row)
                        self.main_form.tbl_selected_scans.setCellWidget(0, 0,  btn )
                        
                        item = QtWidgets.QTableWidgetItem( os.path.basename( filepath ))
                        item.setData(QtCore.Qt.UserRole, filepath)
                        self.main_form.tbl_selected_scans.setItem(0, 1, item)
                        
                        self.main_form.tbl_selected_scans.setItem(0, 2, QtWidgets.QTableWidgetItem( time.strftime( '%Y-%m-%d %H:%M:%S', time.gmtime( os.path.getmtime( filepath ))) ) )
                        self.main_form.tbl_selected_scans.setItem(0, 3, QNumericTableWidgetItem( QtWidgets.QTableWidgetItem( str( os.path.getsize( filepath ))) ) )
                        self.main_form.tbl_selected_scans.setItem(0, 4, QtWidgets.QTableWidgetItem( extension ))
                        
                        self.main_form.tbl_selected_scans.resizeColumnsToContents()
                        self.main_form.tbl_selected_scans.horizontalHeader().setStretchLastSection(True)
