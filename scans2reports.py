#!/usr/bin/python3
""" Scans2Reports module """

# NOTES:
# Python Path: C:\Users\admin\AppData\Local\Programs\Python\Python37
# Convert UI to PY: .\Scripts\pyuic5.exe -x S:\Misc\Development\scans2reports\src\ui_scans_to_reports.ui -o S:\Misc\Development\scans2reports\src\ui_scans_to_reports.py
# Execute Applet: clear; .\python.exe S:\Misc\Development\scans2reports\src\scans2reports.py
# from ui_addons import FileDrop

from argparse import ArgumentParser, SUPPRESS
import os
import sys
import time
import json
import logging
import copy
import secrets
import pprint
import dumper
import jmespath
import re

import pickle

from scar_pickles import SCARPickles
from scar_enums import TestResultOptions, MitigationStatementOptions

from enum import Enum
from lxml import etree
from pathlib import Path
from threading import Thread
from queue import Queue
from PyQt5 import QtCore, QtGui, QtWidgets
from reports import Reports
from scan_parser import ScanParser
import datetime
import psutil
from ui_scans_to_reports import UiScansToReports
from ui_addons import UiAddons
from utils import Utils
from scan_file import ScanFile

class Scans2Reports:
    """ Scans2Reports python suite, main file """

    def __init__(self, args):
        """ Constructor """

        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle, the pyInstaller bootloader
            # extends the sys module by a flag frozen=True and sets the app
            # path into variable _MEIPASS'.
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))

        self.scar_conf = SCARPickles('scar_configs')
        self.scar_data = SCARPickles('scar_data')

        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{self.scar_conf.get('application_path')}/scans2reports.log", level=logging.INFO, format=FORMAT)
        logging.info('Started')

        if args.gui or args.input_folder is None:
            logging.info('Executing GUI mode')
            self.scar_conf.set('operating_mode','gui')
        else:
            logging.info('Executing Console mode')
            self.scar_conf.set('operating_mode','console')

        logging.info('Application Path: %s', self.scar_conf.get('application_path'))


        if args.exclude_plugins == 0:
            if self.scar_conf.get('exclude_plugins') is None:
                self.scar_conf.set('exclude_plugins', 30)
        else:
            self.scar_conf.set('exclude_plugins', args.exclude_plugins)
        
        
        if args.skip_info:
            self.scar_conf.set('skip_info', args.skip_info)
        else:
            if self.scar_conf.get('skip_info') is None:
                self.scar_conf.set( 'skip_info', True )
        
        if args.lower_risk:
            self.scar_conf.set('lower_risk', args.lower_risk)
        else:
            if self.scar_conf.get('lower_risk') is None:
                self.scar_conf.set( 'lower_risk', True )
        
        if args.scd:
            self.scar_conf.set('scd', args.scd)
        else:
            if self.scar_conf.get('scd') is None:
                self.scar_conf.set( 'scd', True )
                
        if args.finding_details:
            self.scar_conf.set('include_finding_details', args.finding_details)
        else:
            if self.scar_conf.get('include_finding_details') is None:
                self.scar_conf.set( 'include_finding_details', True )
                
        if args.test_results is None:
            if self.scar_conf.get('test_results') is None:
                self.scar_conf.set('test_results', 'add')
        else:
            self.scar_conf.set('test_results', args.test_results)

        if args.mitigation_statements is None:
            if self.scar_conf.get('mitigation_statements') is None:
                self.scar_conf.set('mitigation_statements', 'blank')
        else:
            self.scar_conf.set('mitigation_statements', args.mitigation_statements)

        if args.threads == 0:
            if self.scar_conf.get('num_threads') is None:
                self.scar_conf.set('num_threads', int(psutil.cpu_count()) - 2 + 1)

            if self.scar_conf.get('threads') is None:
                self.scar_conf.set('threads', 2)
        else:
            if args.threads == 1:
                self.scar_conf.set('num_threads', int(psutil.cpu_count() // 2) + 1)
                self.scar_conf.set('threads', 1)
            elif args.threads == 2:
                self.scar_conf.set('num_threads', int(psutil.cpu_count()) - 2 + 1)
                self.scar_conf.set('threads', 2)
            else:
                self.scar_conf.set('num_threads', int(psutil.cpu_count() * 2) - 1)
                self.scar_conf.set('threads', 3)

        if self.scar_conf.get('num_threads') <= 0:
            self.scar_conf.set('num_threads', 1)
            self.scar_conf.set('threads', 1)

        logging.info('Threads: %s', self.scar_conf.get('num_threads'))

        if 'predisposing_conditions' in args and args.predisposing_conditions is not None and str( args.predisposing_conditions ).strip() != '':
            self.scar_conf.set('predisposing_conditions', args.predisposing_conditions)
        
        
        self.scar_conf.set('input_folder', args.input_folder)
        self.scar_conf.set('skip_reports', [])

        self.scar_data.set('command', (args.command if 'command' in args and args.command is not None and str(args.command).strip() != '' else '') )
        self.scar_data.set('name', (args.name if 'name' in args and args.name is not None and str(args.name).strip() != '' else '') )
        self.scar_data.set('phone', (args.phone if 'phone' in args and args.phone is not None and str(args.phone).strip() != '' else '') )
        self.scar_data.set('email', (args.email if 'email' in args and args.email is not None and str(args.email).strip() != '' else '') )

        with open(os.path.join(self.scar_conf.get('application_path'), "data/dataset.json"), "r") as read_file:
            self.scar_data.set('data_mapping', json.load(read_file) )

        #queue mechanism for parsing scans using multiple threads
        self.q = Queue(maxsize=0)


    def collect_scan_files(self):
        """ Collects all the files to be scanned.  This is called from the CLI operating mode """

        status = f"Collecting scan files"
        logging.info(status)

        if self.scar_conf.get('input_folder').endswith('"') or self.scar_conf.get('input_folder').endswith("'"):
            self.scar_conf.set('input_folder', self.scar_conf.get('input_folder')[:-1] )

        self.scan_files = list( Path( self.scar_conf.get('input_folder') ).glob('**/*') )
        self.scan_results = [{} for x in self.scan_files]

    def parse_scan_files(self):
        """ Add scan file to parsing thread """

        start_time = datetime.datetime.now()
        print( "{} - Parsing Scan Files".format(datetime.datetime.now() - start_time ) )

        status = f"Parsing scan files"
        logging.info(status)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(status)
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents()

        #add scan job to queue
        num_files = len(self.scan_files)
        for i in range(num_files):
            self.q.put((i, self.scan_files[i]))

        #start parse threads
        for i in range( self.scar_conf.get('num_threads') ):
            if i <= num_files:
                worker = Thread(target=self.start_parse_thread, args=(self.q, self.scan_results))
                worker.setDaemon(True)
                worker.start()

        #make sure the main gui doesn't get blocked while waiting for queue to finish
        if main_app.main_window:
            eta_start = datetime.datetime.now()

            while self.q.qsize() > 0:
                run_time = (datetime.datetime.now() - eta_start )
                current_scan = num_files - self.q.qsize()
                time_per = run_time.seconds / (current_scan + 1)
                time_left = datetime.timedelta(seconds= ( (num_files - current_scan)  * time_per) )

                status = "Parsing scan files: {} / {} - Runtime: {}, Time Per Scan: {}s, ETA: {}".format(
                    str(current_scan),
                    str(num_files),
                    str( run_time ),
                    str( round(time_per, 2)),
                    str( time_left)
                )

                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue( ( num_files - self.q.qsize())/num_files * 100 )
                QtGui.QGuiApplication.processEvents()
                # time.sleep(1)

        #wait for threads to all complete
        self.q.join()

        #gather test results from parsed files
        self.scar_data.set('test_result_data', next(iter([ i for i in self.scan_results if type(i) == dict and 'type' in i and i['type'] == 'Test Results' ]),'') )
        
        mitigations = []
        for mitigation_bundle in iter([ i for i in self.scan_results if type(i) == dict and 'type' in i and i['type'] == 'Mitigations' ]):
            for mitigation_row in mitigation_bundle['mitigations']:
                mitigations.append(mitigation_row)
        
        self.scar_data.set('mitigations', {'mitigations':mitigations,'type':'Mitigations'})
        
        #gather scan results from parsed files
        self.scan_results = [ i for i in self.scan_results if type(i) == ScanFile ]

        #pickle to a data file (saves ram and resources)
        with open(os.path.join(self.scar_conf.get('application_path'), "data/scan_results.pkl"), "wb") as f:
            pickle.dump(self.scan_results, f)

        #after pickle, set to none to save memory
        self.scan_results = None

        #show completed parse jobs
        status = "{} - Finished Parsing Scan Files".format(datetime.datetime.now() - start_time )
        logging.info(status)
        print(status)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(status)
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents()

    def start_parse_thread(self, queue, result):
        """ Create / Start parsing thread """
        logging.info('Starting Parse Thread')

        scan_parser = ScanParser(main_app)

        while not queue.empty():
            work = queue.get()
            print(f"Max Threads: {self.scar_conf.get('num_threads'):<3} | Starting thread {work[0]:<14}: {work[1]}")
            logging.info(f"Max Threads: {self.scar_conf.get('num_threads'):<3} | Starting thread {work[0]:<14}: {work[1]}")
            start_time = time.time()
            try:
                file = None
                if  type(work[1]) == str:
                    file = Path(work[1])
                else:
                    file = work[1]

                if file.is_file() and all(ord(c) < 128 for c in str(file)):
                    extension = os.path.splitext(file)[1]
                    if 'xccdf' in str(file).lower() and extension == '.xml':
                        data = scan_parser.parseScap(file)
                    elif extension == '.ckl':
                        data = scan_parser.parseCkl(file)
                    elif extension == '.nessus':
                        data = scan_parser.parseNessus(file)
                    elif extension == '.xlsx' or extension == '.xlsm':
                        data = scan_parser.parseXlsx(file)
                    elif extension == '.csv':
                        data = scan_parser.parseCsv(file)
                    else:
                        data = None
                        logging.warning(f'Skipping scan file: {str(file)}');
                        print(f'Skipping scan file: {str(file)}')
                if data is not None:
                    result[work[0]] = data

            except Exception as err:
                logging.error('Error with scan check!')
                logging.error(err)
                logging.error(work[0])
                logging.error(work[1])
                print(err)
                print('Error with scan check!')
                result[work[0]] = {}
            print(
                "                   Finished thread {:<3}  ({:<6}) : {}".format(
                    work[0], round(time.time() - start_time, 3), work[1]
                )
            )

            queue.task_done()
            if main_app.main_window:
                QtGui.QGuiApplication.processEvents()

        return True

    def generate_reports(self):
        """ After all scan files are parsed, begin generating Excel Tabs """
        logging.info('Generating Reports')

        reports = Reports(main_app.main_window)

        total_reports = list(filter(lambda x: x.startswith('rpt'), dir(reports)))
        index = 0
        for report in total_reports:
            index += 1
            status = f"Generating Report {report}"
            print(status)
            logging.info(status)

            if main_app.main_window:
                main_app.main_window.progressBar.setValue(int(100*index/(len(total_reports))*.9)   )
                QtGui.QGuiApplication.processEvents()
            getattr(reports, report)()

        reports.close_workbook()

        status = f"Report Generated"
        logging.info(status)
        print(status)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(status)
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents()

    def clean_up(self):
        pickles = []
        pickles.append( os.path.join(self.scar_conf.get('application_path'), 'data', 'scar_data.pkl') )
        pickles.append( os.path.join(self.scar_conf.get('application_path'), 'data', 'scan_results.pkl') )

        for pickle in pickles:
            if os.path.isfile( pickle ):
                os.unlink( pickle )

# pylint: disable=C0103
# Disable default help
arg_parser = ArgumentParser(add_help=False)
required = arg_parser.add_argument_group('required arguments')
required.add_argument('input_folder', nargs='?', help='The folder to collect scans from.')

optional = arg_parser.add_argument_group('optional arguments')

optional.add_argument('-i', '--skip-info', help='Skip Informational Findings', action='store_true')
optional.add_argument('-fd', '--finding-details', help='Whether or not to include the finding details in the POAM/RAR Comments', action='store_true')
optional.add_argument('-g', '--gui', help='Use the GUI instead of the console', action='store_true')
optional.add_argument('-l', '--lower-risk', help='Automatically Lower Risk on POAM', action='store_true')
optional.add_argument('--mitigation-statements', help='Import Mitigation Methods (blank, poam, ckl, both)',  type=MitigationStatementOptions, choices=list(MitigationStatementOptions))
optional.add_argument('--predisposing-conditions', help='Enter default Predisposing Conditions')
optional.add_argument('-s', '--scd', help='Prefill Estimated SCD to POAM', action='store_true')
optional.add_argument('--test-results', help='Add, Close or Convert CCI Mismatches',  type=TestResultOptions, choices=list(TestResultOptions))
optional.add_argument('-t', '--threads', help='How intensive should the generator run (1-3).  Defaults to 2.', type=int, default=0)
optional.add_argument('-x', '--exclude-plugins', help='Exclude plugins newer than this number of days.  Defaults to 30.', type=int, default=0)

optional.add_argument('-c', '--command', help='Add Responsible Command/Organization Caption to POAM')
optional.add_argument('-e', '--email', help='Add POC Email Address to POAM')
optional.add_argument('-n', '--name', help='Add POC Name to POAM')
optional.add_argument('-p', '--phone', help='Add POC Phone Number to POAM')

optional.add_argument('-h', '--help', action='help', default=SUPPRESS, help='show this help message and exit')


# pylint: enable=C0103
if __name__ == "__main__":

    main_app = Scans2Reports(arg_parser.parse_args())
    main_app.main_window = None
    if main_app.scar_conf.get('operating_mode') == 'gui':
        print("GUI Mode")
        app = QtWidgets.QApplication(sys.argv)
        main_app.main_window = QtWidgets.QMainWindow()

        ui = UiScansToReports()
        ui.setupUi(main_app.main_window)

        ui_addons = UiAddons(main_app, ui)
        ui_addons.connect_events()
        ui_addons.update_scan_headers()
        ui_addons.update_summary_headers()
        ui_addons.update_form_values()

        main_app.main_window.statusBar().showMessage(f"Ready")
        main_app.main_window.progressBar = QtWidgets.QProgressBar()
        main_app.main_window.progressBar.setGeometry(0, 0, 200, 25)
        main_app.main_window.progressBar.setValue(0)
        main_app.main_window.statusBar().addPermanentWidget(main_app.main_window.progressBar)

        main_app.main_window.show()

        app.exec_()

    else:
        print("Console Mode")
        if main_app.scar_conf.get('input_folder') is not None and main_app.scar_conf.get('input_folder').strip() != '':
            print("Parsing scans in ", main_app.scar_conf.get('input_folder'))
            main_app.collect_scan_files()
            main_app.parse_scan_files()
            main_app.generate_reports()
        else:
            print("Scan Files Not Specified")

    main_app.clean_up()
