#!/usr/bin/python3
""" Scans2Reports module """

# NOTES:
# Python Path: C:\Users\admin\AppData\Local\Programs\Python\Python37
# Convert UI to PU: .\Scripts\pyuic5.exe -x S:\Misc\Development\scans2reports\src\ui_scans_to_reports.ui -o S:\Misc\Development\scans2reports\src\ui_scans_to_reports.py
# Execute Applet: clear; .\python.exe D:\development\scans2poam\scans2report.py
# from ui_addons import FileDrop

from argparse import ArgumentParser, SUPPRESS
import os
import sys
import time
import json
import logging
from pathlib import Path
from threading import Thread
from queue import Queue
from PyQt5 import QtCore, QtGui, QtWidgets
from reports import Reports
from scan_parser import ScanParser
import psutil
from ui_scans_to_reports import UiScansToReports
from ui_addons import UiAddons

class Scans2Reports:
    """ Scans2Reports python suite, main file """
    source_folder = ""
    scan_files = []
    scan_results = []
    q = Queue(maxsize=0)
    num_theads = 10
    data_mapping = {}
    contact_info = {}
    poam_conf = {}
    operating_mode = "console"
    ui = None
    scans_to_reports = None
    
    def __init__(self, args):
        """ Constructor """
        FORMAT = "[%(asctime)s | %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
        logging.basicConfig(filename='scans2reports.log', level=logging.INFO, format=FORMAT)
        logging.info('Started')
        
        if args.gui or args.folder is None:
            logging.info('Executing GUI mode')
            self.operating_mode = 'gui'
        
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle, the pyInstaller bootloader
            # extends the sys module by a flag frozen=True and sets the app 
            # path into variable _MEIPASS'.
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        logging.info('Application Path: %s', application_path)
        
        self.num_theads = int(psutil.cpu_count()) - 2
        
        logging.info('Threads: %s', self.num_theads)
        
        with open(os.path.join(application_path, "data/dataset.json"), "r") as read_file:
            self.data_mapping = json.load(read_file)
        
        self.contact_info = {
            'command' : (args.command if 'command' in args and args.command is not None and str(args.command).strip() != '' else ''),
            'name' : (args.name if 'name' in args and args.name is not None and str(args.name).strip() != '' else ''),
            'phone' : (args.phone if 'phone' in args and args.phone is not None and str(args.phone).strip() != '' else ''),
            'email' : (args.email if 'email' in args and args.email is not None and str(args.email).strip() != '' else '')
        }
        
        self.poam_conf = { 
            'scd' : args.scd, 
            'lower_risk' : args.lower_risk, 
            'exclude_plugins' : args.exclude_plugins 
        }
        self.source_folder = args.folder
        

    def collect_scan_files(self):
        """ Collects all the files to be scanned """
        logging.info('Collecting scan files')
        
        root_directory = Path(self.source_folder)
        self.scan_files = list(root_directory.glob('**/*'))
        self.scan_results = [{} for x in self.scan_files]

    def parse_scan_files(self):
        """ Add scan file to parsing thread """
        logging.info('Parsing scan files')
        
        #add scan job to queue
        for i in range(len(self.scan_files)):
            self.q.put((i, self.scan_files[i]))

        #start parse threads
        for i in range(self.num_theads):
            worker = Thread(target=self.start_parse_thread, args=(self.q, self.scan_results))
            worker.setDaemon(True)
            worker.start()

        #wait for threads to all complete
        self.q.join()

        #show completed parse jobs
        print('All scans parsed.')
        print('')
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage("All scans parsed")

    def start_parse_thread(self, queue, result):
        """ Create / Start parsing thread """
        logging.info('Starting Parse Thread')
        
        scan_parser = ScanParser(self.data_mapping)

        while not queue.empty():
            work = queue.get()
            print(f"Max Threads: {self.num_theads:<3} | Starting thread {work[0]:<14}: {work[1]}")
            logging.info(f"Max Threads: {self.num_theads:<3} | Starting thread {work[0]:<14}: {work[1]}")
            start_time = time.time()
            try:
                file = None
                if  type(work[1]) == str:
                    file = Path(work[1])
                else:
                    file = work[1]
                
                if file.is_file() and all(ord(c) < 128 for c in str(file)):
                    extension = os.path.splitext(file)[1]
                    if extension == '.xml':
                        data = scan_parser.parseScap(file)
                    elif extension == '.ckl':
                        data = scan_parser.parseCkl(file)
                    elif extension == '.nessus':
                        data = scan_parser.parseNessus(file)
                result[work[0]] = data
            except Exception as err:
                print(err)
                print('Error with scan check!')
                result[work[0]] = {}
            print(
                "                   Finished thread {:<3}  ({:<6}) : {}".format(
                    work[0], round(time.time() - start_time, 3), work[1]
                )
            )
            queue.task_done()
        return True

    def generate_reports(self):
        """ After all scan files are parsed, begin generating Excel Tabs """
        logging.info('Generating Reports')
        
        reports = Reports(
            self.scan_results,
            self.data_mapping,
            self.contact_info,
            self.poam_conf,
            S2R.scans_to_reports
        )

        for report in filter(lambda x: x.startswith('rpt'), dir(reports)):
            print(report)
            logging.info('Generating Report %s', report)
            getattr(reports, report)()
            QtWidgets.QApplication.processEvents()

        reports.close()
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage("Report Generated")

# pylint: disable=C0103
# Disable default help
arg_parser = ArgumentParser(add_help=False)
required = arg_parser.add_argument_group('required arguments')
optional = arg_parser.add_argument_group('optional arguments')

optional.add_argument('-g', '--gui', help='Use the GUI instead of the console', action='store_true')
optional.add_argument('-c', '--command', help='Add Responsible Command Caption to POAM')
optional.add_argument('-n', '--name', help='Add POC Name to POAM')
optional.add_argument('-p', '--phone', help='Add POC Phone Number to POAM')
optional.add_argument('-e', '--email', help='Add POC Email Address to POAM')
optional.add_argument('-s', '--scd', help='Prefill Estimated SCD to POAM', action='store_true')
optional.add_argument('-x', '--exclude-plugins', help='Exclude plugins newer than this number of days', type=int, default=30)
optional.add_argument('-l', '--lower-risk', help='Automatically Lower Risk on POAM', action='store_true')
optional.add_argument('-folder', '--folder', required=False)
optional.add_argument('-h', '--help', action='help', default=SUPPRESS, help='show this help message and exit')


# pylint: enable=C0103
if __name__ == "__main__":
    S2R = Scans2Reports(arg_parser.parse_args())

    if S2R.operating_mode == 'gui':
        print("GUI Mode")
        app = QtWidgets.QApplication(sys.argv)
        S2R.scans_to_reports = QtWidgets.QMainWindow()
        ui = UiScansToReports()
        ui.setupUi(S2R.scans_to_reports)

        ui_addons = UiAddons(S2R, ui)
        ui_addons.connect_events()
        ui_addons.update_scan_headers()
        ui_addons.update_summary_headers()
        
        S2R.scans_to_reports.show()
        sys.exit(app.exec_())

        pass
    else:
        print("Console Mode")
        if S2R.source_folder is not None and S2R.source_folder.strip() != '':
            print(S2R.source_folder)
            S2R.collect_scan_files()
            S2R.parse_scan_files()
            S2R.generate_reports()
        else:
            print("Scan Files Not Specified")
