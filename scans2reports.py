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
import copy 
import secrets
import pprint
import dumper
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
    input_folder = ""
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
    application_path = ""
    
    def __init__(self, args):
        """ Constructor """
        
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle, the pyInstaller bootloader
            # extends the sys module by a flag frozen=True and sets the app 
            # path into variable _MEIPASS'.
            self.application_path = sys._MEIPASS
        else:
            self.application_path = os.path.dirname(os.path.abspath(__file__))
            
        FORMAT = "[%(asctime)s | %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
        logging.basicConfig(filename=f'{self.application_path}/scans2reports.log', level=logging.INFO, format=FORMAT)
        logging.info('Started')
        
        if args.gui or args.input_folder is None:
            logging.info('Executing GUI mode')
            self.operating_mode = 'gui'
        
        
        logging.info('Application Path: %s', self.application_path)
        
        self.num_theads = int(psutil.cpu_count()) - 2
        
        logging.info('Threads: %s', self.num_theads)
        
        with open(os.path.join(self.application_path, "data/dataset.json"), "r") as read_file:
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
        self.input_folder = args.input_folder

    def merge_nessus_files(self, files, host_count):
        #open the first file for structure
        file = files[0]
        
        with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
            content = content_file.readlines()
        content = ''.join(content)
        tree = etree.fromstring( str(content ) )
        
        #make structure by removing hosts
        master_nessus = copy.deepcopy(tree)
        for host in master_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):            
            host.getparent().remove(host)
        
        total_files = len(files)
        index = 0
        #loop through each file
        for file in files:
            index += 1
            
            status = f"Merging file {os.path.basename(file)} into master nessus file"
            Utils.update_status(self.application_path, S2R, status, (int(100*index/total_files*.9)) ) 
            
            with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            content = ''.join(content)
            current_scan_file = etree.fromstring( str(content ) )
        
            #loop through each host in the current scan file
            for current_host in current_scan_file.xpath("/NessusClientData_v2/Report/ReportHost"):
                fqdn_val = Utils.fqdn(current_host)
                
                current_scan_date = datetime.datetime.strptime(str(next(iter(current_host.xpath("//HostProperties/tag[@name='HOST_START']/text()")), '')), '%a %b %d %H:%M:%S %Y')
                
                status = f"Processing host: {fqdn_val}, scan date: {current_scan_date}"
                logging.info(status)
                
                #see if the current host from the current scan file is in the master nessus file
                master_date = ""
                found = False
                for master_host in master_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                    master_fqdn_val = Utils.fqdn(master_host)
                    
                    #the host from the current scan is already present in master nessus
                    if master_fqdn_val == fqdn_val:
                        found = True
                        master_date = datetime.datetime.strptime(str(next(iter(master_host.xpath("./HostProperties/tag[@name='HOST_START']/text()")), '')), '%a %b %d %H:%M:%S %Y')
                        master_node = master_host
                        
                        status = f"Found host {master_fqdn_val} already present in master nessus file with scan date {master_date}"
                        logging.info(status)        
                
                #the current host in the current scan is already found in the master nessus file
                if found:
                    logging.info("Master Nessus Scandate for host {}: {}".format(master_fqdn_val, master_date) )
                    logging.info("Current Scandate for host {}: {}".format(fqdn_val, current_scan_date) )
                    if current_scan_date >= master_date:
                        status = f"Replacing host {master_fqdn_val} in Master Nessus File"
                        logging.info(status)        
                        
                        master_node.getparent().remove(master_node)
                        report_host_node = next(iter(master_nessus.xpath("/NessusClientData_v2/Report")),'')
                        report_host_node.append(current_host)
                else:
                    status = f"Inserting host {fqdn_val} in Master Nessus File"
                    logging.info(status)        
                        
                    report_host_node = next(iter(master_nessus.xpath("/NessusClientData_v2/Report")),'')
                    report_host_node.append(current_host)

        if host_count == 0:
            status = f"Updating Server Preferences"
            Utils.update_status(self.application_path, S2R, status )
                        
            report_name = "{}/results/{}".format( os.path.dirname(os.path.realpath(__file__)), datetime.datetime.now().strftime("merged-%Y%m%d_%H%M%S.nessus") )
            report_task_id = "{}-{}-{}-{}-{}-{}".format( secrets.token_hex(4), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(14) )         
            report_node = master_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
            if report_node:
                report_node[0].text = report_task_id
            
            plugins = []
            for current_host in master_nessus.xpath("/NessusClientData_v2/Report/ReportHost/ReportItem"):
                 plugins.append(int(next(iter(current_host.xpath("./@pluginID")),'')))
            plugins = sorted(list(set(plugins)))
            plugs = [str(p) for p in plugins] 
            plugins = (";".join(plugs))
            plugin_node = master_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'plugin_set']/value")
            if plugin_node:
                plugin_node[0].text = plugins
            
            targets = []
            for current_host in master_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                 targets.append(next(iter(current_host.xpath("./@name")),''))
            targets = sorted(list(set(targets)))
            target_node = master_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'TARGET']/value")
            if target_node:
                target_node[0].text = ",".join(targets)
            
            status = f"Saving merged Nessus file to results folder"
            Utils.update_status(self.application_path, S2R, status )
            
            merged_tree = master_nessus.getroottree()
            merged_tree.write(report_name)
            
            
        else:
            
            current_chunk = 1
            total_hosts = len( master_nessus.xpath("/NessusClientData_v2/Report/ReportHost") )
                
            while current_chunk <= total_hosts:
                status = f"Saving hosts {current_chunk} to {(current_chunk + host_count - 1)}"
                Utils.update_status(self.application_path, S2R, status )
            
                chunked_nessus = copy.deepcopy(master_nessus)
                count = 1
                #remove all hosts AFTER this chunk
                for host in chunked_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):            
                    if count > ( current_chunk + host_count - 1):
                        host.getparent().remove(host)
                    count += 1
                    
                #remove all hosts BEFORE this chunk
                for i in range(1, current_chunk ):
                    host = chunked_nessus.xpath("/NessusClientData_v2/Report/ReportHost[1]")
                    if host:
                        host[0].getparent().remove(host[0])
                
                report_name = "{}/results/{}_{}".format(
                    os.path.dirname(os.path.realpath(__file__)),
                    current_chunk,
                    datetime.datetime.now().strftime("merged-%Y%m%d_%H%M%S.nessus") 
                )

                report_task_id = "{}-{}-{}-{}-{}-{}".format( secrets.token_hex(4), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(14) )         
                report_node = chunked_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
                if report_node:
                    report_node[0].text = report_task_id
                
                plugins = []
                for current_host in chunked_nessus.xpath("/NessusClientData_v2/Report/ReportHost/ReportItem"):
                     plugins.append(int(next(iter(current_host.xpath("./@pluginID")),'')))
                plugins = sorted(list(set(plugins)))
                plugs = [str(p) for p in plugins] 
                plugins = (";".join(plugs))
                plugin_node = chunked_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'plugin_set']/value")
                if plugin_node:
                    plugin_node[0].text = plugins
                
                targets = []
                for current_host in chunked_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                     targets.append(next(iter(current_host.xpath("./@name")),''))
                targets = sorted(list(set(targets)))
                target_node = chunked_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'TARGET']/value")
                if target_node:
                    target_node[0].text = ",".join(targets)
                
                merged_tree = chunked_nessus.getroottree()
                merged_tree.write(report_name)
                
                current_chunk += host_count
            
            
        status = "Merged Nessus File is in results folder"
        Utils.update_status(self.application_path, S2R, status, 0 )
            
            
    def split_nessus_file(self, file):
        with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
            content = content_file.readlines()
        content = ''.join(content)
        tree = etree.fromstring( str(content ) )
        
        report_hosts = tree.xpath("/NessusClientData_v2/Report/ReportHost")
        total_hosts = len(report_hosts)
        index = 0
        
        for host in report_hosts:
            index += 1
            fqdn_val = Utils.fqdn(host)
            
            scanDate = datetime.datetime.strptime(
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), ''))
                , '%a %b %d %H:%M:%S %Y'
            ).strftime("%Y%m%d_%H%M%S")
        
            status = f"Processing host: {fqdn_val}, scan date: {scanDate}"
            logging.info(status)
            if S2R.scans_to_reports:
                S2R.scans_to_reports.statusBar().showMessage(status)
                S2R.scans_to_reports.progressBar.setValue(int(100*index/total_hosts*.9)   )
                QtGui.QGuiApplication.processEvents() 
            
            report_name = "{}/results/{}_{}.nessus".format(
                os.path.dirname(os.path.realpath(__file__)),
                fqdn_val,
                scanDate
            )
        
            host_nessus = copy.deepcopy(tree)
            for host in host_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                fqdn_val = Utils.fqdn(host)
                
                if host_fqdn_val != fqdn_val:
                    host.getparent().remove(host)
            
            report_task_id = "{}-{}-{}-{}-{}-{}".format(
                secrets.token_hex(4),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(2),
                secrets.token_hex(14)
            )
            report_node = host_nessus.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
            if report_node:
                report_node[0].text = report_task_id
            
            host_tree = host_nessus.getroottree()
            host_tree.write(report_name) 
        
        status = f"Merged Nessus File is in results folder"
        logging.info(status)
        print(status)
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage("Ready")
            S2R.scans_to_reports.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
        

    def collect_scan_files(self):
        """ Collects all the files to be scanned """
        
        status = f"Collecting scan files"
        logging.info(status)
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage(status)
            S2R.scans_to_reports.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
                
        if self.input_folder.endswith('"'):
            self.input_folder = self.input_folder[:-1]
        
        self.scan_files = list( Path(self.input_folder).glob('**/*') )
        self.scan_results = [{} for x in self.scan_files]

    def parse_scan_files(self):
        """ Add scan file to parsing thread """
        
        status = f"Parsing scan files"
        logging.info(status)
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage(status)
            S2R.scans_to_reports.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
        
        #add scan job to queue
        num_files = len(self.scan_files)
        for i in range(num_files):
            self.q.put((i, self.scan_files[i]))

        #start parse threads
        for i in range(self.num_theads):
            worker = Thread(target=self.start_parse_thread, args=(self.q, self.scan_results))
            worker.setDaemon(True)
            worker.start()
        
        #make sure the main gui doesn't get blocked while waiting for queue to finish
        if S2R.scans_to_reports:
            while self.q.qsize() > 0:
                S2R.scans_to_reports.statusBar().showMessage(status)
                S2R.scans_to_reports.progressBar.setValue( ( num_files - self.q.qsize())/num_files * 100 )
                QtGui.QGuiApplication.processEvents() 
                time.sleep(1)
        
        #wait for threads to all complete
        self.q.join()

            
        
        self.scan_results = [ i for i in self.scan_results if type(i) == ScanFile ]
            
        #show completed parse jobs
        status = f"All scans parsed"
        logging.info(status)
        print(status)
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage(status)
            S2R.scans_to_reports.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
        
    def start_parse_thread(self, queue, result):
        """ Create / Start parsing thread """
        logging.info('Starting Parse Thread')
        
        scan_parser = ScanParser(self.application_path, self.data_mapping, S2R)

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

                if data is not None:
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
            if S2R.scans_to_reports:
                QtGui.QGuiApplication.processEvents()
        return True

    def generate_reports(self):
        """ After all scan files are parsed, begin generating Excel Tabs """
        logging.info('Generating Reports')
        
        reports = Reports(
            self.application_path,
            self.scan_results,
            self.data_mapping,
            self.contact_info,
            self.poam_conf,
            S2R.scans_to_reports
        )

        total_reports = list(filter(lambda x: x.startswith('rpt'), dir(reports)))
        index = 0
        for report in total_reports:
            index += 1
            status = f"Generating Report {report}"
            print(status)
            logging.info(status)        
            
            if S2R.scans_to_reports:
                S2R.scans_to_reports.progressBar.setValue(int(100*index/(len(total_reports))*.9)   )
                QtGui.QGuiApplication.processEvents() 
            getattr(reports, report)()
            
        reports.close()
        
        status = f"Report Generated"
        logging.info(status)        
        if S2R.scans_to_reports:
            S2R.scans_to_reports.statusBar().showMessage(status)
            S2R.scans_to_reports.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 

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

optional.add_argument('-h', '--help', action='help', default=SUPPRESS, help='show this help message and exit')
optional.add_argument('input_folder', nargs='?')

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

        S2R.scans_to_reports.statusBar().showMessage(f"Ready")
        S2R.scans_to_reports.progressBar = QtWidgets.QProgressBar()
        S2R.scans_to_reports.progressBar.setGeometry(0, 0, 200, 25)
        S2R.scans_to_reports.progressBar.setValue(0)
        S2R.scans_to_reports.statusBar().addPermanentWidget(S2R.scans_to_reports.progressBar)
        
        S2R.scans_to_reports.show()
        
        sys.exit(app.exec_())

        pass
    else:
        print("Console Mode")
        if S2R.input_folder is not None and S2R.input_folder.strip() != '':
            print(S2R.input_folder)
            S2R.collect_scan_files()
            S2R.parse_scan_files()
            S2R.generate_reports()
        else:
            print("Scan Files Not Specified")
