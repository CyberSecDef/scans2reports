import logging
import sys
import os.path
import re
import datetime
import copy 
import secrets

from utils import Utils

from lxml import etree
from PyQt5 import QtCore, QtGui, QtWidgets

class ScanUtils():

    @staticmethod
    def update_ckl(source, destination, main_app):
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        
        FORMAT = "[%(asctime)s ] %(levelname)s - %(filename)s; %(lineno)s: %(name)s.%(module)s.%(funcName)s(): %(message)s"
        logging.basicConfig(filename=f"{application_path}/scans2reports.log", level=logging.INFO, format=FORMAT)
        logging.info('Update CKL')
        
        status = f"Updating {source} to {destination}"
        logging.info(status)
        print(status)
        
        main_app.main_window.statusBar().showMessage(status)
        main_app.main_window.progressBar.setValue(0)
        QtGui.QGuiApplication.processEvents() 
            
        with open(source, 'r', errors='replace', encoding='utf-8') as content_file:
            content = content_file.readlines()
        start = 0
        if '?' in content[start]:
            start += 1
        if '!' in content[start]:
            start += 1
        content = content[start:]
        content = ''.join(content)
        content = ''.join([i if ord(i) < 128 else ' ' for i in content])
        source_tree = etree.fromstring( str(content) )
        
        with open(destination, 'r', errors='replace', encoding='utf-8') as content_file:
            content = content_file.readlines()
        start = 0
        if '?' in content[start]:
            start += 1
        if '!' in content[start]:
            start += 1
        content = content[start:]
        content = ''.join(content)
        content = ''.join([i if ord(i) < 128 else ' ' for i in content])
        destination_tree = etree.fromstring( str(content) )
        
        stig_id = str(next(iter(destination_tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='stigid']/SID_DATA/text()")), ''))
        version = str(next(iter(destination_tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='version']/SID_DATA/text()")), ''))
        if '.' in version:
            version = version.split('.')[0]
            
        if version.isdigit():
            version = str(int(version))

        release = re.search('Release: ([0-9\*.]+) Benchmark', str( next(iter(destination_tree.xpath("/CHECKLIST/STIGS/iSTIG/STIG_INFO/SI_DATA[./SID_NAME='releaseinfo']/SID_DATA/text()")), '')  ))
        release = release.group(1) if release is not None else '0'
        if '.' in release:
            release = release.split('.')[1]
        
        if release.isdigit():
            release = str(int(release))

        source_vulns = source_tree.xpath("//VULN")
        index = 0
        total_vulns = len(source_vulns)
            
        for source_vuln in source_vulns:
            index += 1
            source_vuln_id = next(iter(source_vuln.xpath("*[./VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA/text()")), '')
            
            status = f"Copying {source_vuln_id} details"
            logging.info(status)
            print(status)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue( int( index / total_vulns * 100 ) )
                QtGui.QGuiApplication.processEvents() 
            
            if source_vuln_id.strip() != '':
                source_vuln_status = source_vuln.find('STATUS').text
                source_vuln_comments = source_vuln.find('COMMENTS').text
                source_vuln_finding_details = source_vuln.find('FINDING_DETAILS').text
                
                destination_vuln = destination_tree.xpath( "//VULN[./STIG_DATA/ATTRIBUTE_DATA='{}']".format( source_vuln_id.strip() ) )
                if isinstance(destination_vuln, list): 
                    destination_vuln_node = next(iter(destination_vuln), '')
                    
                    if isinstance(destination_vuln_node, etree._Element): 
                        destination_vuln_node.find('STATUS').text = source_vuln_status
                        destination_vuln_node.find('COMMENTS').text = source_vuln_comments
                        destination_vuln_node.find('FINDING_DETAILS').text = source_vuln_finding_details

        
        ckl_name = "{}/results/{}_V{}R{}_{}.ckl".format(
            os.path.dirname(os.path.realpath(__file__)),
            stig_id,
            version,
            release,
            (datetime.datetime.now()).strftime('%Y%m%d_%H%M%S')
        )
            
        destination_string = etree.tostring(destination_tree)
        myfile = open(ckl_name, "wb")
        myfile.write(destination_string)

        print(f"Updated CKL saved to {ckl_name}")
        status = f"Finished Updating CKL"
        logging.info(status)
        print(status)
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage(status)
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
    
    
    def split_nessus_file(file, main_app):
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
            
            scan_date = datetime.datetime.strptime(
                str(next(iter(tree.xpath("/NessusClientData_v2/Report/ReportHost[1]/HostProperties/tag[@name='HOST_START']/text()")), ''))
                , '%a %b %d %H:%M:%S %Y'
            ).strftime("%Y%m%d_%H%M%S")
        
            status = f"Processing host: {fqdn_val}, scan date: {scan_date}"
            logging.info(status)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*index/total_hosts*.9)   )
                QtGui.QGuiApplication.processEvents() 
            
            report_name = "{}/results/{}_{}.nessus".format(
                os.path.dirname(os.path.realpath(__file__)),
                fqdn_val,
                scan_date
            )
        
            host_nessus = copy.deepcopy(tree)
            for host in host_nessus.xpath("/NessusClientData_v2/Report/ReportHost"):
                host_fqdn_val = Utils.fqdn(host)
                
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
        if main_app.main_window:
            main_app.main_window.statusBar().showMessage("Ready")
            main_app.main_window.progressBar.setValue( 0 )
            QtGui.QGuiApplication.processEvents() 
        
        
    def merge_nessus_files(files, host_count, main_app):
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
            
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
            Utils.update_status(application_path, main_app, status, (int(100*index/total_files*.9)) ) 
            
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
            Utils.update_status(application_path, main_app, status )
                        
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
            Utils.update_status(application_path, main_app, status )
            
            merged_tree = master_nessus.getroottree()
            merged_tree.write(report_name)
            
            
        else:
            
            current_chunk = 1
            total_hosts = len( master_nessus.xpath("/NessusClientData_v2/Report/ReportHost") )
                
            while current_chunk <= total_hosts:
                status = f"Saving hosts {current_chunk} to {(current_chunk + host_count - 1)}"
                Utils.update_status(application_path, main_app, status )
            
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
        Utils.update_status(application_path, main_app, status, 0 )
    