import logging
import sys
import os.path
import re
import datetime
import copy
import secrets
import pprint
import dumper
import unicodedata
import string
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

        status = f"Split Nessus File is in results folder"
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

        validFilenameChars = "-_.() %s%s" % (string.ascii_letters, string.digits)                
        policies = {}
        
        status = "Merging selected Nessus Files"
        Utils.update_status(application_path, main_app, status, 0 )
        logging.info(status)
        print(status)
        
        total_files = len(files)
        current_file = 0
        for file in files:
            current_file += 1
        
            status = "Processing file {}".format(file)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
        
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*current_file/total_files*.5)   )
                QtGui.QGuiApplication.processEvents()
                
            with open(file, 'r', errors='replace', encoding='utf-8') as content_file:
                content = content_file.readlines()
            content = ''.join(content)
            tree = etree.fromstring( str(content ) )

            #get the current files policy name and policy definition            
            version_check = tree.xpath("/NessusClientData_v2/Policy/policyName/text()")
            if version_check:
                policy_name = str(next(iter( tree.xpath("/NessusClientData_v2/Policy/policyName/text()")), "" ) )
            else:
                policy_name = str(next(iter( tree.xpath("/NessusClientData_v2/Policy/PolicyName/text()")), "" ) )
            policy_def = copy.deepcopy( tree.xpath("/NessusClientData_v2/Policy") )
            
            status = "    Policy {} Discovered".format(policy_name)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
            
            #if first time policy has been processed, add it to the policies list (with no hosts)
            if policy_name not in policies.keys():
                policies[policy_name] = {}
                policies[policy_name]['policy'] = policy_def[0]
                policies[policy_name]['hosts'] = []

            #now...add all found hosts in the current file to applicable policy item
            for host in tree.xpath("/NessusClientData_v2/Report/ReportHost"):
                clone_host = copy.deepcopy(host)
                policies[policy_name]['hosts'].append(clone_host)
        
        status = "Generating result scans based off of policies"
        Utils.update_status(application_path, main_app, status, 0 )
        logging.info(status)
        print(status)
        total_policies = len(policies.keys())
        current_policy = 0
        for policy in policies.keys():
            current_policy += 1
        
            status = "    Processing Policy {}".format(policy)
            Utils.update_status(application_path, main_app, status, 0 )
            logging.info(status)
            print(status)
            if main_app.main_window:
                main_app.main_window.statusBar().showMessage(status)
                main_app.main_window.progressBar.setValue(int(100*current_policy/total_policies*.5)+50   )
                QtGui.QGuiApplication.processEvents()
                
            chunk_index = 0
            final = [policies[policy]['hosts'][i * host_count:(i + 1) * host_count] for i in range((len(policies[policy]['hosts']) + host_count - 1) // host_count )]  
            for chunk in final:
                chunk_index += 1
                
                status = "        Processing Chunk {}".format(chunk_index)
                Utils.update_status(application_path, main_app, status, 0 )
                logging.info(status)
                print(status)
                
                root = etree.Element("NessusClientData_v2")
                root.append( policies[policy]['policy'] )
                report_node = etree.Element("Report") 
                root.append( report_node  )
                
                for host in chunk:
                    report_node.append( host )
                    
                safe_policy_name = str(policy)
                safe_policy_name = re.sub('[^\w_.)( -]', '', safe_policy_name)
                report_name = "{}/results/merged_POLICY-{}_CHUNK-{}.nessus".format( 
                    os.path.dirname(os.path.realpath(__file__)), 
                    safe_policy_name,
                    str(chunk_index).zfill(3)
                )
                    
                report_task_id = "{}-{}-{}-{}-{}-{}".format( secrets.token_hex(4), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(2), secrets.token_hex(14) )
                report_node = root.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'report_task_id']/value")
                if report_node:
                    report_node[0].text = report_task_id
                
                targets = []
                for current_host in root.xpath("/NessusClientData_v2/Report/ReportHost"):
                     targets.append(next(iter(current_host.xpath("./@name")),''))
                targets = sorted(list(set(targets)))
                target_node = root.xpath("/NessusClientData_v2/Policy/Preferences/ServerPreferences/preference[./name = 'TARGET']/value")
                if target_node:
                    target_node[0].text = ",".join(targets)
                
                my_tree = etree.ElementTree(root)
                with open(report_name, 'wb') as f:
                    f.write(etree.tostring(my_tree))
    
        status = "Merged Nessus File(s) are in results folder"
        Utils.update_status(application_path, main_app, status, 0 )
        print(status)    
        