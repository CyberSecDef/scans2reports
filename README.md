# Overview

![Scans To Reports](https://github.com/CyberSecDef/scans2reports/blob/master/screenshots/scans_to_reports.png?raw=true)

Scans To Reports is the current version of a set of projects that have been ongoing since 2015.  The first version of this tool was a PowerShell v2.0 script that would parse scans and generate an eMASS compatible POAM/RAR.  The overall goal of that project has been maintained and enhanced over the various iterations, culminating in this new cross platform tool suite.  The current release has been completely rewritten in Python and cross-compiled into platform specific binaries, support Windows, Linux and MacOS systems.  

The Scans To Reports Generator makes it easy to verify the overall compliance of your systems and to glean useful information about all your assets.  This tool is able to parse Tenable ACAS/Nessus Scans, DISA STIG Checklists, SPAWAR SCAP Compliance Checker XCCDF files, CSV Mitigation Answer Files and Excel POAM/eMASS Exports.  The final reports are also generated in a format that is compatible with eMASS POAM imports and artifact uploads.  These reports make it much easier to clearly see the overall security posture of your program.
