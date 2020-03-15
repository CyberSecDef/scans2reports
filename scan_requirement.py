""" Scan Requirement Module """
class ScanRequirement(dict):
    """ scan requirement container based on dict """
    port = ""
    mitigation = ""
    impact = ""
    req_title = ""
    plugin_id = ""
    vuln_id = ""
    grp_id = ""
    rule_id = ""
    rule_ver = ""
    comments = ""
    finding_details = ""
    cci = ""
    description = ""
    fix_id = ""
    check_id = ""
    scan_user = ""
    check_text = ""
    ia_controls = ""
    rmf_controls = ""
    assessments = ""
    solution = ""
    references = ""
    severity = ""
    status = ""
    resources = ""
    credentialed = False
    port_range = ""
    
    def __init__(self, data):
        """ Constructor """
        dict.__init__(self)
        for key in data:
            if key in dir(self):
                self[key] = data[key]