""" Scan Requirement Module """
class ScanRequirement(dict):
    """ scan requirement container based on dict """
    port = ""
    mitigation = ""
    impact = ""
    reqTitle = ""
    pluginId = ""
    vulnId = ""
    grpId = ""
    ruleId = ""
    ruleVer = ""
    comments = ""
    findingDetails = ""
    cci = ""
    description = ""
    fixId = ""
    checkId = ""
    scanUser = ""
    checkText = ""
    iaControls = ""
    rmfControls = ""
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
        pass
