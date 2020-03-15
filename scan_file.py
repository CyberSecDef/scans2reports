""" scan file module """
class ScanFile(dict):
    """ ScanFile container based on dict """
    duration = ""
    title = ""
    policy = ""
    scanner_edition = ""
    uuid = ""
    stigid = ""
    description = ""
    type = ""
    hostname = ""
    ip = ""
    mac = ""
    os = ""
    filename = ""
    total = ""
    score = ""
    scan_user = ""
    scan_date = ""
    version = ""
    release = ""
    
    credentialed = False
    requirements = []
    hosts = []
    feed = ''
    port_range = ""

    def __init__(self, data):
        """ Constructor """
        dict.__init__(self)
        self['requirements'] = []
        for key in data:
            if key in dir(self):
                self[key] = data[key]
            else:
                self[key] = ''

    def add_requirement(self, req):
        """ Adds a requirement to the internal array """
        self['requirements'].append(req)
