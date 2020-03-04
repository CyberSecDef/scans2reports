""" scan file module """
class ScanFile(dict):
    """ ScanFile container based on dict """
    duration = ""
    title = ""
    policy = ""
    scannerEdition = ""
    uuid = ""
    stigid = ""
    description = ""
    type = ""
    hostname = ""
    ip = ""
    mac = ""
    os = ""
    fileName = ""
    total = ""
    score = ""
    scanUser = ""
    scanDate = ""
    version = ""
    release = ""
    open = 0
    closed = 0
    notApplicable = 0
    notReviewed = 0
    error = 0
    catI = 0
    catII = 0
    catIII = 0
    catIV = 0
    missing_cf = 0
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
