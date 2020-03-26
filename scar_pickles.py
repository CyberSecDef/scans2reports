import sys
import os
import pickle
from collections.abc import Iterable


class SCARPickles(dict):

    @classmethod
    def loader(cls,file):
        if os.path.isfile(file):
            with open(file, "rb") as f:
                return pickle.load(f)
        else:
            return False

    def __init__(self, pickle_name, data = None):
        dict.__init__(self)
        
        if getattr(sys, 'frozen', False):
            self['application_path'] = sys._MEIPASS
        else:
            self['application_path'] = os.path.dirname(os.path.abspath(__file__))
        
        self['pickle_name'] = pickle_name
        
        if data and isinstance(data, Iterable):
            for key in data.keys():
                self[key] = data[key]

        self.save()
    
    def dump(self):
        results = {}
        for key in self.keys():
            results[key] = self[key]
        return results
    
    def list(self):
        return list(self.keys())
        
    def get(self, key):
        if key in self.keys():
            return self[key]
        else:
            return None

    def set(self, key, value):
        self[key] = value
        self.save()
        
    def append(self, key, value):
        if key in self.keys() and isinstance(self[key], Iterable):
            self[key].append(value)
        self.save()
        
    def save(self):
        if 'application_path' in self.keys() and 'pickle_name' in self.keys():
            with open(os.path.join(self['application_path'], "data", f"{self['pickle_name']}.pkl"), "wb") as f:
                pickle.dump(self, f)