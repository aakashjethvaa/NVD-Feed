import os
print(os.getcwd())
from os import listdir
from os.path import isfile, join
import sys
import datetime
sys.path.append("..")
import zipfile
import json
from database import tables

# Copying the nvd data (jsondata directory) into schema.txt for testing purpose
# Also making data available in all_cves for further parsing and getting value

f = open("schema.txt", "a")
files = [f for f in listdir("jsondata/") if isfile(join("jsondata/", f))]
files.sort()
all_cves = []
for file in files:
    archive = zipfile.ZipFile(join("jsondata/", file), 'r')
    jsonfile = archive.open(archive.namelist()[0])
    cve_dict = json.loads(jsonfile.read())
    all_cves = all_cves + cve_dict['CVE_Items']
    jsonfile.close()

    # print('Output for' + file)
    # print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
    # print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
    # print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
    # print("CVE_data_numberOfCVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
    # print("CVE_data_type: " + str(cve_dict['CVE_data_type']))
    
    f.write('Output for' + file)
    f.write(json.dumps(cve_dict['CVE_Items'][0], sort_keys=True, indent=4, separators=(',', ': ')))
    jsonfile.close()

# End 