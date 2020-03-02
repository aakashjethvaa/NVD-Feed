import requests
import re

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
data = r.text

# Printing the data for testing
#print(data)

for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
    print(filename)
    r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
    with open("jsondata/" + filename, 'wb') as f:
        for chunk in r_file:
            f.write(chunk)