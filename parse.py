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

# Extract method which used in product table for cpe verison

def extract_from_uri(cpe,version):
    prod_name = ''
    if version is None or version is '':
        cpe_arr = cpe.split(':')[3:6]
        prod_name = cpe_arr[0] + ':' + cpe_arr[1]
        version = cpe_arr[2]
    else:
        cpe_arr = cpe.split(':')[3:5]
        prod_name = cpe_arr[0] + ':' + cpe_arr[1]
    return prod_name, version

# End

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

for cves in all_cves:

    cve_id = cves['cve']['CVE_data_meta']['ID']
    description=""
    for descriptions in cves['cve']['description']['description_data']:
                description = description + descriptions['value']
    published_date = cves['publishedDate']
    last_modified_date = cves['lastModifiedDate']

    # print('published_date ' + published_date + 'description ' + description + 'last_modified_date' + last_modified_date + 'cve_id' + cve_id)
    
    cvss = tables.store_cvss(cve_id, description, published_date, last_modified_date)

    impact_score_2, impact_score_3, base_score_2, base_score_3 = '','','',''
    if 'baseMetricV2' in cves['impact']:
        impact_score_2 = cves['impact']['baseMetricV2']['impactScore']
        base_score_2 = cves['impact']['baseMetricV2']['cvssV2']['baseScore']
    if 'baseMetricV3' in cves['impact']: 
        impact_score_3 = cves['impact']['baseMetricV3']['impactScore']
        base_score_3 = cves['impact']['baseMetricV3']['cvssV3']['baseScore']
    
    # print('impact_score_2 ' + str(impact_score_2) + 'base_score_2 ' + str(base_score_2))
    
    tables.store_impact(cve_id, impact_score_2, base_score_2, impact_score_3, base_score_3)
    # print(cve_id)

    try:
        cpe_list_length=len(cves['configurations']['nodes'])
        if (cpe_list_length !=0):
            for i in range(0,cpe_list_length):
                if 'children' in cves['configurations']['nodes'][i]:
                    cpe_child_list_length=len(cves['configurations']['nodes'][i]['children'])
                    if (cpe_child_list_length !=0):
                        for j in range(0,cpe_child_list_length):
                            if('cpe_match' in cves['configurations']['nodes'][i]['children'][j]):
                                cpes = cves['configurations']['nodes'][i]['children'][j]['cpe_match']
                                for cpe in cpes:
                                    cpe22Uri, cpe23Uri, product_version, prod_name, is_vulnerable = '','','','',''
                                    if 'cpe22Uri' in cpe:
                                        cpe22Uri = cpe['cpe22Uri']
                                        # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                        if 'versionEndIncluding' in cpe:
                                            product_version = cpe['versionEndIncluding']
                                        prod_name, prod_version = extract_from_uri(cpe22Uri, product_version)
                                        is_vulnerable = str(cpe['vulnerable'])
                                        # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)

                                    if 'cpe23Uri' in cpe:
                                        cpe23Uri = cpe['cpe23Uri']
                                        # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                        if 'versionEndIncluding' in cpe:
                                            product_version = cpe['versionEndIncluding']
                                        prod_name, prod_version = extract_from_uri(cpe23Uri, product_version)
                                        is_vulnerable = str(cpe['vulnerable'])
                                        # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)
                                    product = tables.store_product(cpe22Uri, cpe23Uri, prod_name, prod_version, is_vulnerable) 
                                    tables.store_cvss_product(cvss, product)                                  
                else:
                    if('cpe_match' in cves['configurations']['nodes'][i]):
                        cpes = cves['configurations']['nodes'][i]['cpe_match']
                        for cpe in cpes:
                            cpe22Uri, cpe23Uri, product_version, prod_name, is_vulnerable = '','','','',''
                            if 'cpe22Uri' in cpe:
                                cpe22Uri = cpe['cpe22Uri']
                                # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                if 'versionEndIncluding' in cpe:
                                    product_version = cpe['versionEndIncluding']
                                prod_name, prod_version = extract_from_uri(cpe22Uri, product_version)
                                is_vulnerable = str(cpe['vulnerable'])
                                # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)
                            if 'cpe23Uri' in cpe:
                                cpe23Uri = cpe['cpe23Uri']
                                # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                if 'versionEndIncluding' in cpe:
                                    product_version = cpe['versionEndIncluding']
                                prod_name, prod_version = extract_from_uri(cpe23Uri, product_version)
                                is_vulnerable = str(cpe['vulnerable'])
                                # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)
                            product = tables.store_product(cpe22Uri, cpe23Uri, prod_name, prod_version, is_vulnerable)
                            tables.store_cvss_product(cvss, product)
                    else:
                        cpe_inner_list_length=len(cves['configurations']['nodes'])
                        if (cpe_inner_list_length!=0):
                            for k in range(0,cpe_inner_list_length):
                                if('cpe_match' in cves['configurations']['nodes'][i]):
                                    cpes = cves['configurations']['nodes'][i]['cpe_match']
                                    for cpe in cpes:
                                        cpe22Uri, cpe23Uri, product_version, prod_name, is_vulnerable = '','','','',''
                                        if 'cpe22Uri' in cpe:
                                            cpe22Uri = cpe['cpe22Uri']
                                            # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                            if 'versionEndIncluding' in cpe:
                                                product_version = cpe['versionEndIncluding']
                                            prod_name, prod_version = extract_from_uri(cpe22Uri, product_version)
                                            is_vulnerable = str(cpe['vulnerable'])
                                            # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)
                                        if 'cpe23Uri' in cpe:
                                            cpe23Uri = cpe['cpe23Uri']
                                            # temp_prod = cpe['cpe23Uri'].replace('cpe:2.3:o:','').replace('cpe:2.3:a:','').split('*', 1)[0].strip(':')
                                            if 'versionEndIncluding' in cpe:
                                                product_version = cpe['versionEndIncluding']
                                            prod_name, prod_version = extract_from_uri(cpe23Uri, product_version)
                                            is_vulnerable = str(cpe['vulnerable'])
                                            # print('prod_name ' + prod_name + '>>>>product_version '+ prod_version + ' is vulnerable ' + is_vulnerable + ' cve_id' + cve_id)
                                        product = tables.store_product(cpe22Uri, cpe23Uri, prod_name, prod_version, is_vulnerable)
                                        tables.store_cvss_product(cvss, product)
    except Exception as e:
        print('Something went wrong. Please check the above code' + e) #check it
f.close()
    

