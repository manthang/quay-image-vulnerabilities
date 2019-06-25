import requests
import json
import time

url_temp = "https://quay.io/api/v1/repository/{}/{}/tag/{}/images"
scan_url_temp = "https://quay.io/api/v1/repository/{}/{}/image/{}/security?vulnerabilities=true"

# Load json input file
with open('input.json') as json_file:  
    data = json.load(json_file)
    for d in data:
        d['Vulnerabilities'] = []

        # measure elapsed time for responses from Quay API
        start = time.time()

        # Form the URLs with the values of the keys <Organisation, Repository, Tag>
        # Make HTTP API requests to https://quay.io/api/v1/repository/<org>/<repo>/tag/<tag>/images
        resp = requests.get(url_temp.format(d.get("Organisation"), d.get("Repository"), d.get("Tag"))) 
        id = (json.loads(resp.text)['images'])[0]['id']

        end = time.time()
        print("The time response for query image IDs from Quay API is in seconds: " + str(end - start))

        start = time.time()
        # Form the URLs for scanning: https://quay.io/api/v1/repository/<org>/<repo>/image/<image_id>/security?vulnerabilities=true    
        # Make HTTP API requests to <secscan> endpoint
        scan_resp = requests.get(scan_url_temp.format(d.get("Organisation"), d.get("Repository"), id))

        end = time.time()
        print("The time response for query (vulnerable) package details from Quay API is in seconds: " + str(end - start))
        
        # Filter vulnerable packages in each scanned image
        y = 0
        for e in (json.loads(scan_resp.text)['data']['Layer']['Features']):
            if 'Vulnerabilities' in e:
                for v in e['Vulnerabilities']:
                    v['PackageName'] = e['Name']
                    data[y]['Vulnerabilities'].append(v)
        y = y + 1

    # Write a json output file to current directory
    with open('result.json', 'w') as outfile:  
        json.dump(data, outfile, indent=4)

