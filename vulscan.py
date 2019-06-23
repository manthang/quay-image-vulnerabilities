import requests
import json

url_temp = "https://quay.io/api/v1/repository/{}/{}/tag/{}/images"
urls     = []
resp     = []

scan_url_temp = "https://quay.io/api/v1/repository/{}/{}/image/{}/security?vulnerabilities=true"
scan_urls     = []
scan_resp     = []

# List of container image IDs to scan vulnerabilities
ids  = []

# Load json input file, then form the URLs with the values of the keys <Organisation, Repository, Tag>
with open('input.json') as json_file:  
    data = json.load(json_file)
    for d in data:
        urls.append(url_temp.format(d.get("Organisation"), d.get("Repository"), d.get("Tag")))
        d['Vulnerabilities'] = []
    
    # Make HTTP API requests to https://quay.io/api/v1/repository/<org>/<repo>/tag/<tag>/images
    for u in urls:
        resp.append(requests.get(u))
    
    # Extract ID of the top-layer image, then store each in the list
    for r in resp:
        ids.append(
            (json.loads(r.text)['images'])[0]['id']
        )

    # Form the URLs for scanning: https://quay.io/api/v1/repository/<org>/<repo>/image/<image_id>/security?vulnerabilities=true
    i = 0
    for d in data:
        scan_urls.append(scan_url_temp.format(d.get("Organisation"), d.get("Repository"), ids[i]))
        i = i + 1
    
    # Make HTTP API requests to <secscan> endpoint
    for s in scan_urls:
        scan_resp.append(requests.get(s))

    # Filter vulnerable packages in each scanned image
    y = 0
    for r in scan_resp:
        for e in (json.loads(r.text)['data']['Layer']['Features']):
            if 'Vulnerabilities' in e:
                for v in e['Vulnerabilities']:
                    v['PackageName'] = e['Name']
                    data[y]['Vulnerabilities'].append(v)
        y = y + 1
    
    # Write a json output file to current directory
    with open('result.json', 'w') as outfile:  
        json.dump(data, outfile, indent=4)


