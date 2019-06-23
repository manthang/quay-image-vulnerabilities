This script accepts a list of Quay image references defined in JSON format. See `input.json` as an example file.

The main program `vulscan.py` does:
* parse the input file to form the usable URLs to talk with Quay API endpoints. See more <https://docs.quay.io/api/swagger>
* parse the responses from Quay API server, and filter only for vulnerable packages in each scanned image.
* write the result file to current directory in JSON format.

--
TODO:
 + Support input file from user-provided path or stdin
 + JSON format checking before processing

--
Testing environment:
 + Python 3.6.5 on macOS 10.14.5