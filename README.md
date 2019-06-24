This script accepts a list of Quay image references defined in JSON format. See `input.json` as an example file.

The main program `vulscan.py` does:
* parse the input file to form the usable URLs to talk with Quay API endpoints. See more <https://docs.quay.io/api/swagger>
* parse the responses from Quay API server, and filter only for vulnerable packages in each scanned image.
* write the result file to current directory in JSON format.

--
Usage:
1. Clone the repo.
2. Edit `input.json` to populate the image references you want to check vulnerabilities.
3. Run the program:
```
$ python3 vulscan.py
```
4. See the output in `result.json` file.

--
TODO:
 + Support input/output file from user-provided path or stdin
 + JSON format checking before processing

--
Testing environment:
 + Python 3.6.5 on macOS 10.14.5