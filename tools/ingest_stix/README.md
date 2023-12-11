# Ingest STIX

Python script to ingest STIX files on MISP.

## Requirements

There are a few requirements for this little python script to run, which are included in the MISP requirements:
- PyMISP
- Python 3.6+ (because PyMISP is Python 3.6+)
- Your API key

The recommended python setup for MISP is described within [the following documentation](https://www.circl.lu/doc/misp/updating-python/).

## Description

The aim of this small piece of code is to ingest STIX files.

In order to ingest STIX data into MISP, there are 2 end points to query, `/events/upload_stix` for STIX 1, and `/events/upload_stix/2` for STIX 2.  
The content of the STIX file to ingest has then to be passed in the body of the query.

The equivalent is available in PyMISP with the `upload_stix` method. The only difference is instead of passing the STIX content, the filename(s) of the file(s) to import are passed.

MISP creates then an event for each file ingested, using the [stix import](https://github.com/MISP/MISP/blob/2.4/app/files/scripts/stix2misp.py) or [stix2 import](https://github.com/MISP/MISP/blob/2.4/app/files/scripts/stix2/stix2misp.py) scripts.

## Usage

Depending of the python environment set in your MISP server, you will have to use the correct python command in order to be sure to reach the correct environment containing all the required libraries and dependencies:
- The recommended environment installed by default in most of our installation scripts, and virtual machine is a virtualenv available using `/var/www/MISP/venv/bin/python`
- If any other python environment is set instead, use the corresponding command. As an example, the built-in python3 provided with most of the linux distribution is available with a simple `python3`
**Please replace the python command in the next examples with your own settings if needed**

In order to connect to MISP, we need an URL and an API key.  
You can either pass those parameters when you call the `ingest_python.py` script, or put them within the `setup.json` file that is passed by default to the script, or event use another setup file as long as it contains the same required fields:
- `misp_url`: the URL of your MISP server
- `misp_key`: your MISP API key
- `misp_verifycert`: (`true` or `false`) to check or not the validity of the certificate

We also require here a STIX version and the path to the files to ingest (**Please use file names instead of directory names**)

As just mentioned, the setup file is used by default, and it avoids empty value issues for the required parameters. It is thus possible to simply run the following:
```
# STIX 1
python3 ingest_stix.py --version 1 --path _PATH_TO_YOUR_FILES_/stix_files*.xml

# STIX 2
python3 ingest_stix.py --version 2 --path _PATH_TO_YOUR_FILES_/stix_files*.json
```

But you can also overwrite the required MISP setups:
```
# Overwrite the SSL verification
python3 ingest_stix.py --version 1 --path _PATH_TO_YOUR_FILES_/stix_files*.xml --misp_verifycert

# Simply define all the parameters without using the setup file
python3 ingest_stix.py --version 1 --path _PATH_TO_YOUR_FILES_/stix_files*.xml --misp_url _MISP_URL_ --misp_key _YOUR_API_KEY_ --misp_verifycert
```

## Important information to be aware of

There are a few reasons why the data you want to ingest may be truncated or there may be missing information:
- The most obvious reason is the impossibility to map 100\% of the STIX objects and fields into MISP format.
- The import of STIX data into MISP is made to keep the uuids when possible. If you import an indicator with an uuid already existing in MISP, it will be skipped.
- If one file raises an error and is not imported at all, there might be an issue in the import script.

Once the ingestion is completed, each ingested file is also saved within the corresponding MISP event, so the initial data is available if needed.
