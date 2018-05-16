Welcome to the kount-ris-python-sdk wiki!

# Kount Python RIS SDK #

Contains the Kount Python SDK, tests, and build/package routines.

## What is this repository for?

Kount's SDK helps integrate Kount's fraud fighting solution into your python app.
http://www.kount.com/fraud-detection-software

    Contains sources, tests, and resources for the Kount Python SDK
    SDK version: 2.0
    Python 2.7.13 and 3.5, 3.6.1 

How do I get set up?  

`pip install kount_ris_sdk`  

How to build the SDK and run integration tests in root directory?

   * First, you need to obtain configuration key from Kount.

   * Download the source code from https://github.com/Kount/kount-ris-python-sdk

   * Go to the root directory of the project and execute:

    pip install .[test]

   * Execute tests providing the configuration key on the command line

    pytest tests --conf-key={KEY}
   * or set shell environment

    export CONF_KEY={KEY}
    pytest tests

### How to use the SDK
For more information read the official docs:
http://kount-ris-sdk.readthedocs.io/en/latest/

### Setting up IDE projects
* Komodo IDE/Edit, Scite, Visual Studio - have automatic python integration

### Who do I talk to?

    Repo owner or admin
    Other community or team contact
