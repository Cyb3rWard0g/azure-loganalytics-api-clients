# Azure Log Analytics API Clients

A few scripts I put together to send and receive data from an Azure Log Analytics workspace leveraging the Azure Monitor HTTP Data Collector API

## Getting Started

### Python

1. Install Python 3.8.
1. Install required packages.
    * `pip install -r requirements.txt`
2. Execute the script to ingest logs to LA Workspace.
    * `python3 ala-python-data-producer.py -w <WorkspaceID> -k <SharedKey> -l "onesample" -f <JSON dataset> -v`

# To-Do

* [ ] Python Data Consumer
* [ ] Powershell Data Consumer
* [ ] C# Data Producer and Consumer
