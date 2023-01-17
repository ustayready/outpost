# Outpost
## AWS Testing and Reporting Management

Outpost is a simple tool to generate AWS configuration files for AssumeRole, a testing capability for verifying accounts work, and a report generator for ScoutSuite scan results.

- Run ScoutSuite
- Parse the results
- ✨Generate Report Findings✨

## Installation

Outpost requires Python3 and boto3 to run.

Install the dependencies.

```sh
virtualenv -p python3 .
source bin/activate
pip install -r requirements.txt
python outpost.py --help
```

## Usage

```sh
usage: outpost.py [-h] --command COMMAND [--config-creds] [--assume ASSUME] [--accounts ACCOUNTS] [--primary PRIMARY] [--token TOKEN]
                  [--secret-key SECRET_KEY] [--access-key ACCESS_KEY] [--directory DIRECTORY] [--risk RISK] [--project PROJECT]

optional arguments:
  -h, --help            show this help message and exit
  --command COMMAND     Commands: generate, report, testaccounts
  --config-creds        Configure creds while using the generate command
  --assume ASSUME       Optional assume role ARN, use ACCOUNT_ID for placeholder. (i.e. arn:aws:iam::ACCOUNT_ID:role/ROLENAME
  --accounts ACCOUNTS   File containing account numbers (one account per line)
  --primary PRIMARY     Primary account used to assume roles
  --token TOKEN         Primary AWS session token
  --secret-key SECRET_KEY
                        Primary AWS secret access key
  --access-key ACCESS_KEY
                        Primary AWS access key
  --directory DIRECTORY
                        Parent directory of ScoutSuite report(s)
  --risk RISK           Select finding risk to report: danger, warning
  --project PROJECT     Project name for report details
```

## Example Usage
Outpost will recursively go through all report folders in search of the `scoutsuite_results*.js` files for parsing. This means if the root folder for reports contains separate ScoutSuite reports, you should provide the root folder as the `--directory` flag.
An example structure could be:
~/Engagements/CustomerName/reports/account1/
~/Engagements/CustomerName/reports/account2/
~/Engagements/CustomerName/reports/account3/
You would provide the following command to parse all 3 account reports:
```sh
python outpost.py --command report --directory ~/Engagements/CustomerName/reports/ --project Customer_2022-123
```

## Results
The tool creates a folder called `data_archive` within the root folder of the ScoutSuite results. It will generate a file called `<project name>.txt` with the findings that will copy/paste directly into the report. Additionally, supplemental files for each finding will be created within the folder which outline the account and specific resources that are vulnerable. 

