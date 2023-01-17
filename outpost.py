import argparse
import json
import os
import re
import boto3
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--command', type=str, required=True, help='Commands: generate, report, testaccounts')
parser.add_argument('--config-creds', action='store_true', help='Configure creds while using the generate command')

# Generator
parser.add_argument('--assume', type=str, help='Optional assume role ARN, use ACCOUNT_ID for placeholder. (i.e. arn:aws:iam::ACCOUNT_ID:role/ROLENAME')
parser.add_argument('--accounts', type=str, help='File containing account numbers (one account per line)')
parser.add_argument('--primary', default=None, type=str, help='Primary account used to assume roles')
parser.add_argument('--token', default=None, type=str, help='Primary AWS session token')
parser.add_argument('--secret-key', default=None, type=str, help='Primary AWS secret access key')
parser.add_argument('--access-key', default=None, type=str, help='Primary AWS access key')

# Reporter
parser.add_argument('--directory', type=str, help='Parent directory of ScoutSuite report(s)')
parser.add_argument('--risk', type=str, default='danger', help='Select finding risk to report: danger, warning')
parser.add_argument('--project', type=str, default='aws-report', help='Project name for report details')


def main(args):
    if args.command == 'report':
        #print('Reporting...')
        if args.directory is None:
            #print('Error...')
            parser.error('Error with --command report: requires --directory')

        #print('Trying...')
        findings = find_results_files(args.directory)
        #pretty_print_findings(findings)
        show_findings_by_risk(findings, args.risk, args.directory, args.project)
        save_finding_details(args.directory, findings, args.risk)

    elif args.command == 'testaccounts':

        if args.accounts is None:
            parser.error('Error with --command testaccounts: requires --accounts')

        accounts = load_accounts(args.accounts)
        test_accounts(accounts)

    elif args.command == 'generate':
        configure_creds_ready = False

        if args.assume is None or args.accounts is None or args.primary is None:
            parser.error('Error with --command generate: requires --assume, --accounts, --primary')

        if args.config_creds:
            if args.primary is None or args.secret_key is None or args.access_key is None:
                parser.error('Error with --config-creds: requires --primary, --access-key, and --secret-key')
            configure_creds_ready = True

        accounts = load_accounts(args.accounts)
        config = generate_config(args.assume, accounts, args.primary)

        print('Copy the following configuration entries into ~/.aws/config or %USERPROFILE%\.aws\config')
        print('----------------------------------------------------------------------------------------')
        for config_entry in config:
            entry = json.loads(config_entry)
            profile_name = entry['profile_name']
            role_arn = entry['role_arn']
            source_profile = entry['source_profile']

            print(
                f'[profile {profile_name}]\n',
                'output = json\n',
                'cli_pager = \n',
                f'role_arn = {role_arn}\n',
                f'source_profile = {source_profile}\n'
            )

        if configure_creds_ready:
            configure_creds(args.primary, args.access_key, args.secret_key, args.token)


def load_accounts(account_file):
    with open(account_file,'r') as fh:
        return [x.strip() for x in fh.readlines()]


def generate_config(arn, accounts, primary):
    aws_config = []
    for account in accounts:
        new_arn = re.sub('account_id', account, arn, flags=re.IGNORECASE)

        config_entry = json.dumps(
            {
                'profile_name': account,
                'role_arn': new_arn,
                'source_profile': primary
            }
        )
        aws_config.append(config_entry)
    return aws_config


def test_accounts(accounts):
    print(f'Testing accounts: {len(accounts)}')
    print('----------------------------------------------------------------------------------------')
    for account in accounts:
        try:
            session = boto3.Session(profile_name=account)
            sts = session.client('sts')
            identity = sts.get_caller_identity()

            user_id = identity['UserId']
            arn = identity['Arn']
            print(f'Account: {account} -> Status: VALID')
        except:
            print(f'Account: {account} -> Status: UNAUTHORIZED OR INVALID\n')


def configure_creds(primary, access_key, secret_key, session_token=None):
    token = ''

    if session_token is not None:
        token = f'aws_session_token={session_token}'

    print('Copy the following credentials into ~/.aws/credentials or %USERPROFILE%\.aws\credentials')
    print('----------------------------------------------------------------------------------------')

    print(
        f'[{primary}]\n',
        'output=json\n',
        'cli_pager=\n',
        f'aws_access_key_id={access_key}\n',
        f'aws_secret_access_key={secret_key}\n',
        f'{token}\n'
    )

def friendly_finding_name(description):
    description = re.sub(r"[^a-zA-Z0-9 ]","",description)
    return description

def file_finding_name(description):
    description = re.sub(r"[^a-zA-Z0-9 ]","", description)
    description = description.replace(' ','_').lower()
    return description

def show_findings_by_risk(findings, risk, directory, project):
    append_report_details(directory, project, 'FSH:Amazon Web Services (AWS) Findings\n')

    for finding in findings:
        details = findings[finding]

        if details['level'].lower() == risk.lower():
            accounts = details['accounts']
            total_accounts = len(details['accounts'])
            description = details['description']
            rationale = details['rationale']
            service = details['service']
            compliance = details['compliance']
            remediation = details['remediation']

            if not remediation:
                remediation = '{{ TODO Fill in recommendations }}'

            clean_finding = friendly_finding_name(description)
            file_finding = file_finding_name(description)
            finding = f'{clean_finding}'
            observation = f'Observation:\nBHIS observed that {total_accounts} active AWS account(s) had {service} resources with security issues pertaining to {description}.\n\n'
            observation += f'Details pertaining to the affected resources have been recorded in the data archive file named: {file_finding}.txt\n\n'
            for acct in accounts:
                observation += f'{acct}\n'

            discussion = f'Discussion:\n {rationale}\n{{ TODO Explain more information }}\n'
            recommendation = f'Recommendations:\nIn efforts to remediate these issues, BHIS suggests:\n- {remediation}'

            finding_details = f'{finding}\n\n{observation}\n\n{discussion}\n\n{recommendation}\n\n'
            append_report_details(directory, project, f'SEVM:{finding_details}\n')

            print(finding_details)
            print('----------------------------------------------------------------------------')

def pretty_print_findings(findings):
    print(json.dumps(findings, sort_keys=True, indent=4))

def pretty_findings(findings):
    return json.dumps(findings, sort_keys=True, indent=4)

def check_finding(dict, key):
    if key in dict.keys():
        return True
    else:
        return False

def enum_finding(findings, include_value=True, recursive=True):
    stack = list(findings.items())
    visited = set()
    while stack:
        k, v = stack.pop()
        if isinstance(v, dict) and recursive:
            if k not in visited:
                stack.extend(v.items())
        else:
            if include_value:
                print(f'{k}: {v}')
            else:
                print(k)
        visited.add(k)

def append_report_details(directory, project, details):
    save_folder = f'{directory}/data_archive'
    report_path = f'{save_folder}/{project}.txt'
    if not os.path.exists(save_folder):
        os.mkdir(save_folder)

    with open(report_path,'a+') as rf:
        rf.write(details)

def save_finding_details(directory, findings, risk):
    save_folder = f'{directory}/data_archive'
    if not os.path.exists(save_folder):
        os.mkdir(save_folder)

    for finding in findings:
        details = findings[finding]

        if details['level'].lower() == risk.lower():
            accounts = details['accounts']
            description = details['description']

            file_name = file_finding_name(description)
            with open(f'{save_folder}/{file_name}.txt', 'a+') as sf:
                for account_id in accounts:
                    for resource_id in details['accounts'][account_id]['account_resources']:
                        sf.write(f'{account_id},{resource_id}\n')

def save_service_details(directory, account_id, service_name, service_details):
    save_folder = f'{directory}/services'
    if not os.path.exists(save_folder):
        os.mkdir(save_folder)

    with open(f'{save_folder}/{service_name}_{account_id}.json', 'w') as sf:
        sf.write(json.dumps(service_details))

def find_results_files(directory):
    all_results = [path for path in Path(directory).rglob('scoutsuite_results*.js')]
    all_findings = {}
    service_data_cats = {}

    for all_result in all_results:
        with open(all_result.resolve(), 'r') as rf:
            next(rf)
            json_results = json.load(rf)

            account_id = json_results['account_id']
            provider_name = json_results['provider_name']

            for service_name in json_results['services']:
                service_details = json_results['services'][service_name]

                if not service_name in service_data_cats.keys():
                    service_data_cats[service_name] = set()

                for service_detail in service_details:
                    service_data_cats[service_name].add(service_detail)

                for finding_name in json_results['services'][service_name]['findings']:
                    finding = json_results['services'][service_name]['findings'][finding_name]

                    finding_path = finding.get('path', '')
                    finding_rationale = finding.get('rationale', '')
                    finding_remediation = finding.get('remediation', '')
                    finding_service = finding.get('service', '')
                    finding_checked_items = finding.get('checked_items', '')
                    finding_compliance = finding.get('compliance', '')
                    finding_description = finding.get('description', '')
                    finding_flagged_items = finding.get('flagged_items', '')
                    finding_items = finding.get('items', '')
                    finding_level = finding.get('level', '')

                    if not check_finding(all_findings, finding_description):
                        if finding_flagged_items > 0:
                            all_findings[finding_description] = {}
                            all_findings[finding_description]['rationale'] = finding_rationale
                            all_findings[finding_description]['remediation'] = finding_remediation
                            all_findings[finding_description]['service'] = finding_service
                            all_findings[finding_description]['compliance'] = finding_compliance
                            all_findings[finding_description]['description'] = finding_description
                            all_findings[finding_description]['level'] = finding_level
                            all_findings[finding_description]['accounts'] = {}

                    if finding_flagged_items > 0:
                        all_findings[finding_description]['accounts'][account_id] = {}
                        all_findings[finding_description]['accounts'][account_id]['account_resources'] = finding_items
                        all_findings[finding_description]['accounts'][account_id]['checked_items'] = finding_checked_items
                        all_findings[finding_description]['accounts'][account_id]['flagged_items'] = finding_flagged_items

    return all_findings


if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
