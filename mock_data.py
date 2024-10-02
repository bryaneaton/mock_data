#!/usr/bin/env python3
import string
from datetime import datetime
from random import randint, choice

from faker import Faker
import argparse
from pathlib import Path
import json
import csv

fake = Faker()


def generate_realistic_docker_repo():

    # Sample repo names
    repo_names = ['lscr.io/linuxserver', 'docker.io', 'regscalecontainerregistry.azurecr.io', 'mcr.microsoft.com']
    # Sample realistic repository names
    image_names = [
        'nginx',
        'ubuntu',
        'alpine',
        'node',
        'python',
        'redis',
        'mysql',
        'postgres',
        'nginx',
        'busybox',
        'regscale',
        'mssql-tools',
        'python'
    ]

    repo_name = choice(repo_names)
    # Randomly select a base repository
    image_name = choice(image_names)

    # Optional: Add a tag (e.g., a version number)
    tag = f"v{randint(1, 10)}.{randint(0, 9)}.{randint(0, 9)}"

    return repo_name, image_name, tag

def generate_docker_image_id(length=12):
    characters = string.hexdigits[:-6]  # Use only hex characters (0-9, a-f)
    return ''.join(choice(characters) for _ in range(length))



def generate_cve():
    cves = []
    cve_path = Path(f"./cve")
    for file in cve_path.iterdir():
        with open(file, 'r') as f:
            data = json.load(f)
        cves.append({'name': file.stem,
                     'publishedDate': data.get('published'),
                     'description': data.get('descriptions')[0].get('value', 'unknown') if data.get('descriptions') else 'unknown',})
    return cves

def gen_header_from_config(config_path):
    header = []
    if config_path.exists():
        with open(config_path, 'r') as f:
            data = json.load(f)
            for key in data.get('fields', {}).keys():
                header.append(key)
    return header

def open_config(config_path):
    if config_path.exists():
        with open(config_path, 'r') as f:
            data = json.load(f)
            return data
    return {}


import random


def generate_random_cvss_v2():
    # Define possible values for each metric
    access_vector = ['N', 'A', 'L']
    access_complexity = ['L', 'H']
    authentication = ['N', 'S', 'M']
    confidentiality = ['N', 'P', 'C']
    integrity = ['N', 'P', 'C']
    availability = ['N', 'P', 'C']

    # Randomly select values for each metric
    cvss_vector = (
        f"AV:{random.choice(access_vector)} "
        f"AC:{random.choice(access_complexity)} "
        f"Au:{random.choice(authentication)} "
        f"C:{random.choice(confidentiality)} "
        f"I:{random.choice(integrity)} "
        f"A:{random.choice(availability)}"
    )

    return cvss_vector


def generate_random_cvss_v3():
    # Define possible values for each metric
    attack_vector = ['N', 'A', 'L', 'P']
    attack_complexity = ['L', 'H']
    privileges_required = ['N', 'L', 'H']
    user_interaction = ['N', 'R']
    scope = ['U', 'C']
    confidentiality = ['N', 'L', 'H']
    integrity = ['N', 'L', 'H']
    availability = ['N', 'L', 'H']

    # Randomly select values for each metric
    cvss_vector = (
        f"AV:{random.choice(attack_vector)} "
        f"AC:{random.choice(attack_complexity)} "
        f"PR:{random.choice(privileges_required)} "
        f"UI:{random.choice(user_interaction)} "
        f"S:{random.choice(scope)} "
        f"C:{random.choice(confidentiality)} "
        f"I:{random.choice(integrity)} "
        f"A:{random.choice(availability)}"
    )

    return cvss_vector

def generate_random_float():
    return round(random.uniform(0.0, 9.9), 1)

def generate_csv(config_path):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'sys_dig_sample_{timestamp}.csv'
    # make directory
    Path.cwd().joinpath('sysdig', 'generated').mkdir(parents=True, exist_ok=True)
    config = open_config(config_path)
    with open(Path.cwd() / 'sysdig' / 'generated' / filename, 'w', newline='') as file:
        writer = csv.writer(file)
        header = gen_header_from_config(config_path)
        writer.writerow(header)  # Write the header
        # write random # of rows
        for i in range(randint(5, 30)):
            row = []
            for field in header:
                cve = fake.random_element(cves)
                if config.get('special', {}).get(field) == 'cve':
                    row.append(cve.get('name'))
                elif field.lower() == 'severity':
                    row.append(fake.random_element(config.get('special', {}).get(field, [])))
                elif field.lower() == 'image id':
                    row.append(generate_docker_image_id())
                elif field.lower() == 'image name':
                    row.append(generate_realistic_docker_repo()[1])
                elif field.lower() == 'image tag':
                    row.append(generate_realistic_docker_repo()[2])
                elif field.lower() == 'vulnerability type':
                    row.append(fake.random_element(config.get('special', {}).get(field, [])))
                elif field.lower() == 'cvss v2 vector':
                    row.append(generate_random_cvss_v2())
                elif field.lower() == 'cvss v3 vector':
                    row.append(generate_random_cvss_v3())
                elif 'base score' in field.lower():
                    row.append(generate_random_float())
                elif 'published date' in field.lower():
                    dt = datetime.strptime(cve.get('publishedDate'), "%Y-%m-%dT%H:%M:%S.%f")
                    row.append(dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
                elif 'date' in field.lower():
                    if config.get('fields').get(field) == 'date':
                        row.append(fake.date_this_year().strftime('%m/%d/%Y'))
                    else:
                        row.append(fake.date_this_year().strftime('%Y-%m-%dT%H:%M:%SZ'))
                elif config.get('fields', {}).get(field) == 'int':
                    row.append(randint(1, 100))
                elif 'description' in field.lower():
                    row.append(cve.get('description'))
                else:
                    row.append('unknown')
            writer.writerow(row)


if __name__ == '__main__':
    # take a single argument from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--file_type', help='Type of file to generate', type=str)
    args = parser.parse_args()
    # args must be present
    if not args.file_type:
        print('Please provide a file type to generate')
        exit(1)
    # find config in dir
    file_type = str(args.file_type)
    print('generate file type:', file_type)
    cves = generate_cve()
    config = Path.cwd() / 'sysdig' / 'config.json'
    generate_csv(config)
