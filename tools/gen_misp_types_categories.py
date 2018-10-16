#!/usr/bin/env python3
'''
by Christophe Vandeplas

Takes the MISP categories and types and saves them in the MISP-book, misp-website and PyMISP format.

# TODO - do some more data-validation between the mappings and defaults, and alert if we're missing something
'''

import json
import os
import re
import subprocess


def make_matrix_header(pos, max_cols):
    out = []
    out.append('|Category|')
    cur_pos = 0
    for category in categories:
        cur_pos += 1
        # skip if we are not there yet
        if cur_pos < pos + 1:
            continue
        # skip if we have reached the max cols
        if cur_pos > pos + max_cols:
            continue
        # we are in the right range
        out.append(' {} |'.format(category.replace('|', '&#124;')))
    out.append('\n')

    out.append('| --- |')
    cur_pos = 0
    for category in categories:
        cur_pos += 1
        # skip if we are not there yet
        if cur_pos < pos + 1:
            continue
        # skip if we have reached the max cols
        if cur_pos > pos + max_cols:
            continue
        # we are in the right range
        out.append(':---:|')
    out.append('\n')
    return out


def make_matrix_content(pos, max_cols):
    out = []
    for t in types:
        cur_pos = 0
        out.append('|{}|'.format(t.replace('|', '&#124;')))
        for category in categories:
            cur_pos += 1
            # skip if we are not there yet
            if cur_pos < pos + 1:
                continue
            # skip if we have reached the max cols
            if cur_pos > pos + max_cols:
                continue
            # we are in the right range
            if t in category_definitions[category]['types']:
                out.append(' X |')
            else:
                out.append(' |')
        out.append('\n')
    return out


# verify if the folders exist before continuing
folders = ['PyMISP', 'misp-book', 'misp-website', 'misp-rfc']
for folder in folders:
    if not os.path.isdir('../../' + folder):
        exit("Make sure you git clone all the folders before running the script: {}".format(folders))


# Extract categoryDefinitions and typeDefinitions
#################################################
# We do this by:
# - reading out the PHP file
# - extracting the variables in PHP code
# - using PHP to convert it to a JSON
# - read the JSON in python
with open('../app/Model/Attribute.php', 'r') as f:
    attribute_php_file = f.read()
re_match = re.search(r'\$categoryDefinitions\s?=\s?([^;]+);', attribute_php_file)
php_code = re_match.group(1)
category_definitions_binary = subprocess.run(['php', '-r', 'echo json_encode({});'.format(php_code)], stdout=subprocess.PIPE).stdout
category_definitions = json.loads(category_definitions_binary.decode('utf-8'))
categories = list(category_definitions.keys())
categories.sort()

re_match = re.search(r'\$typeDefinitions\s?=\s?([^;]+);', attribute_php_file)
php_code = re_match.group(1)
type_definitions_binary = subprocess.run(['php', '-r', 'echo json_encode({});'.format(php_code)], stdout=subprocess.PIPE).stdout
type_definitions = json.loads(type_definitions_binary.decode('utf-8'))
types = list(type_definitions.keys())
types.sort()


# Generate matrix and list
##########################
matrix_and_list = []

# build the matrix
col_count = len(categories)
col_max = 6
col_pos = 0
while col_pos < col_count:
    # make the header
    matrix_and_list += make_matrix_header(col_pos, col_max)
    # make the content
    matrix_and_list += make_matrix_content(col_pos, col_max)
    matrix_and_list.append('\n')
    col_pos += col_max


# build the Categories list
matrix_and_list.append("\n### Categories\n\n")
for category in categories:
    matrix_and_list.append("*   **{}**: {}\n".format(category.replace('|', '&#124;'), category_definitions[category]['desc'].replace('|', '&#124;')))

# build the Types list
matrix_and_list.append("\n### Types\n\n")
for t in types:
    matrix_and_list.append("*   **{}**: {}\n".format(t.replace('|', '&#124;'), type_definitions[t]['desc'].replace('|', '&#124;')))


# MISP-book
#############
# overwrite full file
print("Updating MISP book - ../misp-book/categories-and-types/README.md")
misp_book = ('<!-- toc -->\n'
             '\n'
             '### Attribute Categories vs. Types\n\n')
misp_book += ''.join(matrix_and_list)
with open('../../misp-book/categories-and-types/README.md', 'w') as f:
    f.write(misp_book)


# MISP-website
##############
# Replace the select content of the file
# Find the offset of the start header: "### MISP default attributes and categories"
# Find the offset of the end/next header:  "## MISP objects"
# Replace our new content in between
print("Updating MISP website - ../../misp-website/_pages/datamodels.md")
misp_website = []
store_lines = True
with open('../../misp-website/_pages/datamodels.md', 'r') as f:
    for line in f:
        # start marker
        if store_lines:
            misp_website.append(line)
        if line.startswith('### MISP default attributes and categories'):
            store_lines = False
            misp_website.append('\n### Attribute Categories vs. Types\n\n')
            misp_website += matrix_and_list
            misp_website.append('\n')
        elif line.startswith('## MISP objects'):
            store_lines = True
            misp_website.append(line)
with open('../../misp-website/_pages/datamodels.md', 'w') as f:
    f.write(''.join(misp_website))


# MISP-rfc
##########
# Replace the select content of the file
# Find the offset of the start header: "The list of valid category-type combinations is as follows:"
# Find the offset of the end/next header:  "Attributes are based on the usage within their different communities"
# Replace our new content in between
print("Updating MISP RFC - ../../misp-rfc/misp-core-format/raw.md")
misp_rfc = []
rfc_list = []
for category in categories:
    rfc_list.append('\n**{}**\n'.format(category))
    rfc_list.append(':   ')
    rfc_list.append(', '.join(category_definitions[category]['types']))
    rfc_list.append('\n')
with open('../../misp-rfc/misp-core-format/raw.md', 'r') as f:
    for line in f:
        # start marker
        if store_lines:
            misp_rfc.append(line)
        if 'The list of valid category-type combinations is as follows:' in line:
            store_lines = False
            misp_rfc += rfc_list
            misp_rfc.append('\n')
        elif 'Attributes are based on the usage within their different communities' in line:
            store_lines = True
            misp_rfc.append(line)
with open('../../misp-rfc/misp-core-format/raw.md', 'w') as f:
    f.write(''.join(misp_rfc))


# PyMISP
########
print("Updating PyMISP - ../../PyMISP/pymisp/data/describeTypes.json")
describe_types = {'result': {}}

describe_types['result']['types'] = types
describe_types['result']['categories'] = categories
describe_types['result']['category_type_mappings'] = {}
for category in categories:
    describe_types['result']['category_type_mappings'][category] = category_definitions[category]['types']
describe_types['result']['sane_defaults'] = {}
for t in types:
    if t not in describe_types['result']['sane_defaults']:
        describe_types['result']['sane_defaults'][t] = {}
    describe_types['result']['sane_defaults'][t]['default_category'] = type_definitions[t]['default_category']
    describe_types['result']['sane_defaults'][t]['to_ids'] = type_definitions[t]['to_ids']

with open('../../PyMISP/pymisp/data/describeTypes.json', 'w') as f:
    json.dump(describe_types, f, sort_keys=True, indent=2)


print("\nPlease initiate the git commit and push for each repository!")
print("- misp-book")
print("- misp-website")
print("- misp-rfc")
print("- PyMISP")
