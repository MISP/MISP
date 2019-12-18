#!/usr/bin/env python3

# Sanitize the gitchangelog output

import shutil

inputFile = "../docs/Changelog.md"
outputFile = "/tmp/Changelog.tmp"

previousLine = ""

output_file = open(outputFile, "w")

for line in open(inputFile, "r"):
    if line == previousLine:
        previousLine = line
        continue
    else:
        output_file.write(line)
        previousLine = line

output_file.close()

shutil.move(outputFile, inputFile)
