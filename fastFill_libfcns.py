#!/usr/bin/env python

import re

pfaSpecification = open("pfa-specification-source.tex").read()

for line in open("libfcns.tex"):
    m = re.match(r"^    {(.+)}{(\\hypertarget.+)}%$", line)
    if m is not None:
        name, replacement = m.groups()
        libfcnName = r"\libfcn{" + name + "}"
        if libfcnName in pfaSpecification:
            pfaSpecification = pfaSpecification.replace(libfcnName, replacement)
        else:
            print name, "in libfcns.tex but not in pfa-specification-source.tex"

for name in re.findall(r"\\libfcn{([^}]+)}", pfaSpecification):
    print name, "in pfa-specification-source.tex but not libfcns.tex"

if "n" not in raw_input("overwrite pfa-specification.tex [Y/n]? ").lower():
    open("pfa-specification.tex", "w").write(pfaSpecification)
