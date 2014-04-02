#!/usr/bin/env python

import subprocess
from distutils.core import setup

setup(name="pfa",
      version="0.0.1",
      author="Jim Pivarski",
      author_email="jpivarski@gmail.com",
      packages=["pfa", "pfa.lib1", "pfa.lib1.stat", "pfa.lib1.model", "pfa.pmml"],
      license="Apache 2.0",
      description="Portable Format for Analytics (PFA), Python version",
      )
