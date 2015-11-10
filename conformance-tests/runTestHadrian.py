#!/usr/bin/env python

import json
import signal
import sys
import re

from runTest import *

import java.lang.Exception

from com.opendatagroup.hadrian.errors import PFARuntimeException
from com.opendatagroup.antinous.pfainterface import PFAEngineFactory

if __name__ == "__main__":
    pef = PFAEngineFactory()
    pef.setDebug(False)

    if len(sys.argv[1:]) == 1:
        inputFile, = sys.argv[1:]
        outputFile = None
    else:
        inputFile, outputFile = sys.argv[1:]

    if outputFile is not None:
        template = dict(enumerate(open(inputFile).readlines()))
        lookup = {}
        numFunctions = 0
        for lineNumber, lineContent in template.items():
            m = re.search('"(UNKNOWN_[0-9]+)"', lineContent)
            if m is not None:
                lookup[m.group(1)] = lineNumber
            if lineContent.startswith('     {"function":'):
                numFunctions += 1
    else:
        template = None
        lookup = None
        numFunctions = None

    for counter, example in enumerate(getExamples(open(inputFile))):
        engine = pef.engineFromJson(json.dumps(example["engine"]))

        if numFunctions is not None:
            print "%4d/%4d   %-20s" % (counter + 1, numFunctions, example["function"])  # %s -> %s    , json.dumps(example["engine"]["input"]), json.dumps(example["engine"]["output"])

        functionWritten = False
        def maybeWriteFunction(functionWritten):
            if not functionWritten:
                print "%4d    %-20s%s" % (counter + 1, example["function"], json.dumps(example["engine"]))
            return True

        for trial in example["trials"]:
            trialWritten = False
            try:
                result = {"success": convertOut(pef.action(engine, trial["sample"]), json.loads(engine.outputType().toString()), dobase64=False)}
            except PFARuntimeException as err:
                result = {"fail": err.code()}

            if "success" in result:
                actual = json.dumps(result["success"])
            else:
                actual = "ERROR CODE " + str(result["fail"])

            def maybeWriteTrial(trialWritten):
                if not trialWritten:
                    print "                            input:    " + json.dumps(trial["sample"])
                    print "                            expected: " + json.dumps(trial["result"])
                    print "                            actual:   " + actual
                return True

            if "error" in trial:
                if trial["error"] != result.get("fail", None):
                    functionWritten = maybeWriteFunction(functionWritten)
                    if not trialWritten:
                        print "                            input:    " + json.dumps(trial["sample"])
                        print "                            expected: ERROR CODE " + str(trial["error"])
                        print "                            actual:   " + actual
                        trialWritten = True

            elif trial.get("nondeterministic", None) is not None:
                if outputFile is not None and trial["result"].startswith("UNKNOWN_"):
                    lineNumber = lookup[trial["result"]]
                    if trial["nondeterministic"] == "pseudorandom":
                        template[lineNumber] = template[lineNumber].replace(', "result": "' + trial["result"] + '"', "")
                    elif "success" in result:
                        template[lineNumber] = template[lineNumber].replace('"result": "' + trial["result"] + '"', '"result": ' + json.dumps(result["success"]))
                    else:
                        template[lineNumber] = template[lineNumber].replace('"result": "' + trial["result"] + '"', '"error": ' + json.dumps(result["fail"]))
                else:
                    if trial["nondeterministic"] == "unordered":
                        if "success" in result:
                            for errorMessage in compare(sorted(trial["result"]), sorted(result["success"]), 1e-8, 0.01, 1e80):
                                functionWritten = maybeWriteFunction(functionWritten)
                                trialWritten = maybeWriteTrial(trialWritten)
                                print "                                " + errorMessage
                        else:
                            functionWritten = maybeWriteFunction(functionWritten)
                            trialWritten = maybeWriteTrial(trialWritten)
                            print "                                " + errorMessage

            else:
                if outputFile is not None and trial["result"].startswith("UNKNOWN_"):
                    lineNumber = lookup[trial["result"]]
                    if "success" in result:
                        template[lineNumber] = template[lineNumber].replace('"result": "' + trial["result"] + '"', '"result": ' + json.dumps(result["success"]))
                    else:
                        template[lineNumber] = template[lineNumber].replace('"result": "' + trial["result"] + '"', '"error": ' + json.dumps(result["fail"]))
                else:
                    if "success" in result:
                        for errorMessage in compare(trial["result"], result["success"], 1e-8, 0.01, 1e80):
                            functionWritten = maybeWriteFunction(functionWritten)
                            trialWritten = maybeWriteTrial(trialWritten)
                            print "                                " + errorMessage
                    else:
                        functionWritten = maybeWriteFunction(functionWritten)
                        trialWritten = maybeWriteTrial(trialWritten)
                        print "                                " + errorMessage

        if outputFile is None and not functionWritten:
            print "%4d    %s" % (counter + 1, example["function"])

    if outputFile is not None:
        out = open(outputFile, "w")
        for lineNumber in xrange(len(template)):
            out.write(template[lineNumber])
        out.close()
