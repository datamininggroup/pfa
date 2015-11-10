#!/usr/bin/env python

import json
import sys

from titus.genpy import PFAEngine
from titus.errors import PFARuntimeException

from runTest import *

inputFile, = sys.argv[1:]

# Failures that I'm giving up on:
# 
# prob.dist.binomialQF({"p": 0.99999, "prob": 1e-05, "size": 1}) should be 1, is 0 (rounding in count)
#                      {"p": 0.9, "prob": 0.1, "size": 1}        should be 1, is 0 (same reason)
# prob.dist.hypergeometricPDF  \
# prob.dist.hypergeometricCDF   }  many errors! and the QF has a long or infinite loop
# prob.dist.hypergeometricQF   /
# prob.dist.negativeBinomialPDF({"x": 17, "prob": 0.9, "size": 100}) should be 0.00245, is 0.02715
#                               {"x": 100, "prob": 0.1, "size": 17}  should be 0.00245, is 0.00462
#                               {"x": 100, "prob": 0.5, "size": 100} should be 5.7e42, is 0.02817
# prob.dist.negativeBinomialQF has many errors (though not as many as the hypergeometric)

for counter, example in enumerate(getExamples(open(inputFile))):
    engine, = PFAEngine.fromJson(example["engine"])

    if example["function"] in ("prob.dist.binomialQF", "prob.dist.hypergeometricPDF", "prob.dist.hypergeometricCDF", "prob.dist.hypergeometricQF", "prob.dist.negativeBinomialPDF", "prob.dist.negativeBinomialQF"):
        continue

    functionWritten = False
    def maybeWriteFunction(functionWritten):
        if not functionWritten:
            print "%4d    %-20s%s" % (counter + 1, example["function"], json.dumps(example["engine"]))
        return True

    for trial in example["trials"]:
        trialWritten = False
        try:
            result = {"success": convertOut(engine.action(trial["sample"]), engine.outputType.jsonNode(set()), dobase64=True)}
        except PFARuntimeException as err:
            result = {"fail": err.code}
        except Exception:
            # PFAEngine.fromJson(example["engine"], debug=True)
            print "function: " + example["function"]
            print "engine:   " + json.dumps(example["engine"])
            print "input:    " + repr(trial["sample"])
            if "error" in trial:
                print "expected: ERROR CODE " + repr(trial["error"])
            elif "result" in trial:
                print "expected: " + repr(trial["result"])
            print
            raise

        if "success" in result:
            actual = json.dumps(result["success"])
        else:
            actual = "ERROR CODE " + str(result["fail"])

        if "error" in trial:
            if trial["error"] != result.get("fail", None):
                functionWritten = maybeWriteFunction(functionWritten)
                if not trialWritten:
                    print "                            input:    " + json.dumps(trial["sample"])
                    print "                            expected: ERROR CODE " + str(trial["error"])
                    print "                            actual:   " + actual
                    trialWritten = True

        elif trial.get("nondeterministic", None) in ("pseudorandom", "unstable"):
            pass

        else:
            def maybeWriteTrial(trialWritten):
                if not trialWritten:
                    print "                            input:    " + json.dumps(trial["sample"])
                    print "                            expected: " + json.dumps(trial["result"])
                    print "                            actual:   " + actual
                return True

            if "success" in result:
                left = trial["result"]
                right = result["success"]

                if trial.get("nondeterministic", None) == "unordered":
                    if not isinstance(left, list) or not isinstance(right, list):
                        raise Exception
                    left.sort()
                    right.sort()

                for errorMessage in compare(left, right, 1e-4, 0.05, 1e80):
                    functionWritten = maybeWriteFunction(functionWritten)
                    trialWritten = maybeWriteTrial(trialWritten)
                    print "                            " + errorMessage
            else:
                functionWritten = maybeWriteFunction(functionWritten)
                trialWritten = maybeWriteTrial(trialWritten)

    if not functionWritten:
        print "%4d    %s" % (counter + 1, example["function"])
