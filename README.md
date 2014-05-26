## Portable Format for Analytics (PFA)

Statistical model training and machine learning generally produce procedures as output, known as scoring engines.  These scoring engines are executable--- usually they are simple but highly parameterized algorithms, such as decision trees.  Often, the scoring engine must run in a tightly constrained production environment.  Concerns about the mathematical correctness of the scoring engine's algorithm (the model) should be separated from concerns about the stability and security of the production environment.  Hand-written code, written in a general purpose programming language, potentially mixes the math with the machinery.

PFA is a way of separating those concerns.  PFA is a mini-language whose only capability is to compute mathematical functions suitable for statistical analyses.  Since it is incapable of accessing or injuring its environment, PFA code reviews can focus on the analytic itself.  Also unlike traditional languages, PFA is intended to be generated programmatically, by the machine learning algorithm rather than by hand.  As such, it is enitely contained _within_ JSON, and can be manipulated by standard JSON tools.  It is the object language of statistical metaprogramming.

**See [scoringengine.org](http://scoringengine.org) for more details and interactive tutorials.**

This repository contains two implementations of PFA hosts (compilers and runtime environments for PFA that connect to an external data pipeline) and the PFA specification.  The current status of each is:
  * [PFA specification](https://github.com/scoringengine/pfa/blob/master/doc/spec/PFA.pdf?raw=true): first draft complete (106 pages; half detailed explanations, half of which is function reference).
  * [PFA-JVM (Scala)](https://github.com/scoringengine/pfa/tree/master/src/main/scala/org/scoringengine/pfa): static code analysis and on-the-fly bytecode compiler are complete.  This version has been [embedded in Google App Engine](https://github.com/scoringengine/pfa-gae), but it should also be embedded in large-scale data pipelines (Hadoop, Spark, Storm, etc.).
  * [PFA-py (Python)](https://github.com/scoringengine/pfa/tree/master/src/main/python): static code analysis and on-the-fly interpreter are complete.  This version produces PFA from PMML, but it should also produce PFA from other common analysis tools ([SciKit Learn](https://github.com/scoringengine/pfa-sklearn), etc.).

Also, the library needs to be filled up with more statistical models and techniques.
