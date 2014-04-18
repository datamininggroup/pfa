## Portable Format for Analytics (PFA)

Statistical model training and machine learning generally produce procedures as output, known as scoring engines.  These scoring engines are executable, usually simple algorithms that are highly parameterized, such as a decision tree.  Often, the scoring engine must run in a tightly constrained production environment.  Concerns about the mathematical correctness of the scoring engine's algorithm (the model) should be separated from concerns about the stability and security of the production environment.  If scoring engines are deployed as hand-written code written in a general programming language, they're not.

PFA is a way of separating those concerns.  PFA is a mini-language whose only capability is to compute mathematical functions suitable for statistical analyses.  Since it is incapable of accessing or injuring its environment, PFA code reviews can focus on the analytic itself.  Also unlike traditional languages, PFA is intended to be generated programmatically, by the machine learning algorithm rather than by hand.  As such, it is enitely contained _within_ JSON, and can be manipulated by standard JSON tools.  It is the object language of statistical metaprogramming.

This repository contains two implementations of PFA hosts (compilers and interpreters of PFA that also manage the data pipeline) and the PFA specification.  The current status of each is:
  * [PFA specification](https://github.com/scoringengine/pfa/blob/master/doc/spec/PFA.pdf?raw=true): first draft complete (106 pages, mostly descriptions of standardized functions).
  * [PFA-JVM (Scala)](https://github.com/scoringengine/pfa/tree/master/src/main/scala/org/scoringengine/pfa): static analysis and dynamic compiler are complete.  Needs more data pipeline.
  * [PFA-py (Python)](https://github.com/scoringengine/pfa/tree/master/src/main/python): static analysis is complete; interpreter not yet started.  Also needs more &forall;x x &rarr; PFA translators.

Also, the library needs to be filled up with common statistical models and techniques.

See the specification for a verbose introduction.  The [testing code](https://github.com/scoringengine/pfa/tree/master/src/test/scala) includes many working examples.  Gentle-introduction tutorials and online demos are coming soon.
