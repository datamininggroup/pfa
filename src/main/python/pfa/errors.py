#!/usr/bin/env python

class SchemaParseException(RuntimeError): pass

class PFAException(RuntimeError): pass

class PFASyntaxException(PFAException):
    def __init__(self, message, at):
        if at is None or at == "":
            super(PFASyntaxException, self).__init__(message)
        else:
            super(PFASyntaxException, self).__init__(message + " at " + at)

class PFASemanticException(PFAException):
    def __init__(self, message, pos):
        super(PFASemanticException, self).__init__(message + " at " + pos)

class PFARuntimeException(PFAException):
    def __init__(self, message):
        super(PFARuntimeException, self).__init__(message)
