#!/usr/bin/env python

class Fcn(object):
    pass

class LibFcn(Fcn):
    name = None
    def genpy(self, paramTypes, args):
        return "self.functionTable.functions[{}]({})".format(repr(self.name), ", ".join([repr(paramTypes)] + args))
    def __call__(self):
        raise NotImplementedError
