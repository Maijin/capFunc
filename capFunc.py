#!/usr/bin/env python
# -*- coding: utf-8 -*-
# capFunc.py - Capstone Function Disassembler IDA Python Script
__author__ = "Tyler Halfpop"
__version__ = "0.1"
__license__ = "BSD 3-Clause license"

#-----------------------------------------------------------------------
import idc
import idaapi
from capstone import *

#-----------------------------------------------------------------------
def usage():
  print "CapFunc v{} \nUse F3 to disassemble with Capstone whatever function the cursor is in".format(__version__)

def make_hotkey():
  idaapi.CompileLine('static key_F3() { RunPythonStatement("main(idc.ScreenEA())"); }')
  AddHotkey("F3", 'key_F3')
  print "F3 Hotkey Added"

#-----------------------------------------------------------------------
def main(ea):
  # Get Function Bytes
  start = idc.GetFunctionAttr(ea, FUNCATTR_START)
  end = idc.GetFunctionAttr(ea, FUNCATTR_END)
  length = end - start
  code = ""
  for byte in idc.GetManyBytes(start, length):
  	 code += byte

  # Determine Architecture
  info = idaapi.get_inf_structure()
  proc = info.procName

  if info.is_64bit():
    if proc == "metapc":
      md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif proc == "ARM":
      md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
  elif info.is_32bit():
    if proc == "metapc":
      md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif proc == "ARM":
      md = Cs(CS_ARCH_ARM, CS_MODE_ARM) # If need change: CS_MODE_THUMB

  # Disassemble with Capstone and print
  for i in md.disasm(code, start):
    try:
      db = ""
      for ba in i.bytes:
        db += str("%X " %(ba)).rjust(3, "0")
      print("%x:\t%s\t%s\t%s" %(i.address, str(db).ljust(24, " "), i.mnemonic, i.op_str))
    except Exception as e:
      print "Exception: {}".format(e)

if __name__ == "__main__":
  if len(sys.argv) < 2:
    usage()
    make_hotkey()
  else:
    main(sys.argv[1])
