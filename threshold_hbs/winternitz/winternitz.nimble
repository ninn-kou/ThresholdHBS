# Package

version       = "0.1.0"
author        = "Will Kennedy"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
bin           = @["winternitz"]
backend       = "c"

# Dependencies

requires "nim >= 2.0.8"

requires "nimcrypto >= 0.7.3"

# Build steps

import os, strutils

# Hook to build the shared library before the main binary
before build:
  let libName = "winternitz"
  # Platform‑specific output extension
  let outputExt = when defined(windows): "dll"
                 elif defined(macosx): "dylib"
                 else: "so"
  let outFile = libName & "." & outputExt

  # Build the library with --app:lib
  let cmd = "nim " & backend & " --app:lib --noMain -o:" & outFile & " src/winternitz.nim"
  echo "Building library: ", cmd
  exec(cmd)