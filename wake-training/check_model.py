#!/usr/bin/env python3
"""Verify a trained wake-word .onnx is Android/ONNX-Runtime compatible.

Usage:
    python3 check_model.py hey_muse.onnx        # needs: pip install onnx

Checks:
- IR version <= 7
- opset(s) <= 11
- no Reshape with allowzero=1 (breaks old ORT)
- classifier input [1,16,96], output [1,1]
"""
import sys

import onnx


def main():
    model = onnx.load(sys.argv[1])
    ok = True

    def check(cond, msg):
        global ok
        print(("PASS " if cond else "FAIL ") + msg)
        ok = ok and cond

    check(model.ir_version <= 7, f"ir_version={model.ir_version} (need <= 7)")
    for imp in model.opset_import:
        check(imp.version <= 11, f"opset {imp.domain or 'ai.onnx'}={imp.version} (need <= 11)")
    bad = [n.name for n in model.graph.node
           if n.op_type == "Reshape" and any(a.name == "allowzero" and a.i == 1 for a in n.attribute)]
    check(not bad, f"no allowzero Reshape (bad nodes: {bad or 'none'})")

    def shape(v):
        return [d.dim_value for d in v.type.tensor_type.shape.dim]

    ins = [shape(i) for i in model.graph.input]
    outs = [shape(o) for o in model.graph.output]
    check([1, 16, 96] in ins, f"classifier input [1,16,96] in {ins}")
    check([1, 1] in outs, f"classifier output [1,1] in {outs}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
