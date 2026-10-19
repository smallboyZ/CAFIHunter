package dataflow;

import soot.SootMethod;
import soot.Unit;
import soot.ValueBox;


public interface RuleChecker {
    boolean isSink(Unit checkedUnit, ValueBox taintValueBox);

    boolean isDependConditionSink(SootMethod method,SootMethod caller);
}
