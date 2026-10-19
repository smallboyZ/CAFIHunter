package dataflow;


import soot.SootMethod;
import soot.Unit;
import java.util.List;


public interface Analyze {
    boolean checkAnalyze(Unit unit, SootMethod method, List<CallSite> callStack);
}
