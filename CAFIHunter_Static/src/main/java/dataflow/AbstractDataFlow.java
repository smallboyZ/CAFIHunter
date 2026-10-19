package dataflow;

import cg.CallGraphUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import java.util.*;


public abstract class AbstractDataFlow implements Analyze {

    public static final Logger logger = LoggerFactory.getLogger(AbstractDataFlow.class);

    protected int MAX_DEPTH = 15;

    public void setMAX_DEPTH(int depth){
        this.MAX_DEPTH=depth;
    }

    public static boolean isValueDefinedInUnit(Unit unit, Value value) {
        List<String> definedValue = new ArrayList<>();
        for (ValueBox defBox : unit.getDefBoxes()) {
            definedValue.add(defBox.getValue().toString());
        }
        return definedValue.contains(value.toString());
    }

    public static boolean isSystemClass(SootClass sootClass) {
        String name = sootClass.getName();
        if (name.startsWith("java") || name.startsWith("javax")||name.startsWith("android.")||name.startsWith("androidx.")||name.startsWith("com.android")||name.startsWith("sun.")) {
            return true;
        }
        return false;

    }


    public static boolean isMethodCalled(List<CallSite> callStack, SootMethod method) {
        for (CallSite callSite : callStack) {
            if (callSite.caller.getSignature().equals(method.getSignature()))
                return true;
        }
        return false;
    }

    public static InvokeExpr getInvokeExpr(Unit u){

        if(u instanceof InvokeStmt){
            return ((InvokeStmt)u).getInvokeExpr();
        }

        if(u instanceof AssignStmt){
            AssignStmt assignStmt = (AssignStmt) u;
            if(assignStmt.containsInvokeExpr())
                return assignStmt.getInvokeExpr();
        }
        return null;
    }

    public static HashSet<SootMethod> getMethodFromCG(Unit u) {
        return CallGraphUtils.getMethod(u);
    }

}
