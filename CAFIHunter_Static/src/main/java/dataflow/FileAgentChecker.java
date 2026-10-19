package dataflow;
import cg.CallGraphUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import java.util.*;

public class FileAgentChecker implements RuleChecker {

    private Logger logger= LoggerFactory.getLogger(SensitiveActionChecker.class);

    private HashSet<String> sinks = new HashSet<>();

    private HashSet<SootMethod> methodsCanReachSink=new HashSet<>();

    private HashSet<SootMethod> controlFlowMethods=new HashSet<>();

    private JimpleBasedInterproceduralCFG icfg ;

    private HashSet<String> sinkMethodTrue = new HashSet<>();

    private HashSet<SootMethod> sinkMethods=new HashSet<>();

    public HashSet<String> getSinkMethodTrue() {
        return this.sinkMethodTrue;
    }

    public void clearSinkMethodTrue(){
        this.sinkMethodTrue.clear();
    }

    public HashSet<SootMethod> getSinkMethods(){
        return this.sinkMethods;
    }

    public void clearSinkMethods(){this.sinkMethodTrue.clear();}

    public FileAgentChecker(HashSet<String> sinks, JimpleBasedInterproceduralCFG icfg){
        logger.info("Init Sensitive Checker");
        this.icfg=icfg;
        this.sinks=sinks;
        initReachableMethod();
    }

    private void initReachableMethod(){
        for(String signature:this.sinks){
            try{
                SootMethod method = Scene.v().getMethod(signature);
                controlFlowMethods.add(method);
            }catch (Exception e){
            }
        }

        if(sinks.isEmpty())
            return;
        methodsCanReachSink=CallGraphUtils.getAllMethodsCanReachTargetMethods(controlFlowMethods);
    }



    @Override
    public boolean isSink(Unit checkedUnit, ValueBox taintValueBox) {

        InvokeExpr invokeExpr = getInvokeExpr(checkedUnit);

        if(invokeExpr==null)
            return false;
        if (sinks.contains(invokeExpr.getMethod().getSignature()) && invokeExpr.getArgs().contains(taintValueBox.getValue())) {
            logger.info("Detect sensitive data flow method {} is trigger!",invokeExpr.getMethod().getSignature());
            String info = getFormatInfo(invokeExpr.getMethod(), 0,null,icfg.getMethodOf(checkedUnit));
            sinkMethodTrue.add(info);
            sinkMethods.add(icfg.getMethodOf(checkedUnit));

        }
        return false;
    }

    @Override
    public boolean isDependConditionSink(SootMethod method,SootMethod caller) {
        if(methodsCanReachSink.contains(method)){
            logger.info("Detect sensitive control flow method {} is trigger!",method.getSignature());
            String info = getFormatInfo(method, 1,caller,null);
            if(info==null)
                return false;
            sinkMethodTrue.add(info);
        }
        return false;
    }



    private InvokeExpr getInvokeExpr(Unit u) {
        if (u instanceof AssignStmt) {
            AssignStmt assignStmt = (AssignStmt) u;
            if (assignStmt.containsInvokeExpr())
                return assignStmt.getInvokeExpr();
        }
        if (u instanceof InvokeStmt) {
            InvokeStmt invokeStmt = (InvokeStmt) u;
            return invokeStmt.getInvokeExpr();
        }
        return null;
    }

    private String getFormatInfo(SootMethod method,int mode,SootMethod caller,SootMethod methodOf){
        String msg="";
        if(mode==0){
            msg+="SINK METHOD: "+method.getSignature()+"\n";
            msg+="LOCATION: "+methodOf.getSignature()+"\n";

        }else {
            List<String> res=new ArrayList<>();
            CallGraphUtils.getReachableMethodInGivenSet(method,controlFlowMethods,0,res,new HashSet<>());
            if(res.isEmpty())
                return null;
            msg+="SINK TYPE: CONTROL_FLOW_SINK\n";
            msg+="DEPEND METHOD: "+method.getSignature()+'\n';
            msg+="DEPEMD METHOD CALLER: "+caller.getSignature()+"\n";
            int counter=0;
            for(String sinkMethod:res){
                msg+="SINK METHOD "+"["+counter+"]: "+sinkMethod+'\n';
                counter++;
            }
        }
        return msg;

    }
}
