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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;


public class SensitiveActionChecker implements RuleChecker {

    private Logger logger= LoggerFactory.getLogger(SensitiveActionChecker.class);

    private HashMap<String,String> sinks=new HashMap<>();

    private HashSet<SootMethod> methodsCanReachSink=new HashSet<>();

    private HashSet<SootMethod> controlFlowMethods=new HashSet<>();




    private HashSet<String> sinkMethodTrue = new HashSet<>();

    public HashSet<String> getSinkMethodTrue() {
        return this.sinkMethodTrue;
    }

    public void clearSinkMethodTrue(){
        this.sinkMethodTrue.clear();
    }

    public SensitiveActionChecker(HashMap<String,String> sinks){
        logger.info("Init Sensitive Checker");
        this.sinks=sinks;
        initReachableMethod();
    }

    private void initReachableMethod(){
        for(String signature:this.sinks.keySet()){
            try{
                String type = this.sinks.get(signature).trim();
                if(type.equals("C5")||type.equals("C4-AD")) {
                    SootMethod method = Scene.v().getMethod(signature);
                    controlFlowMethods.add(method);
                }
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
        if (sinks.keySet().contains(invokeExpr.getMethod().getSignature()) && invokeExpr.getArgs().contains(taintValueBox.getValue())) {
            logger.info("Detect sensitive data flow method {} is trigger!",invokeExpr.getMethod().getSignature());
            String info = getFormatInfo(invokeExpr.getMethod(), 0,null);
            sinkMethodTrue.add(info);
        }
        return false;
    }

    @Override
    public boolean isDependConditionSink(SootMethod method,SootMethod caller) {
        if(methodsCanReachSink.contains(method)){
            logger.info("Detect sensitive control flow method {} is trigger!",method.getSignature());
            String info = getFormatInfo(method, 1,caller);
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

    private String getFormatInfo(SootMethod method,int mode,SootMethod caller){
        String msg="";
        if(mode==0){
            msg+="SINK TYPE: DATA_FLOW_SINK\n";
            msg+="METHOD: "+method.getSignature()+"\n";
            msg+="TYPE: "+sinks.get(method.getSignature());
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
                if(counter<res.size()-1){
                    msg += "TYPE: " + sinks.get(sinkMethod) + '\n';
                }else {
                    msg += "TYPE: " + sinks.get(sinkMethod);
                }
                counter++;
            }
        }
        return msg;

    }


}
