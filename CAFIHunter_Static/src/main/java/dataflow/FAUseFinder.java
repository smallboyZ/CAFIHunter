package dataflow;

import constant.FileAgentMethods;
import soot.*;
import soot.jimple.Constant;
import soot.jimple.InvokeExpr;

import java.util.ArrayList;
import java.util.List;

public class FAUseFinder extends AbstractDataFlow{

    enum OpType {
        VALIDATION_API, URI_HANDLE_API, CONTENT_QUERY_API, CONTENT_OPEN_API, GET_KEYVALUE_API, FILE_API, NULL
    }

    private List<String> fileAPIs=new ArrayList<>();

    private List<String> uriHandlerAPIs=new ArrayList<>();

    private  List<String> getColumnValue= new ArrayList<>();

    private  List<String> getExtras= new ArrayList<>();

    private List<String> checkValue=new ArrayList<>();

    public void clearApiRecords(){
        fileAPIs.clear();
        uriHandlerAPIs.clear();
        getColumnValue.clear();
        getExtras.clear();
        checkValue.clear();
    }
    public String getApiRecords(){
        String res="";
        res+="getColumnValue#"+getColumnValue+"\n";
        res+="getExtras#"+getExtras+"\n";
        res+="checkValue#"+checkValue+"\n";
        res+="fileHandler#"+fileAPIs+"\n";
        res+="uriHandler#"+uriHandlerAPIs+"\n";
        return res;
    }

    public boolean checkAnalyze(Unit unit, SootMethod method,List<CallSite>callStack) {

        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if (invokeExpr == null)
            return false;
        SootMethod m = invokeExpr.getMethod();
        switch (getType(m)){
            case VALIDATION_API:
                validationHandler(unit,method,callStack);
                break;
            case URI_HANDLE_API:
                uriHandler(unit,method);
                break;
            case CONTENT_QUERY_API:
                contentQueryHandler(unit,method,callStack);
                break;
            case CONTENT_OPEN_API:
                contentOpenHandler(unit,method);
                break;
            case GET_KEYVALUE_API:
                getKeyValueHandler(unit,method,callStack);
                break;
            case FILE_API:
                fileHandler(unit,method);
                break;
            default:
                break;
        }

        return false;
    }

    private String getValueOfObject(Value value, Unit u, SootMethod method, List<CallSite> callChain) {
        if(value instanceof Constant)
            return value.toString();
        return "";
    }

    public void validationHandler(Unit unit,SootMethod method,List<CallSite> callStack){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        Value arg = invokeExpr.getArg(0);
        String value = getValueOfObject(arg,unit,method, callStack);
        if(value.isEmpty())
            return;
        logger.info("Call#validationHandler: {} in {}",signature,method.getSignature());
        logger.info("Check#{}: {}",invokeExpr.getMethod().getName(),value);

        String msg = String.format("Check#%s: %s", invokeExpr.getMethod().getName(), value);
        if(!checkValue.contains(msg))
            checkValue.add(msg);
    }

    public void getKeyValueHandler(Unit unit,SootMethod method,List<CallSite> callStack){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        Value arg = invokeExpr.getArg(0);
        String value = getValueOfObject(arg,unit,method, callStack);
        if(value.isEmpty())
            return;
        logger.info("Call#getKeyValueHandler: {} in {}",signature,method.getSignature());
        logger.info("Get#{}: {}",invokeExpr.getMethod().getName(),value);
        if(signature.contains("getColumnIndex")){
            if(!getColumnValue.contains(value)){
                getColumnValue.add(value);
            }
        }else{
            if(!getExtras.contains(value)){
                getExtras.add(value);
            }
        }

    }

    public void contentQueryHandler(Unit unit,SootMethod method,List<CallSite> callStack){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        logger.info("Call#contentQueryHandler: {} @ {}",signature,method);
    }

    public void contentOpenHandler(Unit unit,SootMethod method){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        logger.info("Call#contentOpenHandler: {} @ {}",signature,method);
    }

    public void fileHandler(Unit unit,SootMethod method){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        if(fileAPIs.contains(signature))
            return;
        fileAPIs.add(signature);

    }

    public void uriHandler(Unit unit,SootMethod method){
        InvokeExpr invokeExpr = getInvokeExpr(unit);
        if(invokeExpr==null)
            return;
        String signature = invokeExpr.getMethod().getSignature();
        if(uriHandlerAPIs.contains(signature))
            return;
        uriHandlerAPIs.add(signature);
    }
    
    public static FAUseFinder.OpType getType(SootMethod method) {

        if (FileAgentMethods.getValidationAPIList().contains(method.getSignature()))
            return OpType.VALIDATION_API;
        if(FileAgentMethods.getUriHandleAPIList().contains(method.getSignature()))
            return OpType.URI_HANDLE_API;
        if (FileAgentMethods.getContentQueryAPIList().contains(method.getSignature()))
            return OpType.CONTENT_QUERY_API;
        if (FileAgentMethods.getContentOpenAPIList().contains(method.getSignature()))
            return OpType.CONTENT_OPEN_API;
        if(FileAgentMethods.getKeyValueAPIList().contains(method.getSignature()))
            return OpType.GET_KEYVALUE_API;
        if (FileAgentMethods.getFileAPIList().contains(method.getSignature()))
            return OpType.FILE_API;

        return FAUseFinder.OpType.NULL;
    }

    public void inter_forward(SootMethod method, int depth, List<CallSite> callStack) {
        if (depth > MAX_DEPTH)
            return;
        if (isSystemClass(method.getDeclaringClass()))
            return;
        if (isMethodCalled(callStack, method))
            return;
        if (!method.isConcrete())
            return;
        for (Unit u : method.retrieveActiveBody().getUnits()) {
            InvokeExpr invokeExpr = getInvokeExpr(u);
            if (invokeExpr != null) {
                checkAnalyze(u, method, callStack);
                for (SootMethod m : getMethodFromCG(u)) {
                    List<CallSite> temp_call_stack = new ArrayList<>(callStack);
                    temp_call_stack.add(new CallSite(method, u, -1));
                    inter_forward(m, depth + 1, temp_call_stack);
                }
            }
        }
    }


}
