package component;

import constant.EntryPointsDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent;
import soot.toolkits.graph.BriefUnitGraph;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;


public class EntryPointAnalyze {

    private static final Logger logger = LoggerFactory.getLogger(EntryPointAnalyze.class);

    public static HashMap<String, HashSet<SootMethod>> getComponent2MapEntryPoint(HashSet<AbstractBinaryAndroidComponent> components) {
        HashMap<String, HashSet<SootMethod>> res = new HashMap<>();
        for (AbstractBinaryAndroidComponent component : components) {
            HashSet<SootMethod> entryPoints = new HashSet<>();
            String componentType = component.getAXmlNode().getTag();
            String componentName = component.getNameString();
            if (componentName == null)
                componentName = "null_component";
            if (componentName.startsWith(".")) {
                logger.warn("TODO: handle component name concat:" + componentName);
            } else {
                switch (componentType) {
                    case "activity":
                        entryPoints.addAll(getLifeCycleMethodByComponent(componentName, EntryPointsDefinition.getActivityLifecycleMethods()));
                        break;
                    case "service":
                        entryPoints.addAll(getLifeCycleMethodByComponent(componentName, EntryPointsDefinition.getServiceLifecycleMethods()));
                        entryPoints.addAll(getEntryPointByOnBindForService(componentName));
                        break;
                    case "receiver":
                        entryPoints.addAll(getLifeCycleMethodByComponent(componentName, EntryPointsDefinition.getBroadcastLifecycleMethods()));
                        break;
                    case "provider":
                        entryPoints.addAll(getLifeCycleMethodByComponent(componentName, EntryPointsDefinition.getContentproviderLifecycleMethods()));
                        break;
                    default:
                        logger.warn("{} is an unsupport component type", componentType);
                }
            }
            res.put(componentName, entryPoints);
        }
        return res;
    }

    private static SootMethod findMethodBySubSignature(SootClass currentClass, String subsignature) {
        if (currentClass.getName().startsWith("android.") || currentClass.getName().startsWith("androidx"))
            return null;

        SootMethod m = currentClass.getMethodUnsafe(subsignature);

        if (m != null) {
            return m;
        }
        if (currentClass.hasSuperclass()) {
            return findMethodBySubSignature(currentClass.getSuperclass(), subsignature);
        }
        return null;
    }

    private static SootMethod findMethodByName(SootClass currentClass, String methodName) {
        if (currentClass.getName().startsWith("android.") || currentClass.getName().startsWith("androidx"))
            return null;

        SootMethod m = currentClass.getMethodByNameUnsafe(methodName);
        if (m != null) {
            return m;
        }
        if (currentClass.hasSuperclass()) {
            return findMethodByName(currentClass.getSuperclass(), methodName);
        }
        return null;
    }


    public static HashSet<SootMethod> getLifeCycleMethodByComponent(String componentName, List<String> lifeCycleMethods) {
        HashSet<SootMethod> res = new HashSet<>();
        SootClass currentClass = Scene.v().getSootClassUnsafe(componentName);
        if (currentClass == null) {
            logger.warn("Can't find the {} class", componentName);
        } else {
            for (String method : lifeCycleMethods) {
                SootMethod lifeCycleMenthod = findMethodBySubSignature(currentClass, method);
                if (lifeCycleMenthod != null)
                    res.add(lifeCycleMenthod);
            }
        }
        return res;
    }

    public static HashSet<SootMethod> getEntryPointByOnBindForService(String componentName) {
        HashSet<SootMethod> res = new HashSet<>();
        SootClass currentClass = Scene.v().getSootClass(componentName);
        if (currentClass == null) {
            logger.warn("Can't find the {} class", componentName);
        } else {
            SootMethod method = findMethodBySubSignature(currentClass, EntryPointsDefinition.SERVICE_ONBIND);
            if (method == null) {
                logger.info("onBind is not override by app developer");
            } else {

                HashSet<String> returnValueType = getReturnValueType(method);
                if (returnValueType.size() == 0) {
                    logger.info("onBind return null");
                } else {
                    for (String type : returnValueType) {
                        if (type.startsWith("STUB_")) {
                            String stubClassName = type.substring(5);
                            res.addAll(getStubPublicMethod(stubClassName));
                        } else {
                            String handlerClassName = type.substring(8);
                            res.addAll(getHandlerPublicMethod(handlerClassName));
                        }
                    }
                }

            }

        }
        return res;
    }

    private static HashSet<SootMethod> getHandlerPublicMethod(String className) {
        HashSet<SootMethod> res = new HashSet<>();
        SootClass handlerClass = Scene.v().getSootClass(className);
        SootMethod onHandleMessage = handlerClass.getMethodByNameUnsafe("handleMessage");
        res.add(onHandleMessage);
        return res;
    }

    private static HashSet<SootMethod> getStubPublicMethod(String className) {
        HashSet<SootMethod> res = new HashSet<>();
        SootClass currentClass = Scene.v().getSootClass(className);
        while (currentClass.hasSuperclass() && !currentClass.getSuperclass().getName().equals("android.os.Binder")) {
            currentClass = currentClass.getSuperclass();
        }

        if (currentClass.getInterfaceCount() != 1)
            return res;
        if (!currentClass.getInterfaces().getFirst().implementsInterface("android.os.IInterface"))
            return res;

        HashSet<String> publicMethodName = new HashSet<>();
        for (SootField sootField : currentClass.getFields()) {
            if (sootField.getName().startsWith("TRANSACTION")) {
                publicMethodName.add(sootField.getName().substring(12));
            }
        }

        currentClass = Scene.v().getSootClass(className);
        for (String methodName : publicMethodName) {
            SootMethod method = findMethodByName(currentClass, methodName);
            if (method != null && method.isPublic())
                res.add(method);
        }
        return res;
    }


    private static HashSet<String> getReturnValueType(SootMethod sootMethod) {
        HashSet<String> res = new HashSet<>();
        Body body;
        try {
            body = sootMethod.retrieveActiveBody();
        }catch (Exception e){
            return res;
        }
        if (body == null)
            return res;
        BriefUnitGraph graph = new BriefUnitGraph(body);
        for (Unit unit : graph.getTails()) {
            if (unit instanceof ReturnStmt) {
                Value retValue = ((ReturnStmt) unit).getOp();
                if (!retValue.toString().equals("null")) {
                    HashSet<Unit> defUnit = findLastDefUnit(graph, unit, retValue);
                    deterBinderType(defUnit, res);
                }
            }
        }
        return res;
    }

    private static void deterBinderType(HashSet<Unit> unitSet, HashSet<String> res) {
        for (Unit unit : unitSet) {
            String type = null;
            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                if (assignStmt.containsFieldRef()) {
                    type = assignStmt.getFieldRef().getField().getType().toString();
                    if (type.equals("android.os.Messenger")) {
                        SootClass declaringClass = assignStmt.getFieldRef().getFieldRef().declaringClass();
                        boolean flag = false;
                        for (SootMethod method : declaringClass.getMethods()) {
                            if (method.getName().equals("<init>") && !flag) {
                                for (Unit u : method.retrieveActiveBody().getUnits()) {
                                    if (u instanceof InvokeStmt) {
                                        InvokeStmt invokeStmt = (InvokeStmt) u;
                                        if (invokeStmt.getInvokeExpr().getMethod().getSignature().equals("<android.os.Messenger: void <init>(android.os.Handler)>")) {
                                            type = "HANDLER_" + invokeStmt.getInvokeExpr().getArgs().get(0).getType();
                                            flag = true;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if (type.equals("android.os.IBinder")) {
                            SootClass declaringClass = assignStmt.getFieldRef().getFieldRef().declaringClass();
                            SootMethod init = declaringClass.getMethodByName("<init>");
                            for (Unit u : init.retrieveActiveBody().getUnits()) {
                                if (u instanceof AssignStmt) {
                                    AssignStmt assign = (AssignStmt) u;
                                    if (assign.getLeftOp().toString().equals(assignStmt.getRightOp().toString()))
                                        type = assign.getUseBoxes().get(0).getValue().getType().toString();

                                }
                            }
                            if (type.equals("android.os.IBinder")) {
                                SootMethod onBind = declaringClass.getMethodByName("onBind");

                            }
                        }
                        type = "STUB_" + type;
                    }
                } else if (assignStmt.getRightOp() instanceof NewExpr) {
                    type = "STUB_" + assignStmt.getRightOp().getType().toString();
                }
            } else if (unit instanceof InvokeStmt) {
                InvokeStmt invokeStmt = (InvokeStmt) unit;
                InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
                type = "HANDLER_" + invokeExpr.getArgs().get(0).getType().toString();

            }
            if (type != null)
                res.add(type);
        }
    }

    private static HashSet<Unit> findLastDefUnit(BriefUnitGraph graph, Unit unit, Value value) {
        HashSet<Unit> res = new HashSet<>();
        HashSet<Unit> visit = new HashSet<>();
        Queue<Unit> queue = new LinkedList<>();
        queue.add(unit);
        while (!queue.isEmpty()) {
            Unit currentUnit = queue.poll();
            visit.add(currentUnit);

            if (isValueDefInUnit(currentUnit, value)) {
                if (currentUnit instanceof AssignStmt) {
                    AssignStmt assignStmt = (AssignStmt) currentUnit;
                    if (assignStmt.containsFieldRef()) {
                        res.add(currentUnit);
                    } else if (assignStmt.containsInvokeExpr()) {
                        SootMethod method = assignStmt.getInvokeExpr().getMethod();
                        if (method.getSignature().equals("<android.os.Messenger: android.os.IBinder getBinder()>")) {
                            Value messengerValue = assignStmt.getUseBoxes().get(assignStmt.getUseBoxes().size() - 1).getValue();
                            res.addAll(findLastDefUnit(graph, currentUnit, messengerValue));
                            continue;
                        }
                        if (!method.isConcrete())
                            continue;
                        Body body = method.retrieveActiveBody();
                        if (body == null) {
                            logger.info("Can't get body of {}", method.getSignature());
                        } else {
                            BriefUnitGraph callerGraph = new BriefUnitGraph(body);
                            for (Unit retUnit : callerGraph.getTails()) {
                                if (retUnit instanceof ReturnStmt) {
                                    ReturnStmt returnStmt = (ReturnStmt) retUnit;
                                    Value retValue = returnStmt.getOp();
                                    if (!retValue.toString().equals("null")) {
                                        res.addAll(findLastDefUnit(callerGraph, retUnit, retValue));
                                    }
                                }
                            }
                        }
                    } else if (!assignStmt.containsArrayRef()) {
                        if (assignStmt.getRightOp() instanceof NewExpr) {
                            String instanceType = ((NewExpr) assignStmt.getRightOp()).getBaseType().toString();
                            if (instanceType.equals("android.os.Messenger")) {
                                HashSet<Unit> isVisit = new HashSet<>();
                                Queue<Unit> queue_temp = new LinkedList<>();
                                queue_temp.add(currentUnit);
                                while (!queue_temp.isEmpty()) {
                                    Unit poll = queue_temp.poll();
                                    isVisit.add(poll);
                                    if (poll instanceof InvokeStmt) {
                                        InvokeStmt invokeStmt = (InvokeStmt) poll;
                                        InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
                                        if (invokeExpr.getMethod().getSignature().equals("<android.os.Messenger: void <init>(android.os.Handler)>")) {
                                            res.add(poll);
                                        } else {
                                            queue_temp.addAll(graph.getSuccsOf(poll));
                                        }
                                    } else {
                                        for (Unit succor : graph.getSuccsOf(poll)) {
                                            if (!isVisit.contains(succor))
                                                queue_temp.add(succor);
                                        }
                                    }
                                }
                            } else {
                                res.add(currentUnit);
                            }
                        } else {
                            value = currentUnit.getUseBoxes().get(0).getValue();
                            for (Unit prrUnit : graph.getPredsOf(currentUnit)) {
                                if (!visit.contains(prrUnit))
                                    queue.add(prrUnit);
                            }
                        }
                    }
                } else if (currentUnit instanceof IdentityStmt) {
                }

            } else {
                for (Unit prrUnit : graph.getPredsOf(currentUnit)) {
                    if (!visit.contains(prrUnit))
                        queue.add(prrUnit);
                }
            }
        }
        return res;
    }

    private static boolean isValueDefInUnit(Unit unit, Value value) {
        for (ValueBox valueBox : unit.getDefBoxes()) {
            if (valueBox.getValue().toString().equals(value.toString()))
                return true;
        }
        return false;
    }

    public static boolean isSystemClass(String clsName) {
        if (clsName.startsWith("java.") || clsName.startsWith("javax."))
            return true;
        if (clsName.startsWith("android.") || clsName.startsWith("androidx.") || clsName.startsWith("com.google.") || clsName.startsWith("com.android."))
            return true;
        if (clsName.startsWith("jdk"))
            return true;
        if (clsName.startsWith("sun."))
            return true;
        if (clsName.startsWith("org.omg") || clsName.startsWith("org.w3c.dom"))
            return true;
        return false;

    }


    public static HashSet<SootMethod> getInputMethodMultiThread_limit(String pkgName) throws InterruptedException {
        Set<SootMethod> inputMethodSet = Collections.newSetFromMap(new ConcurrentHashMap<>());
        List<SootClass> allClasses = new ArrayList<>(Scene.v().getApplicationClasses());

        int nThreads = Math.min(Runtime.getRuntime().availableProcessors(),64);
        ExecutorService executor = Executors.newFixedThreadPool(nThreads);

        int chunkSize = (allClasses.size() + nThreads - 1) / nThreads;
        AtomicBoolean stopFlag = new AtomicBoolean(false);
        int threshold = 300;

        for (int i = 0; i < allClasses.size(); i += chunkSize) {
            int start = i;
            int end = Math.min(i + chunkSize, allClasses.size());

            executor.submit(() -> {
                for (SootClass cls : allClasses.subList(start, end)) {
                    if (stopFlag.get()) return;

                    String clsName = cls.getName();
                    if (isSystemClass(clsName)) continue;
                    if (clsName.contains(".sdk.")) continue;
                    if (clsName.startsWith("com.") && !clsName.startsWith("com." + pkgName.split("\\.")[1] + ".")) continue;
                    if (clsName.startsWith("okio.") || clsName.startsWith("okhttp")) continue;

                    for (SootMethod method : cls.getMethods()) {
                        if (stopFlag.get()) return;

                        if (!method.isConcrete() || method.isJavaLibraryMethod() || method.isAbstract() || method.isPhantom() || method.isNative())
                            continue;

                        Body body;
                        try {
                            body = method.retrieveActiveBody();
                        } catch (Exception e) {
                            continue;
                        }

                        for (Unit u : body.getUnits()) {
                            if (stopFlag.get()) return;

                            Stmt stmt = (Stmt) u;
                            if (stmt.containsInvokeExpr()) {
                                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                                String signature = invokeExpr.getMethod().getSignature();
                                if (signature.contains("getIntent") || signature.contains("getData")) {
                                    inputMethodSet.add(method);

                                    if (inputMethodSet.size() >= threshold) {
                                        stopFlag.set(true);
                                        return;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        executor.shutdown();
        while (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
            if (stopFlag.get()) {
                executor.shutdownNow();
                break;
            }
        }

        return new HashSet<>(inputMethodSet);
    }


}
