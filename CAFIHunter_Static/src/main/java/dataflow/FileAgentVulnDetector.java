package dataflow;
import cg.CallGraphUtils;
import component.EntryPointAnalyze;
import component.FAComponent;
import component.ResolveManifest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import util.DirTraversal;
import util.Log;
import util.SootInit;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static soot.SootClass.BODIES;

public class FileAgentVulnDetector extends Thread {
    private Logger logger = LoggerFactory.getLogger(FileAgentVulnDetector.class);

    private String androidJar;

    private String logFileName;

    private String logError="logError.txt";

    private String permissionInfoFile;

    private String systemActionFile;

    private HashMap<String, Integer> permissionInfo = new HashMap<>();

    private HashSet<String> systemActions=new HashSet<>();

    private String apkDir;

    private HashSet<String> detectedAppInfo = new HashSet<>();

    private String sinkFile;

    private String dataSavedDir;

    private HashSet<String> sinks = new HashSet<>();

    private JimpleBasedInterproceduralCFG icfg = null;

    private Queue<String> appWaitForProcess = new LinkedList<>();

    private HashSet<AbstractBinaryAndroidComponent> reachableComponents = null;

    private Thread executor = null;

    double timeout = 300;

    public void setTimeout(double timeout) {
        this.timeout = timeout;
    }

    public static final String[] component_array={
            "com.onesignal.NotificationOpenedReceiver",
            "com.appsflyer.SingleInstallBroadcastReceiver",
            "com.learnium.RNDeviceInfo.RNDeviceReceiver",
            "com.adobe.phonegap.push.PushHandlerActivity",
            "com.appsflyer.MultipleInstallBroadcastReceiver",
            "host.exp.exponent.LauncherActivity",
            "com.onesignal.NotificationOpenedReceiverAndroid22AndOlder",
            "host.exp.exponent.referrer.InstallReferrerReceiver",
            "com.appbrain.ReferrerReceiver",
            "com.kochava.base.ReferralReceiver",
            "org.altbeacon.beacon.startup.StartupBroadcastReceiver",
            "host.exp.exponent.MainActivity",
            "com.kidoz.sdk.api.receivers.SdkReceiver",
            "com.blingstory.app.ui.launcher.LauncherActivity",
            "com.alipay.sdk.app.PayResultActivity",
            "com.tencent.tauth.AuthActivity",
            "com.alipay.sdk.app.AlipayResultActivity"
    };
    public static final List<String> component_blackList=Arrays.asList(component_array);

    public FileAgentVulnDetector(String apkDir, String androidJar, String logFileName, String permissionInfoFile,String systemActionFile, String sinkInfo,String dataSavedDir) {
        this.apkDir = apkDir;
        this.androidJar = androidJar;
        this.logFileName = logFileName;
        this.permissionInfoFile = permissionInfoFile;
        this.sinkFile = sinkInfo;
        this.dataSavedDir=dataSavedDir;
        this.systemActionFile=systemActionFile;
        init();
    }
    private void init() {
        logger.info("init the detector ...");
        permissionInfo = getDevicePermissionInfo(new File(permissionInfoFile));
        systemActions=null;
        initSinks();

        logError=dataSavedDir+File.separator+"logError.txt";
    }
    public void analyze() throws Exception {

        logger.info("Begin detect app ....");

        new DirTraversal() {
            @Override
            public void work(File f) throws Exception {
                if (!f.getName().endsWith(".apk")) {
                    logger.info("Exit:0 "+f.getName());
                    return;
                }
                detectedAppInfo = getDetectedAppInfo(logFileName);
                if (detectedAppInfo.contains(f.getName())) {
                    logger.info("Exit:1 "+f.getName());
                    return;
                }

                appWaitForProcess.add(f.getPath());
            }
        }.traverse(new File(apkDir));
    }

    public void run() {
        while (!appWaitForProcess.isEmpty()) {
            String apkPath = appWaitForProcess.poll();
            if (apkPath == null) continue;
            File f = new File(apkPath);

            HashSet<String> detected = getDetectedAppInfo(logFileName);
            if (detected.contains(f.getName())) {
                logger.info("Exit:1 {}", f.getName());
                continue;
            }

            long startTime = System.currentTimeMillis();
            int exitCode = runOneApkInChildProcess(apkPath, (long) timeout);

            long endTime = System.currentTimeMillis();
            long cost_time = endTime - startTime;
            Log.openLog(logFileName, true);
            Log.write(Log.Mode.RECORD,
                    "[Info]:Analyze time(s): " + cost_time/1000.0);
            Log.closeLog();

            logger.info("Child finished. app={} exitCode={}", f.getName(), exitCode);
        }
    }

    private int runOneApkInChildProcess(String apkPath, long timeoutSeconds) {
        Process p = null;
        try {
            List<String> cmd = new ArrayList<>();
            cmd.add("java");
            cmd.add("-Xmx6g");
            cmd.add("-cp");
            cmd.add(System.getProperty("java.class.path"));

            cmd.add("dataflow.CAFIVulnDetector");

            cmd.add(apkPath);
            cmd.add(apkDir);
            cmd.add(androidJar);
            cmd.add(logFileName);
            cmd.add(permissionInfoFile);
            cmd.add(systemActionFile);
            cmd.add(sinkFile);
            cmd.add(dataSavedDir);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            p = pb.start();

            Process finalP = p;
            Thread pump = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(finalP.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        logger.info("[child] {}", line);
                    }
                } catch (IOException ignored) {}
            });
            pump.setDaemon(true);
            pump.start();

            boolean ok = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!ok) {
                logger.warn("Time Out! kill child. apk={}", apkPath);

                Log.openLog(logFileName, true);
                Log.write(Log.Mode.RECORD, "[Error]:Time Out!");
                Log.closeLog();

                p.destroy();
                try { p.waitFor(500, TimeUnit.MILLISECONDS); } catch (InterruptedException ignored) {}
                if (p.isAlive()) p.destroyForcibly();

                return -2;
            }

            return p.exitValue();

        } catch (Exception e) {
            logger.error("Run child process failed: {}", apkPath, e);
            try {
                Log.openLog(logFileName, true);
                Log.write(Log.Mode.RECORD, "[Error]:Analyze Failed!");
                Log.closeLog();
            } catch (Exception ignore) {}
            return -1;
        } finally {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
        }
    }


    public void run(String apkPath) {

        File file = new File(apkPath);
        HashSet<String> detectedAppInfo = getDetectedAppInfo(logFileName);
        if (detectedAppInfo.contains(apkPath)) {
            logger.info("App has been analyzed!");
            return;
        }

        Log.openLog(logFileName, true);
        Log.write(Log.Mode.APP, file.getName());
        Log.write(Log.Mode.PKGNAME,ResolveManifest.getPackageName(file));
        String versionName = ResolveManifest.getVersionName(file);
        Log.write(Log.Mode.VERSION, versionName);
        Log.write(Log.Mode.PATH, file.getPath());
        Log.closeLog();

        SootInit.initSootForAndroid(apkPath, androidJar);

        logger.info("detector begin detect {}", file.getName());

        logger.info("get FileAgentComponents");
        List<FAComponent> fileAgentComponents = ResolveManifest.getFileAgentComponents(apkPath);
        for (FAComponent fileAgentComponent : fileAgentComponents) {
            logger.info("FileAgent: {}",fileAgentComponent);
        }

        boolean isfileAgentApp = !fileAgentComponents.isEmpty() && fileAgentComponents.size() != 0;
        if(isfileAgentApp)
            recordManifestAnalyze(apkPath,fileAgentComponents);

        try{
            reachableComponents = ResolveManifest.getReachableComponents(apkPath, permissionInfo,systemActions);

            if(reachableComponents.isEmpty()){
                Log.openLog(logFileName, true);
                Log.write(Log.Mode.RECORD,"[Error] no reachableComponents");
                Log.closeLog();
                return;
            }
        }catch (Exception e){
            e.printStackTrace();
            Log.openLog(logFileName, true);
            Log.write(Log.Mode.RECORD,"[Error] Reachable components analysis failed!");
            Log.closeLog();
            return;

        }


        List<SootMethod> entrys = new ArrayList<>();

        logger.info("Add all export component life cycle methods as entry! ");
        assert reachableComponents != null;
        HashMap<String, HashSet<SootMethod>> component2MapEntryPoint =
                EntryPointAnalyze.getComponent2MapEntryPoint(reachableComponents);

        for (String components : component2MapEntryPoint.keySet()){
            if(component_blackList.contains(components))
                continue;
            if(isFilterComponent(components)){
                continue;
            }
            for (SootMethod m : component2MapEntryPoint.get(components))
                if (m != null)
                    entrys.add(m);
        }
        logger.info("All export component entry size: {}",entrys.size());
        logger.info("Add all input methods as entry!");

        HashSet<SootMethod> inputMethods = null;
        try {
            inputMethods = EntryPointAnalyze.getInputMethodMultiThread_limit(ResolveManifest.getPackageName(file));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        logger.info("Input methods as size: {}",inputMethods.size());
        entrys.addAll(inputMethods);


        logger.info("There are {} entry points", entrys.size());

        logger.info("Building CG ......");

        CallGraphUtils.buildCGbyCHA(entrys);
        CallGraph callGraph = Scene.v().getCallGraph();

        logger.info("Call Graph Size: {}", callGraph.size());

        logger.info("ReachableMethods Size: {}",Scene.v().getReachableMethods().size());

        int counter_sink = computeSinkInApp();
        if (counter_sink == 0) {
            logger.info("No sink is found in App!");
            Log.openLog(logFileName, true);
            Log.write(Log.Mode.RECORD,"[Error] no sink");
            Log.closeLog();
            return;
        }

        logger.info("There are {} sinks which is found in App!", counter_sink);

        logger.info("Building ICFG ......");

        icfg = new JimpleBasedInterproceduralCFG();
        HashMap<Unit, HashSet<String>> loader2SensitiveSite = new HashMap<>();
        HashMap<Unit,String> loader2MetaData=new HashMap<>();

        HashMap<String, HashSet<SootMethod>> mapEntryPoint = EntryPointAnalyze.getComponent2MapEntryPoint(reachableComponents);
        HashSet<SootMethod> allEntrys = new HashSet<>();
        for (String component : mapEntryPoint.keySet()) {
            if(component_blackList.contains(component))
                continue;
            if(isFilterComponent(component)){
                continue;
            }
            HashSet<SootMethod> methods = mapEntryPoint.get(component);
            for(SootMethod stMethod:methods){
                String methodSignature=stMethod.getSignature();
                if(methodSignature.contains("onCreate") || methodSignature.contains("onNewIntent")){
                    allEntrys.add(stMethod);
                }
            }
        }


        try {
            Map<String,List<String>> callMethodMap=new HashMap<>();
            List<List<String>> callgetIntentPaths = findPathToTarget(callGraph, allEntrys, "getIntent", 5);
            for (int i = 0; i < callgetIntentPaths.size(); i++) {
                List<String> path = callgetIntentPaths.get(i);
                System.out.println("Path " + (i + 1) + ":");
                for (String sig : path) {
                    System.out.println("  -> " + sig);
                }
                System.out.println();
                callMethodMap.put(path.get(path.size()-2),path);
            }

            FileAgentChecker fileAgentChecker = new FileAgentChecker(sinks,icfg);

            DataFlowEngine sensitiveDataUsageDetector = new DataFlowEngine(icfg);

            sensitiveDataUsageDetector.setChecker(fileAgentChecker);

            FAUseFinder FA_USE_FINDER=new FAUseFinder();

            sensitiveDataUsageDetector.setImplicitMode(false);

            sensitiveDataUsageDetector.setTimeOut(300);

            for(SootMethod m:inputMethods){
                if(callMethodMap.containsKey(m))
                    continue;
                callMethodMap.put(m.getSignature(), Arrays.asList(new String[]{"Input Method Enrty"}));
            }

            for(String callMethod:callMethodMap.keySet()){

                logger.info("Analyse call genIntent method: {}",callMethod);

                SootMethod method=Scene.v().getMethod(callMethod);

                HashSet<Unit> intentInvokeUnits = getGetIntentInvokeUnit(method);

                logger.info("intentInvokeUnits size: {}",intentInvokeUnits.size());

                for (Unit callSite:intentInvokeUnits){

                    ValueBox headBox = callSite.getDefBoxes().get(0);

                    headBox.addTag(new AccessPathTag());

                    sensitiveDataUsageDetector.forwardDataFlow_1(method, null, callSite, headBox, -1, 0);

                    HashSet<String> sinkMethodTrue = fileAgentChecker.getSinkMethodTrue();

                    HashSet<SootMethod> sinkMethods = fileAgentChecker.getSinkMethods();

                    logger.info("genIntent to sinkMethod size: {}",sinkMethodTrue.size());

                    if (!sinkMethodTrue.isEmpty()) {
                        if(!check_core_sinks(sinkMethodTrue)){
                            logger.info("No core sinkMethods are called.");
                            continue;
                        }
                        if (!loader2SensitiveSite.containsKey(callSite))
                            loader2SensitiveSite.put(callSite, new HashSet<>());

                        List<String> path = callMethodMap.get(callMethod);
                        String pathChain="";
                        for (String sig : path) {
                            pathChain+="  -> " + sig+"\n";
                        }


                        FA_USE_FINDER.setMAX_DEPTH(3);

                        FA_USE_FINDER.inter_forward(method,0,new ArrayList<>());
                        for (SootMethod sinkMethod : sinkMethods) {
                            FA_USE_FINDER.inter_forward(sinkMethod,0,new ArrayList<>());
                        }
                        String apiRecords = FA_USE_FINDER.getApiRecords();
                        logger.info(apiRecords);
                        loader2SensitiveSite.get(callSite).addAll(sinkMethodTrue);
                        loader2MetaData.put(callSite,"FILE_Agent EntryPoint\n"+pathChain+apiRecords);

                        FA_USE_FINDER.clearApiRecords();
                        fileAgentChecker.clearSinkMethodTrue();
                        fileAgentChecker.clearSinkMethods();
                    }

                }

            }

            logger.info("Record analyze result ...");
            recordAnalyze(apkPath, loader2SensitiveSite,loader2MetaData,isfileAgentApp);

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private boolean check_core_sinks(HashSet<String> sinkMethods){
        boolean contains = sinkMethods.stream()
                .anyMatch(m -> m.contains("FileOutputStream")
                        || m.contains("openInputStream")
                        || m.contains("openFileDescriptor")
                        || m.contains("openAssetFileDescriptor")
                        || m.contains("write"));
        return contains;
    }

    public static boolean isFilterComponent(String componentName){
        String[] filterKey={".wxapi.","com.tencent.tauth",".sdk.",".amap.api."};
        boolean flag=false;
        for(String key:filterKey){
            if(componentName.contains(key)){
                flag=true;
                break;
            }
        }
        return flag;
    }

    public static List<List<String>> findPathToTarget(CallGraph cg,Collection<SootMethod> entryPoints,
                                                      String methodName,
                                                      int maxDepth) {
        List<List<String>> results = new ArrayList<>();

        Queue<List<SootMethod>> queue = new LinkedList<>();

        for (SootMethod entry : entryPoints) {
            List<SootMethod> init = new ArrayList<>();
            init.add(entry);
            queue.add(init);
        }

        Set<SootMethod> visited = new HashSet<>();

        while (!queue.isEmpty()) {
            List<SootMethod> path = queue.poll();
            SootMethod current = path.get(path.size() - 1);

            if (path.size() > maxDepth) {
                continue;
            }
            if (!visited.add(current)) {
                continue;
            }
            Iterator<Edge> outEdges = cg.edgesOutOf(current);
            while (outEdges.hasNext()) {
                SootMethod callee = outEdges.next().tgt();

                List<SootMethod> newPath = new ArrayList<>(path);
                newPath.add(callee);

                if (callee.getName().equals(methodName)||callee.getSubSignature().contains("getData")) {
                    List<String> pathStrings = new ArrayList<>();
                    for (SootMethod m : newPath) {
                        pathStrings.add(m.getSignature());
                    }
                    results.add(pathStrings);
                } else {
                    queue.add(newPath);
                }
            }
        }

        return results;
    }

    public static HashSet<Unit> getGetIntentInvokeUnit(SootMethod method) {

        HashSet<Unit> res = new HashSet<>();
        if (method.getDeclaringClass().resolvingLevel() != BODIES)
            return res;
        for (Unit unit : method.retrieveActiveBody().getUnits()) {
            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                if (assignStmt.containsInvokeExpr()) {
                    String subSignature = assignStmt.getInvokeExpr().getMethod().getSubSignature();
                    if (subSignature.contains("getIntent") || subSignature.contains("getData")) {
                        res.add(unit);
                    }
                }
            }
        }
        return res;
    }

    private void recordManifestAnalyze(String apkName,List<FAComponent> fileAgentComponents){
        try {
            String dirPath = dataSavedDir+File.separator+"data_use_info";
            File dir = new File(dirPath);
            if(!dir.exists())
                dir.mkdirs();
            File temp = new File(apkName);
            String path = dirPath + File.separator + temp.getName().replace("apk", "txt");
            File file = new File(path);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
            writer.write("[App]:" + apkName + "\n");
            for (FAComponent fileAgentComponent : fileAgentComponents) {
                writer.write("=============================================================================\n");
                writer.write(fileAgentComponent.toString());
            }
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void recordAnalyze(String apkName, HashMap<Unit, HashSet<String>> res,HashMap<Unit,String> loader2Metadata,boolean isFileAgentApp) {
        try {
            String dirPath = dataSavedDir+File.separator+"data_use_info";
            File dir = new File(dirPath);
            if(!dir.exists())
                dir.mkdirs();
            File temp = new File(apkName);
            String path = dirPath + File.separator + temp.getName().replace("apk", "txt");
            File file = new File(path);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));

            if(!isFileAgentApp)
                writer.write("[App]:" + apkName + "\n");

            for (Unit loaderSite : res.keySet()) {
                writer.write("=============================================================================\n");
                writer.write("[Loader Site]: " + loaderSite + '\n');
                writer.write("[LOAD_FILE_INFO]: \n"+loader2Metadata.get(loaderSite)+'\n');
                SootMethod method = icfg.getMethodOf(loaderSite);
                writer.write("[Load Method]: " + method.getSignature() + '\n');
                int counter = 0;
                for (String info : res.get(loaderSite)) {
                    writer.write("--------------------------------sink method " + counter + "---------------------------------" + '\n');
                    writer.write(info + '\n');
                    counter++;
                }
            }
            if(res.isEmpty()){
                writer.write("=============================================================================\n");
                writer.write("[Error]: No File Agent Usage is found!" + '\n');
            }

            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int computeSinkInApp() {
        int counter = 0;
        ReachableMethods reachableMethods = Scene.v().getReachableMethods();
        for (String sig : sinks) {
            try {
                SootMethod method = Scene.v().getMethod(sig);
                if (reachableMethods.contains(method))
                    counter++;

            } catch (Exception e) {}
        }
        return counter;
    }

    public static HashSet<String> getDetectedAppInfo(String fileName) {
        HashSet<String> res = new HashSet<>();
        try {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader reader = new BufferedReader(fileReader);
            String line = null;
            while ((line = reader.readLine()) != null) {
                if (line.contains("APP:")) {
                    String[] split = line.split(":");
                    res.add(split[1].substring(1));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public static HashMap<String, Integer> getDevicePermissionInfo(File permissionFile) {
        HashMap<String, Integer> res = new HashMap<>();
        try( FileInputStream in = new FileInputStream(permissionFile);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in))){

            String line = null;
            String permission = null;
            String protectLevel = null;
            while ((line = reader.readLine()) != null) {
                if (line.contains("permission:")) {
                    permission = line.split(":")[1];
                }
                if (line.contains("protectionLevel:")) {
                    protectLevel = line.split(":")[1];
                    if (protectLevel.contains("normal")) {
                        res.put(permission, 0);
                    } else if (protectLevel.contains("dangerous")) {
                        res.put(permission, 1);
                    } else if (protectLevel.contains("signature")) {
                        res.put(permission, 2);
                    } else {
                        res.put(permission, 3);
                    }
                }
            }
            return res;
        } catch (Exception e) {
            return res;
        }
    }

    private void initSinks() {
        logger.info("Init Sinks Info ....");
        File file = new File(this.sinkFile);
        try(BufferedReader bufferedReader = new BufferedReader(new FileReader(file))){
            String line = null;
            while ((line = bufferedReader.readLine()) != null) {
                sinks.add(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        logger.info("Sinks size: {}",sinks.size());

    }

}
