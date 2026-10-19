package analyze;

import dataflow.FileAgentVulnDetector;
import picocli.CommandLine;
import picocli.CommandLine.Option;

import java.io.*;
import java.util.*;


public class MainAnalyze {


    public static  String apkDir="";

    public static String androidJar="";

    public static  String logFileName="";

    public static  String permissionInfoFile="";

    public static  String analyzeTimeout="";

    public static String sinkInfo="";

    public static String dataSavedDir="";

    public static String systemActionFile="";

    @Option(names = {"-c", "--config"}, description = "set config file path")
    private static String configPath = "config.properties";
    public static void main(String[] args) throws Exception {

        CommandLine cmd = new CommandLine(MainAnalyze.class);
        cmd.parseArgs(args);

        if (cmd.isUsageHelpRequested()) {
            cmd.usage(System.out);
            return;
        }

        if(!initConfig()){
            System.err.println("init config failed ;-( exit.");
            return;
        }

        FileAgentVulnDetector fileAgentVulnDetector = new FileAgentVulnDetector(apkDir, androidJar, logFileName, permissionInfoFile, systemActionFile, sinkInfo, dataSavedDir);
        fileAgentVulnDetector.analyze();
        fileAgentVulnDetector.setTimeout(Integer.valueOf(analyzeTimeout));
        fileAgentVulnDetector.start();


    }


    private static boolean initConfig() {
        System.out.println("config file path: " + configPath);

        Properties props = new Properties();
        try (InputStream input = new FileInputStream(configPath)) {
            props.load(input);
        } catch (Exception e) {
            System.err.println("read config file failed: " + configPath);
            e.printStackTrace();
            return false;
        }

        apkDir = props.getProperty("apkDir", "");
        androidJar = props.getProperty("androidJar", "");
        logFileName = props.getProperty("logFileName", "");
        permissionInfoFile = props.getProperty("permissionInfoFile", "");
        sinkInfo = props.getProperty("sinkInfo", "");
        dataSavedDir = props.getProperty("dataSavedDir", "");
        systemActionFile = props.getProperty("systemActionFile", "");
        analyzeTimeout=props.getProperty("analyzeTimeOut","1200");
        return true;
    }
}
