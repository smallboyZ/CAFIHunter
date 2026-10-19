package dataflow;
public class CAFIVulnDetector {

    public static void main(String[] args) throws Exception {
        if (args.length < 8) {
            System.err.println("Usage: CAFIVulnDetector <apkPath> <apkDir> <androidJar> <logFileName> <permissionInfoFile> <systemActionFile> <sinkInfo> <dataSavedDir>");
            System.exit(2);
        }

        String apkPath = args[0];
        String apkDir = args[1];
        String androidJar = args[2];
        String logFileName = args[3];
        String permissionInfoFile = args[4];
        String systemActionFile = args[5];
        String sinkInfo = args[6];
        String dataSavedDir = args[7];

        FileAgentVulnDetector d = new FileAgentVulnDetector(
                apkDir, androidJar, logFileName, permissionInfoFile, systemActionFile, sinkInfo, dataSavedDir
        );

        d.run(apkPath);

        System.exit(0);
    }
}
