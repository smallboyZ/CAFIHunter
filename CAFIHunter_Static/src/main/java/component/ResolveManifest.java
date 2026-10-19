package component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.manifest.binary.*;
import java.io.File;
import java.util.*;


public class ResolveManifest {

    private final static Logger logger = LoggerFactory.getLogger(ResolveManifest.class.getName());

    private static boolean permissionIsProtected(String permission, HashMap<String, Integer> permissionMap){
        if(!permissionMap.containsKey(permission)){
            logger.warn("A permission without definition, marked as low level as default");
            return false;
        }
        if(permissionMap.get(permission) == 2 || permissionMap.get(permission) == 3)
            return true;
        else return false;
    }

    private static boolean isReachableActivity(AXmlNode aXmlNode, HashMap<String, Integer> allPermissionMap){
        if(isCalledBySelf(aXmlNode))
            return false;
        AXmlAttribute<?> attrEnabled = aXmlNode.getAttribute("enabled");
        boolean enabled = attrEnabled == null || !attrEnabled.getValue().equals(Boolean.FALSE);
        if(!enabled)
            return false;

        if(aXmlNode.hasAttribute("exported")){
            if(aXmlNode.getAttribute("exported").getValue().equals(false)) return false;
            else{
                if(!aXmlNode.hasAttribute("permission")) return true;
                else{
                    String permission = (String) aXmlNode.getAttribute("permission").getValue();
                    return !permissionIsProtected(permission, allPermissionMap);
                }
            }
        }
        else {
            if(aXmlNode.getChildrenWithTag("intent-filter").size() > 0) {
                if(!aXmlNode.hasAttribute("permission")) return true;
                else{
                    String permission = (String) aXmlNode.getAttribute("permission").getValue();
                    return !permissionIsProtected(permission, allPermissionMap);
                }
            }
            else return false;
        }
    }

    private static boolean isReachableActivity(AXmlNode aXmlNode){
        if(isCalledBySelf(aXmlNode))
            return false;
        AXmlAttribute<?> attrEnabled = aXmlNode.getAttribute("enabled");
        boolean enabled = attrEnabled == null || !attrEnabled.getValue().equals(Boolean.FALSE);
        if(!enabled)
            return false;

        if(aXmlNode.hasAttribute("exported")){
            if(aXmlNode.getAttribute("exported").getValue().equals(false)) return false;
            else{
                return true;
            }
        }
        else {
            if(aXmlNode.getChildrenWithTag("intent-filter").size() > 0) {
                    return true;
            }
            else return false;
        }
    }

    private static boolean isReachableProvider(AXmlNode aXmlNode, HashMap<String, Integer> allPermissionMap, String mode){
        if(isCalledBySelf(aXmlNode))
            return false;
        assert Arrays.asList("wr", "r", "w", "w|r").contains(mode);
        AXmlAttribute<?> attrEnabled = aXmlNode.getAttribute("enabled");
        boolean enabled = attrEnabled == null || !attrEnabled.getValue().equals(Boolean.FALSE);
        if(!enabled)
            return false;
        if(aXmlNode.hasAttribute("exported")){
            if(aXmlNode.getAttribute("exported").getValue().equals(false)) return false;
            else{
                boolean flag, readFlag, writeFlag;
                if(!aXmlNode.hasAttribute("permission")) flag = true;
                else{
                    String permission = (String) aXmlNode.getAttribute("permission").getValue();
                    flag = !permissionIsProtected(permission, allPermissionMap);
                }
                if(!aXmlNode.hasAttribute("writePermission")) writeFlag = true;
                else{
                    String permission = (String) aXmlNode.getAttribute("writePermission").getValue();
                    writeFlag = !permissionIsProtected(permission, allPermissionMap);
                }
                if(!aXmlNode.hasAttribute("readPermission")) readFlag = true;
                else{
                    String permission = (String) aXmlNode.getAttribute("readPermission").getValue();
                    readFlag = !permissionIsProtected(permission, allPermissionMap);
                }
                if(mode.equals("r")) return flag && readFlag;
                if(mode.equals("w")) return flag && writeFlag;
                if(mode.equals("wr")) return flag && writeFlag && readFlag;
                if(mode.equals("w|r")) return flag && (writeFlag || readFlag);
                logger.warn("Using isReachableProvider() with wrong mode");
                return flag && (writeFlag || readFlag);
            }
        }
        else {
            return false;
        }
    }


    private static boolean isCalledBySelf(AXmlNode aXmlNode){
        if(!aXmlNode.hasAttribute("process"))
            return false;
        return aXmlNode.getAttribute("process").getValue().toString().contains(":");
    }
    private static boolean isSystemAction(AXmlNode aXmlNode,HashSet<String> systemActions){
        List<AXmlNode> children = aXmlNode.getChildrenWithTag("intent-filter");
        if(children.isEmpty())
            return false;
        for(AXmlNode child:children){
            List<AXmlNode> actionAxmlNode = child.getChildrenWithTag("action");
            for(AXmlNode action:actionAxmlNode){
                if(action.hasAttribute("name")){
                    String actionName = action.getAttribute("name").getValue().toString();
                    if(!systemActions.contains(actionName))
                        return false;
                }
            }
        }
        return true;
    }


    public static HashSet<AbstractBinaryAndroidComponent> getReachableComponents(String apkPath,HashMap<String,Integer> permissionInfo,HashSet<String> systemAction){

        if(!apkPath.endsWith(".apk"))
            return null;

        try {
            ProcessManifest manifest = new ProcessManifest(apkPath);
            HashMap<String,Integer> permissionMap=new HashMap<>(permissionInfo);
            HashSet<String> protectedBroadcasts=new HashSet<>();
            HashSet<AbstractBinaryAndroidComponent> reachableComponents = new HashSet<>();
            for(AXmlNode permission:manifest.getManifest().getChildrenWithTag("permission")) {
                if(permission.getAttribute("protectionLevel") == null) permissionMap.put(permission.getAttribute("name").getValue().toString(), 0);
                else {
                    permissionMap.put(permission.getAttribute("name").getValue().toString(),(Integer) permission.getAttribute("protectionLevel").getValue());
                }
            }
            for(BinaryManifestActivity activity: manifest.getActivities()){
                AXmlNode aXmlNode=activity.getAXmlNode();
                if(isReachableActivity(aXmlNode, permissionMap)) {
                    reachableComponents.add(activity);
                }
            }

            for(BinaryManifestContentProvider provider: manifest.getContentProviders()){
                AXmlNode aXmlNode=provider.getAXmlNode();
                if(isReachableProvider(aXmlNode, permissionMap, "w")) {
                    reachableComponents.add(provider);
                }
            }
            return reachableComponents;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String getPackageName(File file){
        try {
            ProcessManifest processManifest = new ProcessManifest(file);

            return processManifest.getPackageName();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String getVersionName(File file){
        try {
            ProcessManifest processManifest = new ProcessManifest(file);
            return processManifest.getVersionName();
        }catch (Exception e){
            e.printStackTrace();

        }
        return "";
    }

    public static List<FAComponent> getFileAgentComponents(String apkPath){
        List<FAComponent> res = new ArrayList<>();
        try {
            ProcessManifest manifest = new ProcessManifest(apkPath);
            for (BinaryManifestActivity activity : manifest.getActivities()) {

                AXmlNode aXmlNode = activity.getAXmlNode();
                if(!isReachableActivity(aXmlNode)){
                    continue;
                }

                FAComponent fac=new FAComponent(activity.getNameString());


                List<AXmlNode> intentFilters  = aXmlNode.getChildrenWithTag("intent-filter");
                for (AXmlNode filterNode : intentFilters ) {

                    List<AXmlNode> actions = filterNode.getChildrenWithTag("action");
                    for (AXmlNode actionNode : actions) {
                        if (actionNode.hasAttribute("name")){
                            String actionName = actionNode.getAttribute("name").getValue().toString();
                            if(actionName!=null)
                                fac.actions.add(actionName);
                        }
                    }

                    List<AXmlNode> datas = filterNode.getChildrenWithTag("data");
                    for (AXmlNode dataNode : datas) {

                        if(dataNode.hasAttribute("scheme")){
                            String scheme = dataNode.getAttribute("scheme").getValue().toString();
                            if(scheme!=null) fac.dataSchemes.add(scheme);
                        }

                        if (dataNode.hasAttribute("mimeType")) {
                            Object mimeTypeValue = dataNode.getAttribute("mimeType").getValue();
                            if (mimeTypeValue != null) {
                                fac.mimeTypes.add(mimeTypeValue.toString());
                            }
                        }

                        if (dataNode.hasAttribute("pathPattern")) {
                            Object pathPatternValue = dataNode.getAttribute("pathPattern").getValue();
                            if (pathPatternValue != null) {
                                fac.pathPatterns.add(pathPatternValue.toString());
                            }
                        }
                    }

                }

                if (fac.matchesFilter()) {
                    res.add(fac);
                }
            }


        }catch (Exception e){
            e.printStackTrace();

        }
        return res;
    }
}
