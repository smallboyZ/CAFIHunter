package component;

import java.util.HashSet;

public class FAComponent {
    public String component;
    public HashSet<String> actions = new HashSet<>();
    public HashSet<String> dataSchemes = new HashSet<>();
    public HashSet<String> mimeTypes = new HashSet<>();
    public HashSet<String> pathPatterns = new HashSet<>();

    public FAComponent(String component) {
        this.component = component;
    }
    @Override
    public String toString() {
        return "FAComponent: " + component+ "\n" +
                "   actions: " + actions+ "\n" +
                "   dataSchemes: " + dataSchemes+ "\n" +
                "   mimeTypes: " + mimeTypes+ "\n" +
                "   pathPatterns: " + pathPatterns+"\n";
    }
    public boolean matchesFilter() {
        for (String action : actions) {
            String upper = action.toUpperCase();
            if (upper.contains("SEND")) return true;
        }
        for (String scheme : dataSchemes) {
            if ("file".equalsIgnoreCase(scheme) || "content".equalsIgnoreCase(scheme)) return true;
        }
        return !mimeTypes.isEmpty();
    }
}
