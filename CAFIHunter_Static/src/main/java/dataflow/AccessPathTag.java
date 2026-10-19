package dataflow;

import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;


public class AccessPathTag implements Tag {

    private int fieldLength = 0;

    private String fieldChain = "";

    @Override
    public String getName() {
        return "AccessPath";
    }

    public AccessPathTag(Tag tag) {
        AccessPathTag accessPathTag = (AccessPathTag) tag;
        fieldChain = accessPathTag.fieldChain;
        fieldLength=accessPathTag.fieldLength;
    }

    public AccessPathTag() {

    }


    @Override
    public byte[] getValue() throws AttributeValueException {
        return null;
    }

    public boolean appendAccessPath(String fieldName) {
        if (fieldLength == 5) {
            return false;
        } else {
            fieldChain = fieldName + "." + fieldChain;
            fieldLength += 1;
            return true;
        }
    }

    public boolean removeAccessPath() {
        if (fieldLength == 0)
            return true;
        byte[] bytes = fieldChain.getBytes();
        for (int i = 0; i < fieldChain.length(); i++) {
            if ((char) bytes[i] == '.') {
                fieldChain = fieldChain.substring(i+1);
                return true;
            }
        }
        return false;

    }

    public boolean match(String fieldName) {
        if (fieldChain.isEmpty())
            return true;
        String[] split = fieldChain.split("/.");
        return split[0].replace(".","").equals(fieldName);
    }

    public int getFieldLength() {
        return fieldLength;
    }

    public String getFieldChain(){
        return fieldChain;
    }
}
