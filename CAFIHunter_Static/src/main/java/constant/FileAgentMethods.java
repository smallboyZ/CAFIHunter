package constant;

import java.util.Arrays;
import java.util.List;
public class FileAgentMethods {

    public static final String STRING_EQUALS = "<java.lang.String: boolean equals(java.lang.Object)>";
    public static final String STRING_EQUALSIGNORECASE = "<java.lang.String: boolean equalsIgnoreCase(java.lang.String)>";
    public static final String STRING_STARTSWITH_0 = "<java.lang.String: boolean startsWith(java.lang.String)>";
    public static final String STRING_STARTSWITH_1 = "<java.lang.String: boolean startsWith(java.lang.String,int)>";
    public static final String STRING_ENDSWITH = "<java.lang.String: boolean endsWith(java.lang.String)>";
    public static final String STRING_CONTAINS = "<java.lang.String: boolean contains(java.lang.CharSequence)>";
    public static final String STRING_MATCHES = "<java.lang.String: boolean matches(java.lang.String)>";
    public static final String STRING_INDEXOF_0 = "<java.lang.String: int indexOf(java.lang.String)>";
    public static final String STRING_INDEXOF_1 = "<java.lang.String: int indexOf(java.lang.String,int)>";
    public static final String STRING_LASTINDEXOF_0 = "<java.lang.String: int lastIndexOf(java.lang.String)>";
    public static final String STRING_LASTINDEXOF_1 = "<java.lang.String: int lastIndexOf(java.lang.String,int)>";

    public static final String[] validationAPI={STRING_EQUALS,STRING_EQUALSIGNORECASE,STRING_STARTSWITH_0,STRING_STARTSWITH_1,STRING_ENDSWITH,STRING_CONTAINS,STRING_MATCHES,
            STRING_INDEXOF_0,STRING_INDEXOF_1,STRING_LASTINDEXOF_0,STRING_LASTINDEXOF_1};


    public static final String URI_GETPATH = "<android.net.Uri: java.lang.String getPath()>";
    public static final String URI_GETLASTPATHSEGMENT = "<android.net.Uri: java.lang.String getLastPathSegment()>";
    public static final String URI_GETHOST = "<android.net.Uri: java.lang.String getHost()>";
    public static final String URI_GETAUTHORITY = "<android.net.Uri: java.lang.String getAuthority()>";
    public static final String URI_GETQUERY = "<android.net.Uri: java.lang.String getQuery()>";
    public static final String URI_GETFRAGMENT = "<android.net.Uri: java.lang.String getFragment()>";
    public static final String URLDECODER_DECODE_0 = "<java.net.URLDecoder: java.lang.String decode(java.lang.String,java.lang.String)>";
    public static final String URLDECODER_DECODE_1 = "<java.net.URLDecoder: java.lang.String decode(java.lang.String)>";
    public static final String CONTENTRESOLVER_GETTYPE = "<android.content.ContentResolver: java.lang.String getType(android.net.Uri)>";
    public static final String STRING_SUBSTRING_0 = "<java.lang.String: java.lang.String substring(int)>";
    public static final String STRING_SUBSTRING_1 = "<java.lang.String: java.lang.String substring(int,int)>";

    public static final String[] uriHandleAPI={URI_GETPATH,URI_GETLASTPATHSEGMENT,URI_GETHOST,URI_GETAUTHORITY,URI_GETQUERY,URI_GETFRAGMENT,URLDECODER_DECODE_0,
            URLDECODER_DECODE_1,CONTENTRESOLVER_GETTYPE,STRING_SUBSTRING_0,STRING_SUBSTRING_1};


    public static final String CURSOR_GETCOLUMNINDEX = "<android.database.Cursor: int getColumnIndex(java.lang.String)>";
    public static final String CURSOR_GETCOLUMNINDEXORTHROW = "<android.database.Cursor: int getColumnIndexOrThrow(java.lang.String)>";
    public static final String CONTENTRESOLVER_QUERY_4 = "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],android.os.Bundle,android.os.CancellationSignal)>";
    public static final String INTENT_GETPARCELABLEEXTRA = "<android.content.Intent: android.os.Parcelable getParcelableExtra(java.lang.String)>";
    public static final String INTENT_GETPARCELABLEEXTRA_1 = "<android.content.Intent: java.lang.Object getParcelableExtra(java.lang.String,java.lang.Class)>";
    public static final String INTENT_GETPARCELABLEARRAYLISTEXTRA = "<android.content.Intent: java.util.ArrayList getParcelableArrayListExtra(java.lang.String)>";
    public static final String INTENT_GETPARCELABLEARRAYLISTEXTRA_1 = "<android.content.Intent: java.util.ArrayList getParcelableArrayListExtra(java.lang.String,java.lang.Class)>";
    public static final String URI_GETQUERYPARAMETER = "<android.net.Uri: java.lang.String getQueryParameter(java.lang.String)>";

    public static final String[] keyValueAPI={CURSOR_GETCOLUMNINDEX,CURSOR_GETCOLUMNINDEXORTHROW,INTENT_GETPARCELABLEEXTRA,INTENT_GETPARCELABLEEXTRA_1,INTENT_GETPARCELABLEARRAYLISTEXTRA,INTENT_GETPARCELABLEARRAYLISTEXTRA_1,URI_GETQUERYPARAMETER};


    public static final String FILE_GETNAME = "<java.io.File: java.lang.String getName()>";
    public static final String FILE_EXISTS = "<java.io.File: boolean exists()>";
    public static final String FILE_DELETE = "<java.io.File: boolean delete()>";
    public static final String FILE_CREATENEWFILE = "<java.io.File: boolean createNewFile()>";
    public static final String FILE_MKDIR = "<java.io.File: boolean mkdir()>";
    public static final String FILE_MKDIRS = "<java.io.File: boolean mkdirs()>";
    public static final String FILE_LENGTH = "<java.io.File: long length()>";
    public static final String FILE_LASTMODIFIED = "<java.io.File: long lastModified()>";
    public static final String FILE_ISFILE = "<java.io.File: boolean isFile()>";
    public static final String FILE_ISDIRECTORY = "<java.io.File: boolean isDirectory()>";
    public static final String FILE_CANREAD = "<java.io.File: boolean canRead()>";
    public static final String FILE_CANWRITE = "<java.io.File: boolean canWrite()>";
    public static final String FILE_RENAMETO = "<java.io.File: boolean renameTo(java.io.File)>";
    public static final String FILE_LIST = "<java.io.File: java.lang.String[] list()>";
    public static final String FILE_LISTFILES = "<java.io.File: java.io.File[] listFiles()>";
    public static final String FILE_GETPARENT = "<java.io.File: java.lang.String getParent()>";
    public static final String FILE_GETABSOLUTEPATH = "<java.io.File: java.lang.String getAbsolutePath()>";
    public static final String FILE_GETCANONICALPATH = "<java.io.File: java.lang.String getCanonicalPath()>";

    public static final String[] fileAPI={FILE_GETNAME,FILE_EXISTS,FILE_DELETE,FILE_CREATENEWFILE,FILE_MKDIR,FILE_MKDIRS,FILE_LENGTH, FILE_LASTMODIFIED,FILE_ISFILE,FILE_ISDIRECTORY,
            FILE_CANREAD,FILE_CANWRITE,FILE_RENAMETO,FILE_LIST,FILE_LISTFILES,FILE_GETPARENT,FILE_GETABSOLUTEPATH,FILE_GETCANONICALPATH};

    public static final String CONTENTRESOLVER_QUERY_0 = "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri)>";
    public static final String CONTENTRESOLVER_QUERY_1 = "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[])>";
    public static final String CONTENTRESOLVER_QUERY_2 = "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>";
    public static final String CONTENTRESOLVER_QUERY_3 = "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String,android.os.CancellationSignal)>";
    public static final String[] contentQueryAPI={CONTENTRESOLVER_QUERY_0,CONTENTRESOLVER_QUERY_1,CONTENTRESOLVER_QUERY_2,CONTENTRESOLVER_QUERY_3,CONTENTRESOLVER_QUERY_4};

    public static final String CONTENTRESOLVER_OPENINPUTSTREAM_0 = "<android.content.ContentResolver: java.io.InputStream openInputStream(android.net.Uri)>";

    public static final String CONTENTRESOLVER_OPENINPUTSTREAM_1 = "<android.content.ContentResolver: java.io.InputStream openInputStream(android.net.Uri,java.io.FileDescriptor)>";

    public static final String CONTENTRESOLVER_OPENFILEDESCRIPTOR_0 = "<android.content.ContentResolver: android.os.ParcelFileDescriptor openFileDescriptor(android.net.Uri,java.lang.String)>";

    public static final String CONTENTRESOLVER_OPENFILEDESCRIPTOR_1 = "<android.content.ContentResolver: android.os.ParcelFileDescriptor openFileDescriptor(android.net.Uri,java.lang.String,android.os.CancellationSignal)>";

    public static final String CONTENTRESOLVER_OPENASSETFILEDESCRIPTOR_0 = "<android.content.ContentResolver: android.content.res.AssetFileDescriptor openAssetFileDescriptor(android.net.Uri,java.lang.String)>";

    public static final String CONTENTRESOLVER_OPENASSETFILEDESCRIPTOR_1 = "<android.content.ContentResolver: android.content.res.AssetFileDescriptor openAssetFileDescriptor(android.net.Uri,java.lang.String,android.os.CancellationSignal)>";

    public static final String[] contentOpenAPI={CONTENTRESOLVER_OPENINPUTSTREAM_0,
            CONTENTRESOLVER_OPENINPUTSTREAM_1,CONTENTRESOLVER_OPENFILEDESCRIPTOR_0,CONTENTRESOLVER_OPENFILEDESCRIPTOR_1,CONTENTRESOLVER_OPENASSETFILEDESCRIPTOR_0,CONTENTRESOLVER_OPENASSETFILEDESCRIPTOR_1};
    public static final List<String> validationAPIList=Arrays.asList(validationAPI);
    public static final List<String> contentQueryAPIList=Arrays.asList(contentQueryAPI);
    public static final List<String> contentOpenAPIList=Arrays.asList(contentOpenAPI);
    public static final List<String> fileAPIList=Arrays.asList(fileAPI);
    public static final List<String> keyValueAPIList=Arrays.asList(keyValueAPI);
    public static final List<String> uriHandleAPIList=Arrays.asList(uriHandleAPI);

    public static List<String> getValidationAPIList(){return validationAPIList;}
    public static List<String> getContentQueryAPIList(){return contentQueryAPIList;}
    public static List<String> getContentOpenAPIList(){return contentOpenAPIList;}
    public static List<String> getUriHandleAPIList(){return uriHandleAPIList;}

    public static List<String> getFileAPIList(){return fileAPIList;}
    public static List<String> getKeyValueAPIList(){return keyValueAPIList;}


}
