# -*- coding:utf-8 -*-
import frida

open_file_flag=False
dynamic_record={}

def dynamic_record_init():
    global open_file_flag
    open_file_flag=False
    global dynamic_record
    dynamic_record={
        "query_keys":[],
        "open_pocs":[],
        "call_getType":False,
        "file_paths":[]
    }

def get_open_file_flag():
    global open_file_flag
    return open_file_flag

def get_dynamic_record():
    global dynamic_record
    return dynamic_record

def on_message(message, data):
    global open_file_flag
    global dynamic_record
    print(message)

    if message['type'] == 'send':
        if 'payload' in message:
            payload = message['payload']
            method = payload['method']
            poc_uri = payload['uri']

            if method=="query":
                projection=payload['projection']
                if projection and projection not in dynamic_record['query_keys']:
                    dynamic_record['query_keys'].append(projection)

            elif method=="openFile":
                if not open_file_flag:
                    open_file_flag=True
                if poc_uri not in dynamic_record['open_pocs']:
                    dynamic_record['open_pocs'].append(poc_uri)

            elif method=="getType":
                if not dynamic_record['call_getType']:
                    dynamic_record['call_getType']=True

def frida_init():
    device = frida.get_usb_device()
    process=device.attach("PocAgent")
    f=open('Frida_js/sendIntent.js','r',encoding='utf-8')
    jscode=f.read()
    script=process.create_script(jscode)
    script.on('message',on_message)
    script.load()
    return script



