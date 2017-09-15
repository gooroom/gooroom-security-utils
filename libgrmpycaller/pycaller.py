#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import traceback
import OpenSSL
import reprlib
import base64

#-----------------------------------------------------------------------
def do_task(taskin):
    """
    do task
    """

    taskout = {'result':'SUCCESS', 'message':''}

    try:
        taskin = json.loads(taskin)
        eval('task_%s(taskin,taskout)' % taskin['task_name'])

    except:
        taskout['result'] = 'ERROR'
        e = '\n'.join(traceback.format_exc().split('\n')[-4:-1])
        taskout['message'] = e

    return json.dumps(taskout)

#-----------------------------------------------------------------------
def task_verify_signature(taskin, taskout):
    '''
    verify file signature
    '''

    file_name = taskin['file_name']
    splited = file_name.split('/')
    short_file_name = splited[-1]
    signature_name = '/var/tmp/gooroom-agent-service/%s/%s+signature' \
        % ('.'.join(splited), short_file_name)

    with open(file_name) as f0:
        data = f0.read()
    with open(signature_name) as f1:
        signature = f1.read()

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, 
        open('/etc/gooroom/agent/server_certificate.crt').read())

    OpenSSL.crypto.verify(cert, 
        base64.b64decode(signature.encode('utf8')), 
        data.encode('utf8'), 'sha256')
