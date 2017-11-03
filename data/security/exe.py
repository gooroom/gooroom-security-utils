#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
안전한 부팅 관련 처리를 담당한다
"""
import re
import datetime
import subprocess

EXE_PROTECTOR_SERVICE_NAME = 'gep-daemon'

#-----------------------------------------------------------------------
def get_status(vulnerable):
    if vulnerable == True:
        return '취약'

    return '안전'


#-----------------------------------------------------------------------
def get_run_status(logs):
    """
    로그와 시스템의 특정 정보를 이용해서 실행파일 검증 기능이 정상적으로 동작하는지 반환한다.
    """
    # 서비스 구동 상태와 정상 설치 여부를 검사
    pipe = subprocess.Popen('/usr/sbin/service %s status' % EXE_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    status_output, error =  pipe.communicate()
    status_output = status_output.decode('utf-8')

    pipe = subprocess.Popen('/usr/sbin/service %s check' % EXE_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    check_output, error =  pipe.communicate()
    check_output = check_output.decode('utf-8')
    if not 'active (exited)' in status_output or \
       not '%s active.' % EXE_PROTECTOR_SERVICE_NAME in check_output:
        return '중단'

    return '동작'


#-----------------------------------------------------------------------
def get_summary(logs):
    """
    실행파일 검증 상태와 관련 로그를 반환한다
    """
    korean_text = {u'"invalid-hash"' : u'비정상 해시', u'"invalid-signature"' : u'비정상 시그니처', u'"missing-hash"' : u'해시 미존재', u'"no_label"' : '레이블 미존재'}
    vulnerable = False
    exec_logs = []

    p_cause = re.compile('cause=\S*')
    p_file = re.compile('name=\S*')
    p_errorcode = re.compile('errorcode=\S*')

    for data in logs:
        local_vulnerable = 0
        # syslog의 tag 정보와 실제 로그를 남긴 프로세스 정보를 같이 비교함
        if 'SYSLOG_IDENTIFIER' in data.keys() and \
           data['SYSLOG_IDENTIFIER'] == EXE_PROTECTOR_SERVICE_NAME and \
           '_COMM' in data and data['_COMM'] == EXE_PROTECTOR_SERVICE_NAME:
            search = p_errorcode.search(data['MESSAGE'])
            if search == None:
                continue

            error_string = search.group().replace('errorcode=', '')
            if error_string == '0':
                log = '%s 실행 파일 보호 서비스가 정상적으로 실행되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            elif error_string == '1':
                log = '%s 실행 파일 보호 서비스가 정상적으로 종료되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            else:
                log = '%s 실행 파일 보호 기능이 비활성화되어 서비스가 실행되지 않았습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                vulnerable = True
                local_vulnerable = 1

            exec_logs.append({"type": local_vulnerable, "log": log})

	# 커널의 IMA에서 남긴 로그
        elif 'audit' in data['_TRANSPORT']:
            search_cause = p_cause.search(data['MESSAGE'])
            search_file = p_file.search(data['MESSAGE'])
            if search_cause != None and search_file != None:
                cause_string = search_cause.group().replace('cause=', '')
                file_string = search_file.group().replace('name=', '').replace('"', '')

                # 시간 변환 및 메시지 한글화
                cause_string = korean_text[cause_string]

                # no_label의 경우, name 필드에 해시 값이 들어있으므로, 사람이 인지할 수 있는 파일명으로 변환
                if cause_string == '"no_label"':
                    file_string = data['_AUDIT_FIELD_NAME'].replace('"', '')

                # 로그 추가
                log = "%s 비인가된 실행파일(%s, %s)이 실행되어 차단하였습니다." % (data['__REALTIME_TIMESTAMP'].strftime("%Y-%m-%d %H:%M:%S"), cause_string, file_string)
                exec_logs.append({"type": 1, "log": log})
                vulnerable = True

    run = get_run_status(logs)
    status = get_status(vulnerable)

    return [run, status, exec_logs]
