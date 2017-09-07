#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
안전한 부팅 관련 처리를 담당한다
"""
import re
import datetime
import os
import subprocess

BOOT_PROTECTOR_SERVICE_NAME = 'gbp-daemon'

#-----------------------------------------------------------------------
def get_status(vulnerable):
    if vulnerable == True:
        return '취약'

    return '안전'

#-----------------------------------------------------------------------
def get_run_status(logs):
    """
    로그와 시스템의 특정 정보를 이용해서 안전하게 부팅되었는지 여부를 반환한다.
    """
    # 서비스 구동 상태와 정상 설치 여부를 검사
    pipe = subprocess.Popen('/usr/sbin/service %s status' % BOOT_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    status_output, error =  pipe.communicate()
    status_output = status_output.decode('utf-8')

    pipe = subprocess.Popen('/usr/sbin/service %s check' % BOOT_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    check_output, error =  pipe.communicate()
    check_output = check_output.decode('utf-8')

    if not 'active (exited)' in status_output or \
       not '%s active.' % BOOT_PROTECTOR_SERVICE_NAME in check_output:
        return '중단'

    return '동작'

#-----------------------------------------------------------------------
def get_summary(logs):
    """
    안전한 부팅 상태와 관련 로그를 반환한다
    """

    # 안전한 부팅과 관련된 로그를 분석함
    vulnerable = False
    boot_logs = []
    p_errorcode = re.compile('errorcode=\S*')

    for data in logs:
        # syslog의 tag 정보와 실제 로그를 남긴 프로세스 정보를 같이 비교함
        if data['SYSLOG_IDENTIFIER'] != BOOT_PROTECTOR_SERVICE_NAME or \
           not '_COMM' in data or \
           data['_COMM'] != BOOT_PROTECTOR_SERVICE_NAME:
            continue

        local_vulnerable = 0
        search = p_errorcode.search(data['MESSAGE'])
        if search != None:
            error_string = search.group().replace('errorcode=', '')
            if error_string == '0':
                log = '%s 안전한 부팅 서비스가 정상적으로 실행되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            elif error_string == '1':
                log = '%s 안전한 부팅 서비스가 정상적으로 종료되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            else:
                log = '%s 안전한 부팅 기능이 비활성화되어 서비스가 실행되지 않았습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                vulnerable = True
                local_vulnerable = 1

            boot_logs.append({"type": local_vulnerable, "log":log})

    run = get_run_status(logs)
    status = get_status(vulnerable)

    return [run, status, boot_logs]
