#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
매체제어 관련 처리를 담당한다
"""
import re
import datetime
import subprocess

GRAC_SERVICE_NAME = 'grac-device-daemon'

#-----------------------------------------------------------------------
def get_status(vulnerable):
    if vulnerable == True:
        return '취약'

    return '안전'

#-----------------------------------------------------------------------
def get_run_status(logs):
    """
    로그와 시스템의 특정 정보를 이용해서 매체제어 기능이 정상적으로 구동되었는지 여부를 반환한다.
    '동작', '중단' 중 하나를 반환한다.
    """
    # 서비스 구동 상태와 정상 설치 여부를 검사
    pipe = subprocess.Popen('/usr/sbin/service %s status' % GRAC_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    status_output, error =  pipe.communicate()
    status_output = status_output.decode('utf-8')

    '''
    pipe = subprocess.Popen('/usr/sbin/service %s check' % GRAC_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    check_output, error =  pipe.communicate()
    check_output = check_output.decode('utf-8')
    '''

	# 파일이 경로에 존재하지 않거나 서비스가 실행되지 않았으면 미설치를 반환한다.
    if not 'active (running)' in status_output:
        #or not '%s active.' % GRAC_SERVICE_NAME in check_output:
        return '중단'

    return '동작'

#-----------------------------------------------------------------------

def get_summary(logs):
    """
    매체제어 상태와 관련 로그를 반환한다
    """

    # TODO: 여기 실제 코드로 바꿔넣기
    media_logs = []
    run = get_run_status(logs)
    status = get_status(False)

    return [run, status, media_logs]
