#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OS 보호 관련 처리를 담당한다
"""
import re
import datetime
import os
import subprocess

OS_PROTECTOR_SERVICE_NAME = 'gop-daemon'

#-----------------------------------------------------------------------
def get_status(vulnerable):
    if vulnerable == True:
        return '취약'

    return '안전'

#-----------------------------------------------------------------------
def get_run_status(logs):
    """
    로그와 시스템의 특정 정보를 이용해서 OS 보호 기능이 정상적으로 구동되었는지 여부를 반환한다.
    '동작', '중단' 중 하나를 반환한다.
    """
    # 서비스 구동 상태와 정상 설치 여부를 검사
    pipe = subprocess.Popen('/usr/sbin/service %s status' % OS_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    status_output, error =  pipe.communicate()
    status_output = status_output.decode('utf-8')

    pipe = subprocess.Popen('/usr/sbin/service %s check' % OS_PROTECTOR_SERVICE_NAME, stdout=subprocess.PIPE, stderr=None, shell=True)
    check_output, error =  pipe.communicate()
    check_output = check_output.decode('utf-8')

	# 파일이 경로에 존재하지 않거나 서비스가 실행되지 않았으면 미설치를 반환한다.
    if not 'active (running)' in status_output or \
       not '%s active.' % OS_PROTECTOR_SERVICE_NAME in check_output:
        return '중단'

    return '동작'


"""
OS 보호 상태와 관련 로그를 반환한다.

Shadow-box에서 정의한 errorcode는 다음과 같다.
#define ERROR_SUCCESS                           0
#define ERROR_NOT_START                         1
#define ERROR_HW_NOT_SUPPORT                    2
#define ERROR_LAUNCH_FAIL                       3
#define ERROR_KERNEL_MODIFICATION               4
#define ERROR_KERNEL_VERSION_MISMATCH           5
#define ERROR_SHUTDOWN_TIME_OUT                 6
#define ERROR_MEMORY_ALLOC_FAIL                 7
#define ERROR_TASK_OVERFLOW                     8
#define ERROR_MODULE_OVERFLOW                   9
"""
errorcode_string = {'0': 'OS 보호 모듈이 정상적으로 실행되었습니다',
                    '1': 'OS 보호 모듈이 실행되지 않았습니다',
                    '2': 'OS 보호 모듈이 지원하지 않는 하드웨어입니다',
                    '3': 'OS 보호 모듈을 실행하는데 실패했습니다',
                    '4': '비인가된 커널 변조가 감지되었습니다',
                    '5': '지원되지 않는 커널 버전입니다',
                    '6': '시스템 종료 시간이 초과하였습니다',
                    '7': '메모리 할당에 실패했습니다',
                    '8': '프로세스의 개수가 최대치를 초과하였습니다',
                    '9': '커널 모듈의 개수가 최대치를 초과하였습니다'}


#-----------------------------------------------------------------------
def get_summary(logs):
    os_logs = []
    re_array=[{'key': 'guest linear=', 're_string': 'guest linear=\S*', 'compiled_re': None, 'log_string': '%s 비인가 커널 변조(메모리 주소:0x%s)가 탐지되었습니다.'},
              {'key': 'process name=', 're_string': 'process name=".*"', 'compiled_re': None, 'log_string': '%s 숨겨진 프로세스(%s)가 탐지되었습니다.'},
              {'key': 'module name=', 're_string': 'module name=".*"', 'compiled_re': None, 'log_string': '%s 숨겨진 커널 모듈(%s)이 탐지되었습니다.'},
              {'key': 'function pointer=', 're_string': 'function pointer=".*"', 'compiled_re': None, 'log_string': '%s 비인가 커널 변조(함수 포인터:%s)가 탐지되었습니다.'}]
    vulnerable = False
    p_errorcode = re.compile('errorcode=\S*')
    for re_data in re_array:
        re_data['compiled_re'] = re.compile(re_data['re_string'])

    for data in logs:
        local_vulnerable = 0
        # syslog의 tag 정보와 실제 로그를 남긴 프로세스 정보를 같이 비교함
        if data['SYSLOG_IDENTIFIER'] == OS_PROTECTOR_SERVICE_NAME and \
           '_COMM' in data and data['_COMM'] == OS_PROTECTOR_SERVICE_NAME:
            search = p_errorcode.search(data['MESSAGE'])
            if search == None:
                continue

            error_string = search.group().replace('errorcode=', '')
            if error_string == '0':
                log = '%s OS 보호 서비스가 정상적으로 실행되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            elif error_string == '1':
                log = '%s OS 보호 서비스가 정상적으로 종료되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            else:
                log = '%s OS 보호 기능이 비활성화되어 서비스가 실행되지 않았습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                vulnerable = True
                local_vulnerable = 1

            os_logs.append({"type": local_vulnerable, "log": log})

        # 드라이버에서 남긴 로그
        elif 'kernel' in data['_TRANSPORT'] and 'shadow-box:' in data['MESSAGE'][:11]:
            # 처리하지 않는 errorcode는 제외
            search = p_errorcode.search(data['MESSAGE'])
            if search != None:
                error_string = search.group().replace('errorcode=', '')

                # errorcode 중에서 아래 에러코드는 실제 다음 코드에서 처리됨
                if error_string != '4':
                    # 시간 변환 및 메시지 한글화
                    log = '%s %s' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'), errorcode_string[error_string])
                    if error_string != '0':
                        vulnerable = True
                        local_vulnerable = 1

                    os_logs.append({"type": local_vulnerable, "log": log})
                continue

            # 패턴이 일치하는 문자열 검색 및 로그 저장
            for re_data in re_array:
                search = re_data['compiled_re'].search(data['MESSAGE'])
                if search != None:
                    # = 이후의 부분만 추출하고 로그 메시지 생성
                    matched_data = search.group().replace(re_data['key'], '').replace('"', '')
                    log = re_data['log_string'] % (data['__REALTIME_TIMESTAMP'].strftime("%Y-%m-%d %H:%M:%S"), matched_data)
                    vulnerable = True
                    os_logs.append({"type": 1, "log": log})
                    break

    run = get_run_status(logs)
    status = get_status(vulnerable)
    return [run, status, os_logs]
