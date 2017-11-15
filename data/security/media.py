#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
매체제어 관련 처리를 담당한다
"""
import re
import datetime
import subprocess
import shlex

BROWSER_SERVICE_NAME = 'gooroom-browser'
GRAC_SERVICE_NAME = 'grac-device-daemon'
GRAC_NETWORK_NAME = 'GRAC: Disallowed Network'
GRAC_NAME = 'GRAC'
GRAC_COMM = ['grac-apply.sh', 'grac-status.sh']

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
    cmd = '/usr/sbin/service %s status' % GRAC_SERVICE_NAME
    argv = shlex.split(cmd)
    pipe = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=None, shell=False)
    status_output, error =  pipe.communicate()
    status_output = status_output.decode('utf-8')

    # 파일이 경로에 존재하지 않거나 서비스가 실행되지 않았으면 미설치를 반환한다.
    if not 'active (running)' in status_output:
        #or not '%s active.' % GRAC_SERVICE_NAME in check_output:
        return '중단'

    return '동작'

#-----------------------------------------------------------------------
def get_browser_summary(logs):
    """
    브라우저 관련 로그를 반환한다
    """

    # 브라우저와 관련된 로그를 분석함
    vulnerable = False
    browser_logs = []
    run = '중단'

    p_policy_type = re.compile('type=\S*')
    p_policy_path = re.compile('policy_path=\S*')
    p_policy_path_trust_prefix = re.compile('/usr/share/gooroom/browser/policies/trust\S*')
    p_policy_path_untrust_prefix = re.compile('/usr/share/gooroom/browser/policies/untrust\S*')
    p_policy_check = re.compile('policy_check=\S*')

    for data in logs:
        # syslog의 tag 정보와 실제 로그를 남긴 프로세스 정보를 같이 비교함
        if 'SYSLOG_IDENTIFIER' in data.keys() and \
            data['SYSLOG_IDENTIFIER'] != BROWSER_SERVICE_NAME and \
            '_COMM' in data and \
            data['_COMM'] != BROWSER_SERVICE_NAME:
            continue

        local_vulnerable = 0
        log_type = 0
        val_type = ''
        val_path = ''
        log = ''

        # log_type = [trust|untrust|undefined]
        if data['MESSAGE'] != None:
            if data['MESSAGE'].startswith('type'):
                log_type = 1
            elif data['MESSAGE'].startswith('SIGN'):
                log_type = 2
            elif data['MESSAGE'].startswith('GOOROOM'):
                log_type = 3
                continue # DO NOT USE THIS LOG
            else:
                log_type = 0 # DO NOT REACH

        if log_type == 1:
            # val_type = [trust|untrust|undefined]
            search_type = p_policy_type.search(data['MESSAGE'])
            val_type = search_type.group().replace('type=', '')
            if val_type != 'trust' and val_type != 'untrust' :
                val_type = 'undefined' # DO NOT REACH

            # val_policy_type = [trust|untrust|none|undefined]
            search_path = p_policy_path.search(data['MESSAGE'])
            val_path = search_path.group().replace('policy_path=', '')
            if p_policy_path_trust_prefix.search(val_path):
                val_policy_type = 'trust'
            elif p_policy_path_untrust_prefix.search(val_path):
                val_policy_type = 'untrust'
            elif val_path == 'none': # Must be notified to hancom
                val_policy_type = 'none'
            else:
                val_policy_type = 'undefined' # DO NOT REACH

            if  val_type != val_policy_type and val_policy_type != 'none':
                local_vulnerable = 1
                vulnerable = True
                log = '%s 잘못된 정책 적용 또는 잘못된 브라우저 타입' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            else:
                log = '%s 올바른 정책 적용 및 올바른 브라우저 실행' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))

            browser_logs.append({"type" : local_vulnerable, "log": log})

        elif log_type == 2:
            if data['MESSAGE'] != "SIGN verified oK":
                local_vulnerable = 1
                vulnerable = True
                log = '%s 서명 검증 실패 또는 에러' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
            else:
                log = '%s 서명 검증 성공' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))

            browser_logs.append({"type" : local_vulnerable, "log": log})

        elif log_type == 3:
            continue # DO NOT USE THIS LOG

        else:
            continue # DO NOT REACH

    return [vulnerable, browser_logs]

#-----------------------------------------------------------------------
def get_grac_summary(logs):
    """
    매체제어 및 방화벽 관련 로그를 반환한다
    """
    grac_logs = []
    vulnerable = False

    p_errorcode = re.compile('errorcode=\S*')
    p_cause = re.compile('cause=\S*')
    p_kind = re.compile('kind=\S*')
    p_src_ip = re.compile('SRC=\S*')
    p_dst_ip = re.compile('DST=\S*')
    p_src_port = re.compile('SPT=\S*')
    p_dst_port = re.compile('DPT=\S*')

    for data in logs:
        local_vulnerable = 0
        # 매체제어 로그
        # syslog의 tag 정보와 실제 로그를 남긴 프로세스 정보를 같이 비교함
        if 'SYSLOG_IDENTIFIER' in data.keys() and \
            data['SYSLOG_IDENTIFIER'] == GRAC_NAME and \
           '_COMM' in data and data['_COMM'] in GRAC_COMM:

            # 서비스 시작과 종료에 관련된 정보
            search = p_errorcode.search(data['MESSAGE'])
            if search != None:
                error_string = search.group().replace('errorcode=', '')
                if error_string == '0':
                    log = '%s 매체 제어 서비스가 정상적으로 실행되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                elif error_string == '1':
                    log = '%s 매체 제어 서비스가 정상적으로 종료되었습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                else:
                    log = '%s 매체 제어 기능이 비활성화되어 서비스가 실행되지 않았습니다' % (data['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S'))
                    vulnerable = True
                    local_vulnerable = 1

                grac_logs.append({"type": local_vulnerable, "log": log})
                continue

            # 매체 제어 통제와 관련된 정보
            search_cause = p_cause.search(data['MESSAGE'])
            search_kind = p_kind.search(data['MESSAGE'])
            if search_cause == None or search_kind == None:
                continue

            cause_string = search_cause.group().replace('cause=', '')
            kind_string = search_kind.group().replace('kind=', '')
            if cause_string == '"disallow"':
                log = "%s 비인가된 매체(%s)가 탐지되어 차단하였습니다." % (data['__REALTIME_TIMESTAMP'].strftime("%Y-%m-%d %H:%M:%S"), kind_string)
            elif cause_string == '"read_only"':
                log = "%s 읽기 전용 매체(%s)에 쓰기가 탐지되어 차단하였습니다." % (data['__REALTIME_TIMESTAMP'].strftime("%Y-%m-%d %H:%M:%S"), kind_string)
            vulnerable = True
            local_vulnerable = 1
            grac_logs.append({"type": local_vulnerable, "log": log})

        # iptable 로그
        elif 'kernel' in data['_TRANSPORT'] and GRAC_NETWORK_NAME in data['MESSAGE']:
            search_src_ip = p_src_ip.search(data['MESSAGE'])
            search_dst_ip = p_dst_ip.search(data['MESSAGE'])
            search_src_port = p_src_port.search(data['MESSAGE'])
            search_dst_port = p_dst_port.search(data['MESSAGE'])

            if (search_src_ip == None or search_src_port == None or
                search_dst_ip == None or search_dst_port == None):
                continue

            src_ip_string = search_src_ip.group().replace('SRC=', '')
            src_port_string = search_src_port.group().replace('SPT=', '')
            dst_ip_string = search_dst_ip.group().replace('DST=', '')
            dst_port_string = search_dst_port.group().replace('DPT=', '')

            log = "%s 비인가 네트워크 패킷(출발지 %s:%s, 목적지 %s:%s)이 탐지되어 차단하였습니다." % (data['__REALTIME_TIMESTAMP'].strftime("%Y-%m-%d %H:%M:%S"), src_ip_string, src_port_string, dst_ip_string, dst_port_string)
            vulnerable = True
            local_vulnerable = 1
            grac_logs.append({"type": local_vulnerable, "log": log})

    return [vulnerable, grac_logs]

#-----------------------------------------------------------------------
def get_summary(logs):
    """
    매체제어 상태와 관련 로그를 반환한다
    """

    [grac_vulnerable, grac_logs] = get_grac_summary(logs)
    [browser_vulnerable, browser_logs] = get_browser_summary(logs)

    run = get_run_status(logs)
    status = get_status(grac_vulnerable or browser_vulnerable)
    grac_logs = grac_logs + browser_logs

    sorted_logs = sorted(grac_logs, key=lambda k: k['log'])

    return [run, status, sorted_logs]
