#! /usr/bin/env python3

#-----------------------------------------------------------------------
import sys
sys.path.append('/usr/lib/gooroom-security-utils')

import simplejson as json
import subprocess
import importlib
import datetime
import locale
import re

from gsl_util import combine_message,JournalLevel,status_lang_set
from gsl_util import get_run_status,format_exc,load_log_config
from gsl_util import load_translation,syslog_identifier_map
from gsl_util import config_diff_internal
from systemd import journal

#-----------------------------------------------------------------------
g_trans_parser = load_translation()

#-----------------------------------------------------------------------
#AGENT is using this function
#Do not move
def config_diff(file_contents):
    """
    return difference from previous config file
    by gooroom-agent
    """

    return config_diff_internal(file_contents)

#-----------------------------------------------------------------------
#GRAC is using this function
#Do not move
def get_notify_level(printname):
    """
    get notify-level in config
    """

    return JournalLevel[load_log_config('GRAC')[printname]['notify_level']].value

#-----------------------------------------------------------------------
g_gop_regex = re.compile('GRMCODE=\w+')

def identifier_processing(entry, mode, printname, notify_level, result):
    """
    SYSLOG_IDENTIFIER가 있는 로그를 처리
    """

    #GRMCODE
    if 'GRMCODE' in entry:
        grmcode = entry['GRMCODE']
    else:
        grmcode = ''

    #MESSAGE
    if 'MESSAGE' in entry:
        message = entry['MESSAGE']

        if type(message) is bytes:
            message = str(message.decode('unicode_escape').encode('utf-8'))

        #FOR GOP
        if not grmcode:
            res = re.search(g_gop_regex, message)
            if res:
                grmcode = res.group().split('=')[1]
    else:
        message = ''

    #TRANSLATION
    if grmcode:
        try:
            lang = locale.getdefaultlocale()
            if lang[0] == 'ko_KR':
                ko = g_trans_parser.get(grmcode, 'ko')    
                message = combine_message(message, ko)
        except:
            pass
    else:
        return 0

    #SAVE
    t = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S.%f')
    log = {
        'grmcode':grmcode,
        'level':JournalLevel(entry['PRIORITY']).name,
        'time':t,
        'log':'{} {}'.format(t, message),
        'type':status_lang_set(mode, 0),
        'eval_level':notify_level}

    result[printname+'_log'].append(log)

    if entry['PRIORITY'] <= JournalLevel[notify_level].value:
        result[printname+'_status'] = status_lang_set(mode, 'vulnerable')
        result['status_summary'] = status_lang_set(mode, 'vulnerable')
        log['type'] = status_lang_set(mode, 1)

    return len(log['log'])

#-----------------------------------------------------------------------
GRAC_NETWORK_NAME = 'GRAC: Disallowed Network'
P_SRC_IP = re.compile('SRC=\S*')
P_DST_IP = re.compile('DST=\S*')
P_SRC_PORT = re.compile('SPT=\S*')
P_DST_PORT = re.compile('DPT=\S*')

P_CAUSE = re.compile('cause=\S*')
P_FILE = re.compile('name=\S*')
P_COMM = re.compile('comm=\S*')

KOREAN_TEXT = {
    u'"invalid-hash"' : u'비정상 해시',
    u'"invalid-signature"' : u'비정상 서명',
    u'"missing-hash"' : u'서명 미존재',
    u'"no_label"' : '레이블 미존재',
    u'"IMA-signature-required"' : u'서명 미존재',
    'invalid-hash' : '비정상 해시',
    'invalid-signature' : '비정상 서명',
    'missing-hash' : '서명 미존재',
    'no_label' : '레이블 미존재',
    'IMA-signature-required' : '서명 미존재'}

def no_identifier_processing(entry, mode, result, log_json):
    """
    SYSLOG_IDENTIFIER가 없는 로그를 처리
    :gep,iptables
    """

    message = ''
    printname = ''
    internal_grmcode = ''

    # iptables
    if 'kernel' in entry['_TRANSPORT'] and GRAC_NETWORK_NAME in entry['MESSAGE']:
        '''
        search_src_ip = P_SRC_IP.search(entry['MESSAGE'])
        search_dst_ip = P_DST_IP.search(entry['MESSAGE'])
        search_src_port = P_SRC_PORT.search(entry['MESSAGE'])
        search_dst_port = P_DST_PORT.search(entry['MESSAGE'])

        if (search_src_ip == None or search_src_port == None or
            search_dst_ip == None or search_dst_port == None):
            return 0

        src_ip_string = search_src_ip.group().replace('SRC=', '')
        src_port_string = search_src_port.group().replace('SPT=', '')
        dst_ip_string = search_dst_ip.group().replace('DST=', '')
        dst_port_string = search_dst_port.group().replace('DPT=', '')

        t = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S.%f')
        message = \
            '비인가 네트워크 패킷(출발지 {}:{}, 목적지 {}:{})이'\
            '탐지되어 차단하였습니다'.format(
                                        src_ip_string, 
                                        src_port_string, 
                                        dst_ip_string, 
                                        dst_port_string)
        printname = 'media'
        internal_grmcode = '001001'
        '''
        pass

	# 커널의 IMA에서 남긴 로그
    elif 'kernel' in entry['_TRANSPORT']:
        search_cause = P_CAUSE.search(entry['MESSAGE'])
        search_file = P_FILE.search(entry['MESSAGE'])
        search_comm = P_COMM.search(entry['MESSAGE'])

        if search_cause != None and search_file != None:

            #TEMP NEEDS
            if search_comm and search_comm.group() and 'gnome-control-c' in search_comm.group():
                return 0
            if search_comm and search_comm.group() and 'alsa-source-ALC' in search_comm.group():
                return 0

            cause_string = search_cause.group().replace('cause=', '')
            if '"' in search_file.group():
                file_string = \
                    search_file.group().replace('name=', '').replace('"', '')
            else:
                file_string = \
                    search_comm.group().replace('comm=', '').replace('"', '')

            # no_label의 경우, name 필드에 해시 값이 들어있으므로
            #사람이 인지할 수 있는 파일명으로 변환
            if cause_string == '"no_label"':
                file_string = entry['_AUDIT_FIELD_NAME'].replace('"', '')

            # 시간 변환 및 메시지 한글화
            if cause_string in KOREAN_TEXT:
                cause_string = KOREAN_TEXT[cause_string]

            # 로그 추가
            message = '비인가된 실행파일({}, {})이'\
                '실행되어 차단하였습니다'.format(cause_string, file_string)
            printname = 'exe'
            internal_grmcode = '001002'

    if message:
        notify_level = log_json[printname]['notify_level']
        t = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S.%f')
        log = {
            'grmcode':internal_grmcode,
            'level':JournalLevel(entry['PRIORITY']).name,
            'time':t,
            'log':'{} {}'.format(t, message),
            'type':status_lang_set(mode, 0),
            'eval_level':notify_level}

        result[printname+'_log'].append(log)

        if entry['PRIORITY'] <= JournalLevel[notify_level].value:
            result[printname+'_status'] = status_lang_set(mode, 'vulnerable')
            result['status_summary'] = status_lang_set(mode, 'vulnerable')
            log['type'] = status_lang_set(mode, 1)

        return len(log['log'])
    else:
        return 0

#-----------------------------------------------------------------------
def get_summary(j, mode='DAEMON'):
    """
    보안기능(os,exe,boot,media)의 journal로그를 파싱해서
    요약로그정보를 출력
    """

    verify_journal_disk_usage()

    log_json = load_log_config(mode)
    identifier_map = syslog_identifier_map(log_json)

    #identifier and priority
    for identifier, printname in identifier_map.items():

        if mode == 'DAEMON':
            transmit_p = \
                JournalLevel[log_json[printname]['transmit_level']].value
            notify_p = \
                JournalLevel[log_json[printname]['notify_level']].value
            if transmit_p < notify_p:
                level_key = 'notify_level'
            else:
                level_key = 'transmit_level'
        else:
            show_p = \
                JournalLevel[log_json[printname]['show_level']].value
            notify_p = \
                JournalLevel[log_json[printname]['notify_level']].value
            if show_p < notify_p:
                level_key = 'notify_level'
            else:
                level_key = 'show_level'

        ############################################
        if log_json[printname][level_key] == 'none':
            continue
        ############################################

        match_identifier = 'SYSLOG_IDENTIFIER='+identifier
        j.add_match(match_identifier)

        value = JournalLevel[log_json[printname][level_key]].value
        for i in range(value+1):
            match_priority = \
                'PRIORITY={}'.format(i)
            j.add_match(match_priority)
        j.add_disjunction()

    #IMA(gep)
    j.add_match('SYSLOG_IDENTIFIER=kernel')
    j.add_match('PRIORITY=5')
    j.add_disjunction()

    #OS 보호 및 방화벽 로그를 추려내기위한 특수한 필터
    j.add_match('SYSLOG_IDENTIFIER=kernel')
    j.add_match('PRIORITY=3')

    #초기화 및 실행상태, 로그등급
    result = {}
    for identifier, printname in identifier_map.items():
        if 'service_name' in log_json[printname]:
            service_name = log_json[printname]['service_name']
        else:
            service_name = ''
        run = get_run_status(service_name)

        result[printname+'_run'] = status_lang_set(mode, run)
        result[printname+'_status'] = status_lang_set(mode, 'safe')
        result[printname+'_notify_level'] = log_json[printname]['notify_level']
        result[printname+'_show_level'] = log_json[printname]['show_level']
        result[printname+'_log'] = []
    result['status_summary'] = status_lang_set(mode, 'safe')

    log_total_len = 0

    last_entry = None
    now_for_nolog = datetime.datetime.now()
    for entry in j:
        if entry['__REALTIME_TIMESTAMP'].timestamp() > datetime.datetime.now().timestamp():
            continue

        if '_KERNEL_SUBSYSTEM' in entry.keys():
            continue

        try:
            #gbp,gop,grac,browser와 같이 SYSLOG_IDENTIFIER를 사용하는 경우와
            #gep,iptables와 같이 별도로 처리해야 되는 경우를 구분
            if 'SYSLOG_IDENTIFIER' in entry \
                and entry['SYSLOG_IDENTIFIER'] in identifier_map.keys():

                printname = identifier_map[entry['SYSLOG_IDENTIFIER']]
                notify_level = log_json[printname]['notify_level']
                log_total_len += \
                    identifier_processing(entry, 
                                        mode, 
                                        printname, 
                                        notify_level, 
                                        result)

            #SYSLOG_IDENTIFIER는 map에 없지만 GROMCODE를 가지고 있는
            #gop의 shadow-box 로그를 처리함
            elif 'kernel' in entry['_TRANSPORT'] \
                and 'shadow-box:' in entry['MESSAGE'][:11]:

                printname = identifier_map['gop-daemon']
                notify_level = log_json[printname]['notify_level']
                log_total_len += \
                    identifier_processing(entry, 
                                        mode, 
                                        printname, 
                                        notify_level, 
                                        result)
            else:
                log_total_len += \
                    no_identifier_processing(entry, mode, result, log_json)

            #LAST ENTRY
            last_entry = entry
        except:
            print(format_exc())

    result['log_total_len'] = log_total_len

    if last_entry:
        next_seek_time = last_entry['__REALTIME_TIMESTAMP'].timestamp()+0.000001
        next_seek_time = datetime.datetime.fromtimestamp(next_seek_time)
    else:
        next_seek_time = now_for_nolog
        
    with open('/var/tmp/GOOROOM-SECURITY-LOGPARSER-NEXT-SEEKTIME', 'w') as f:
        f.write(next_seek_time.strftime('%Y%m%d-%H%M%S.%f'))

    return result

#-----------------------------------------------------------------------
def get_current_journal_disk_usage():
    """
    return current journal disk usage
    """

    pp = subprocess.Popen(
        ['/bin/journalctl', '--disk-usage'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    pp_out, pp_err = pp.communicate()
    disk_usage = pp_out.decode('utf8').split()[6]
    disk_unit = disk_usage[-1]
    if disk_unit != 'G':
        return 0
    return float(disk_usage[:-1])

#-----------------------------------------------------------------------
def verify_journal_disk_usage():
    """
    if verifying is failed, raise exception
    """

    disk_usage = get_current_journal_disk_usage() 
    if disk_usage > 30.0:
        raise Exception('JOURNAL DISK USAGE({}G) '\
            'IS TOO LARGE'.format(disk_usage))

#-----------------------------------------------------------------------
if __name__ == '__main__':

    j = journal.Reader()

    # 시간과 필터 설정
    if len(sys.argv) > 1:
        try:
            from_time = datetime.datetime.strptime(sys.argv[1], '%Y%m%d-%H%M%S.%f')
            j.seek_realtime(from_time)
        except ValueError:
            print(f'Invalid seek time value. {sys.argv[1]}')
            print('seek time format: %Y%m%d-%H%M%S.%f')

    print('JSON-ANCHOR=%s' % json.dumps(
                                get_summary(j, mode='GUI'), 
                                ensure_ascii=False, 
                                sort_keys=True, 
                                indent=4, 
                                separators=(',', ': ')))


