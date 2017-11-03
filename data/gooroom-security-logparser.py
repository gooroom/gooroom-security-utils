#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import importlib
import sys
import datetime

from systemd import journal

#-----------------------------------------------------------------------
SECURITY_FEATURES = ('os', 'exe', 'boot', 'media')
STATUS_KOR_TO_ENG = {'안전':'safe', '취약':'vulnerable', '동작': 'run', '중단':'stop'}

#-----------------------------------------------------------------------
def get_summary():
    """
    보안기능(os,exe,boot,media)의 journal로그를 파싱해서
    요약로그정보를 출력
    """

    logs = []
    func_name = None
    """
    SYSLOG_IDENTIFIER는 데몬의 로그를 수집하기 위함이며, PRIORITY와 _TRANSPORT는
    각각 OS 보호 기술 및 실행파일 보호 기술의 로그를 수집하기 위함이다.
    """
    match_strings = ['SYSLOG_IDENTIFIER=gbp-daemon', 'SYSLOG_IDENTIFIER=gep-daemon',
        'SYSLOG_IDENTIFIER=gop-daemon', 'SYSLOG_IDENTIFIER=grac-daemon',
        'SYSLOG_IDENTIFIER=gooroom-browser', 'PRIORITY=3',
		'PRIORITY=4', '_AUDIT_FIELD_OP="appraise_data"']

    j = journal.Reader()

    # 시간과 필터 설정
    if len(sys.argv) > 1:
        from_time = datetime.datetime.strptime(sys.argv[1], '%Y%m%d-%H%M%S.%f')
        j.seek_realtime(from_time)

    for match in match_strings:
        j.add_match(match)
        j.add_disjunction()

    # 엔트리를 추출해서 로그 배열에 별도 저장
    for entry in j:
        if type(entry['MESSAGE']) is bytes:
            entry['MESSAGE'] = \
                str(entry['MESSAGE'].decode('unicode_escape').encode('utf-8'))
        logs.append(entry)

    result = {}
    status_summary = "안전"

    sys.path.append('/usr/lib/x86_64-linux-gnu/gooroom-security-utils')

    for sf in SECURITY_FEATURES:
        m = importlib.import_module('security.'+sf)
        run, status, log = getattr(m, 'get_summary')(logs)

        result[sf+'_run'] = STATUS_KOR_TO_ENG[run]
        result[sf+'_status'] = STATUS_KOR_TO_ENG[status]
        result[sf+'_log'] = log

        if status == '취약':
            status_summary = '취약'

    result['status_summary'] = STATUS_KOR_TO_ENG[status_summary]
    return result

if __name__ == '__main__':

    print('JSON-ANCHOR=%s' % json.dumps(
                                get_summary(), 
                                ensure_ascii=False, 
                                sort_keys=True, 
                                indent=4, 
                                separators=(',', ': ')))

