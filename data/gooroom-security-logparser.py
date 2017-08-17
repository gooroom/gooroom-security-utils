#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import importlib
import sys
import datetime

from systemd import journal

#-----------------------------------------------------------------------
SECURITY_FEATURES = ('os', 'exe', 'boot', 'media')

#-----------------------------------------------------------------------
def get_summary():
    """
    보안기능(os,exe,boot,media)의 journal로그를 파싱해서
    요약로그정보를 출력
    """
    normal_mode = True

    if len(sys.argv) > 1 and sys.argv[1].lower() == 'emul':
        normal_mode = False

    logs = []
    func_name = None
    """
    SYSLOG_IDENTIFIER는 데몬의 로그를 수집하기 위함이며, PRIORITY와 _TRANSPORT는
    각각 OS 보호 기술 및 실행파일 보호 기술의 로그를 수집하기 위함이다.
    """
    match_strings = ['SYSLOG_IDENTIFIER=gbp-daemon', 'SYSLOG_IDENTIFIER=gep-daemon',
        'SYSLOG_IDENTIFIER=gop-daemon', 'SYSLOG_IDENTIFIER=grac-daemon',
        'PRIORITY=3', '_TRANSPORT=audit']

    if normal_mode:
        j = journal.Reader()

        # 시간과 필터 설정
        #from_date_time = datetime.datetime.strptime("2017-08-11", "%Y-%m-%d")
		#j.seek_realtime(from_date_time)
        for match in match_strings:
            j.add_match(match)
            j.add_disjunction()

        # 엔트리를 추출해서 로그 배열에 별도 저장
        for entry in j:
            if type(entry['MESSAGE']) is bytes:
                entry['MESSAGE'] = str(entry['MESSAGE'].decode('unicode_escape').encode('utf-8'))
            logs.append(entry)

        func_name = 'get_summary'
    else:
        func_name = 'get_summary_emul'

    result = {}
    status_summary = "안전"

    sys.path.append('/usr/lib/x86_64-linux-gnu/gooroom-security-utils')

    for sf in SECURITY_FEATURES:
        m = importlib.import_module('security.'+sf)
        status, log = getattr(m, func_name)(logs)

        result[sf+'_status'] = status
        result[sf+'_log'] = log

        if status == '취약':
            status_summary = status

    result['status_summary'] = status_summary
    return result

if __name__ == '__main__':

	print(json.dumps(get_summary(), ensure_ascii=False, sort_keys=True, indent=4, separators=(',', ': ')))

