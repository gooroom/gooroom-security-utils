#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""
매체제어 관련 처리를 담당한다
"""
import re
import datetime

def get_status(logs, vulnerable):
    """
    로그와 시스템의 특정 정보를 이용해서 매체제어 서비스가 정상적으로 구동되었는지 여부를 반환한다.
    '안전', '취약', '중단' 중 하나를 반환한다
    """
    # TODO: 여기 실제 코드로 바꿔넣기
    if (vulnerable == True):
        return '취약'

    return '안전'


def get_summary(logs):
    """
    매체제어 상태와 관련 로그를 반환한다
    """

    # TODO: 여기 실제 코드로 바꿔넣기
    media_logs = []
    media_status = get_status(logs, False)

    return [media_status, media_logs]

#-----------------------------------------------------------------------
def get_summary_emul(logs):
    """
    emulate get_summary
    """

    vulnerable = False
    return [get_status(logs, vulnerable), []]
