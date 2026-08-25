from datetime import datetime, timedelta

from backend.evidence.security.additional_sources import (
    CLASSIC_FALCO_LINE,
    _falco_event_age_seconds,
    _is_live_falco_line,
    _parse_falco_line,
)


def _line_for(dt: datetime) -> str:
    return dt.strftime('%H:%M:%S.%f') + ': Warning Sensitive file opened for reading | file=/etc/shadow k8s_ns=security-demo process=cat'


def test_classic_falco_warning_line_is_parsed():
    line = '13:14:27.811647863: Warning Sensitive file opened for reading (file=/etc/shadow k8s_ns=security-demo k8s_pod_name=privileged-demo)'
    match = CLASSIC_FALCO_LINE.match(line)
    assert match
    assert match.group('priority').upper() == 'WARNING'
    assert '/etc/shadow' in match.group('output')


def test_falco_json_output_with_embedded_warning_is_parsed():
    line = '{"hostname":"nirmesh","output":"06:37:43.346545985: Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=systemd evt_type=open user=root process=cat container_name=app"}'
    rule, output, priority, resource, classic = _parse_falco_line(line, 'falco', 'falco-abc')
    assert priority == 'WARNING'
    assert rule.startswith('Sensitive file opened for reading by non-trusted program')
    assert '/etc/shadow' in output
    assert resource == 'Pod/falco/falco-abc'
    assert classic


def test_old_falco_event_is_not_live():
    old = datetime.now().astimezone() - timedelta(minutes=10)
    line = _line_for(old)
    assert _falco_event_age_seconds(line) >= 9 * 60
    assert not _is_live_falco_line(line)


def test_recent_falco_event_is_live():
    recent = datetime.now().astimezone() - timedelta(seconds=10)
    line = _line_for(recent)
    assert _is_live_falco_line(line)


def test_untimestamped_falco_event_is_not_live():
    assert not _is_live_falco_line('Warning Sensitive file opened for reading | file=/etc/shadow')
