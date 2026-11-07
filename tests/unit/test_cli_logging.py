"""`cti -v` must not turn on DEBUG for loggers that print request details or keys."""

import logging

from cti import cli


def test_verbose_keeps_key_bearing_loggers_quiet(monkeypatch):
    monkeypatch.setattr(cli, "cmd_status", lambda args, settings: 0)
    root = logging.getLogger()
    before = root.level, [logging.getLogger(n).level for n in cli.NOISY_LOGGERS]
    try:
        assert cli.main(["-v", "status", "--date", "2026-10-26"]) == 0
        # the level set on each logger itself: under pytest the root logger already has
        # handlers, so basicConfig is a no-op and an effective level would pass anyway
        for name in ("httpx", "httpcore", "botocore", "boto3", "s3transfer", "urllib3"):
            assert logging.getLogger(name).level == logging.WARNING
    finally:
        root.setLevel(before[0])
        for name, level in zip(cli.NOISY_LOGGERS, before[1], strict=True):
            logging.getLogger(name).setLevel(level)
