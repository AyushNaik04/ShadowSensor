"""Sysmon event log collector: polls Microsoft-Windows-Sysmon/Operational via the Windows EVT API."""

from .sysmon import SysmonCollector

__all__ = ["SysmonCollector"]
