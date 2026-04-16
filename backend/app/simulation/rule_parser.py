"""
Simplified Suricata rule parser.
Parses the key fields needed for educational simulation matching.
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedRule:
    action: str = "alert"
    protocol: str = "tcp"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"

    # Options
    msg: str = ""
    sid: str = ""
    rev: str = "1"
    classtype: str = ""
    flow: str = ""
    flags: str = ""
    content: list[str] = field(default_factory=list)
    nocase_content: list[str] = field(default_factory=list)
    http_uri: bool = False
    http_method: bool = False
    http_header: bool = False
    dsize_gt: Optional[int] = None
    threshold_count: Optional[int] = None
    threshold_seconds: Optional[int] = None
    itype: Optional[int] = None   # ICMP type

    raw: str = ""


def parse_rule(rule_text: str) -> Optional[ParsedRule]:
    """Parse a Suricata rule string into a ParsedRule object."""
    rule_text = rule_text.strip()
    if not rule_text or rule_text.startswith("#"):
        return None

    # Split header from options
    m = re.match(
        r'^(alert|drop|pass|reject)\s+'
        r'(\w+)\s+'              # protocol
        r'(\S+)\s+'              # src_ip
        r'(\S+)\s+'              # src_port
        r'(<>|->|<-)\s+'         # direction
        r'(\S+)\s+'              # dst_ip
        r'(\S+)\s+'              # dst_port
        r'\((.+)\)\s*$',         # options (inside parens)
        rule_text,
        re.DOTALL,
    )
    if not m:
        return None

    r = ParsedRule(raw=rule_text)
    r.action    = m.group(1)
    r.protocol  = m.group(2).lower()
    r.src_ip    = m.group(3)
    r.src_port  = m.group(4)
    r.direction = m.group(5)
    r.dst_ip    = m.group(6)
    r.dst_port  = m.group(7)
    options_str = m.group(8)

    _parse_options(r, options_str)
    return r


def _parse_options(r: ParsedRule, options_str: str) -> None:
    """Extract key options from the options block."""
    # msg
    mm = re.search(r'msg\s*:\s*"([^"]*)"', options_str)
    if mm:
        r.msg = mm.group(1)

    # sid
    mm = re.search(r'\bsid\s*:\s*(\d+)', options_str)
    if mm:
        r.sid = mm.group(1)

    # classtype
    mm = re.search(r'classtype\s*:\s*([\w-]+)', options_str)
    if mm:
        r.classtype = mm.group(1)

    # flow
    mm = re.search(r'flow\s*:\s*([^;]+)', options_str)
    if mm:
        r.flow = mm.group(1).strip()

    # flags
    mm = re.search(r'flags\s*:\s*([^;]+)', options_str)
    if mm:
        r.flags = mm.group(1).strip()

    # itype (ICMP)
    mm = re.search(r'itype\s*:\s*(\d+)', options_str)
    if mm:
        r.itype = int(mm.group(1))

    # content keywords (collect all, note nocase)
    for cm in re.finditer(r'content\s*:\s*"([^"]*)"', options_str):
        # Check if nocase follows this content keyword
        pos = cm.end()
        snippet = options_str[pos:pos+30]
        kw = cm.group(1)
        if 'nocase' in snippet:
            r.nocase_content.append(kw.lower())
        else:
            r.content.append(kw)

    # http modifiers
    if 'http_uri' in options_str:
        r.http_uri = True
    if 'http_method' in options_str:
        r.http_method = True
    if 'http_header' in options_str:
        r.http_header = True

    # dsize
    mm = re.search(r'dsize\s*:\s*>\s*(\d+)', options_str)
    if mm:
        r.dsize_gt = int(mm.group(1))

    # threshold count/seconds
    mm = re.search(r'threshold\s*:[^;]*count\s+(\d+)\s*,\s*seconds\s+(\d+)', options_str)
    if mm:
        r.threshold_count = int(mm.group(1))
        r.threshold_seconds = int(mm.group(2))
