"""Decode captured network and transport headers for the packet inspector."""
import re


def number(data, offset, size=2):
    return int.from_bytes(data[offset:offset + size], "big")


def network_fields(ip):
    version = ip[0] >> 4
    if version == 6:
        return [("Version", 6), ("Traffic class", (number(ip, 0) >> 4) & 255),
                ("Flow label", number(ip, 0, 4) & 0xfffff),
                ("Payload length", number(ip, 4)), ("Next header", ip[6]),
                ("Hop limit", ip[7])]
    fragment = number(ip, 6)
    return [("Version", version), ("Header length", len(ip)), ("DSCP", ip[1] >> 2),
            ("ECN", ip[1] & 3), ("Total length", number(ip, 2)),
            ("Identification", hex(number(ip, 4))), ("DF", bool(fragment & 0x4000)),
            ("MF", bool(fragment & 0x2000)), ("Fragment offset", fragment & 0x1fff),
            ("TTL", ip[8]), ("Protocol", ip[9]),
            ("Header checksum (unverified)", hex(number(ip, 10)))]


def tcp_fields(tcp):
    flags = number(tcp, 12) & 0x1ff
    names = "FIN SYN RST PSH ACK URG ECE CWR AE".split()
    fields = [("Header length", len(tcp)),
              ("Flags", f"0x{flags:03x} " + " ".join(n for i, n in enumerate(names) if flags & (1 << i))),
              ("Window (raw)", number(tcp, 14)), ("Checksum (unverified)", hex(number(tcp, 16))),
              ("Urgent pointer", number(tcp, 18))]
    pos = 20
    while pos < len(tcp):
        kind = tcp[pos]
        if kind == 0:
            fields.append(("Option", "End of options"))
            break
        if kind == 1:
            fields.append(("Option", "NOP"))
            pos += 1
            continue
        if pos + 2 > len(tcp) or not 2 <= tcp[pos+1] <= len(tcp)-pos:
            fields.append(("Option", "잘못된 옵션 길이"))
            break
        length = tcp[pos+1]
        data = tcp[pos+2:pos+length]
        if kind == 8 and length == 10:
            fields.extend([("Timestamp value", number(data, 0, 4)), ("Timestamp echo", number(data, 4, 4))])
        elif kind == 2 and length == 4:
            fields.append(("MSS", number(data, 0)))
        elif kind == 3 and length == 3:
            fields.append(("Window scale shift", data[0]))
        elif kind == 4 and length == 2:
            fields.append(("Option", "SACK permitted"))
        else:
            fields.append((f"Option {kind}", data.hex(" ")))
        pos += length
    return fields


COMMANDS = {
    "SMTP": "EHLO HELO MAIL RCPT DATA RSET NOOP QUIT STARTTLS AUTH VRFY",
    "POP3": "USER PASS STAT LIST RETR TOP DELE NOOP RSET QUIT UIDL CAPA STLS",
    "IMAP": "LOGIN AUTHENTICATE SELECT EXAMINE FETCH UID SEARCH CAPABILITY NOOP LOGOUT LIST CLOSE",
}


def application_fields(protocol, line):
    prefix, sep, content = line.partition(" | ")
    if not sep or prefix not in (protocol + " S>C", protocol + " C>S"):
        return []
    words = content.split(None, 2)
    if not words:
        return []
    if prefix.endswith("S>C"):
        if protocol == "SMTP":
            match = re.fullmatch(r"(\d{3})([- ])?(.*)", content)
            if match:
                code, separator, message = match.groups()
                meanings = {"220": "Service ready", "221": "Service closing", "235": "Authentication successful",
                            "250": "Requested action completed", "354": "Start mail input",
                            "421": "Service unavailable", "550": "Mailbox unavailable"}
                fields = [("Response code", code)]
                if code in meanings:
                    fields.append(("Meaning", meanings[code]))
                return fields + [("Continuation", separator == "-"), ("Response parameter", message)]
        if protocol == "POP3" and words[0] in ("+OK", "-ERR"):
            return [("Status", words[0]), ("Response text", content[len(words[0]):].lstrip())]
        if protocol == "IMAP" and len(words) >= 2 and (words[0] == "*" or words[1].upper() in ("OK","NO","BAD")):
            return [("Tag", words[0]), ("Response", content.split(None, 1)[1])]
    else:
        index = int(protocol == "IMAP")
        if len(words) > index and words[index].upper() in COMMANDS[protocol].split():
            fields = [("Tag", words[0])] if index else []
            fields.append(("Command", words[index]))
            args = content.split(None, index + 1)
            if len(args) > index + 1:
                fields.append(("Argument", args[-1]))
            return fields
    return []
