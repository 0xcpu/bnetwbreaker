import sys
import struct
import textwrap
import binaryninja

from binaryninja import log
from binaryninja.plugin import PluginCommand
from io import BytesIO
from typing import List, Tuple

__author__ = "0xcpu"


class ETWBreakerException(Exception):
    """
    Base exception for all exception of ETW breaker
    """
    def __init__(self, message):
        super().__init__(message)


class ETWBreakerWevtTemplateNotFound(ETWBreakerException):
    """
    The WEVT_TEMPLATE ressource was not found
    """
    def __init__(self):
        super().__init__("WEVT_TEMPLATE resource not found.")


class ETWBreakerTLNotFound(ETWBreakerException):
    """
    The tracelogging magic was not found
    """
    def __init__(self):
        super().__init__("Trace logging not found")


class ETWBreakerUnexpectedToken(ETWBreakerException):
    """
    During parsing an unexpected token was found.
    Please open an issue on Github.
    """
    def __init__(self, expected, found):
        super().__init__("Unexpected token. Expected {0:s}, found {1:s}".format(expected, found))


class Stream(BytesIO):
    """
    A wrapper that is nicer to understand
    """
    def read_u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_u8(self) -> int:
        return struct.unpack("<B", self.read(1))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]


class Guid:
    """
    A global unique identifier
    """
    def __init__(self, raw):
        self.raw = raw

    def __str__(self):
        entries1 = struct.unpack("<I", self.raw[0:4])[0]
        entries2 = struct.unpack("<H", self.raw[4:6])[0]
        entries3 = struct.unpack("<H", self.raw[6:8])[0]
        entries4 = self.raw[8:16]
        return "{0:08x}-{1:04x}-{2:04x}-{3:s}-{4:s}".format(
            entries1,
            entries2,
            entries3,
            "".join("{:02x}".format(x) for x in entries4[0:2]),
            "".join("{:02x}".format(x) for x in entries4[2:]))



class ETWBreaker(object):
    """
    This is the main plugin class
    """
    def run(self, bv: binaryninja.binaryview.BinaryView):
        """
        
        """
        ETWBreaker.log("ETWBreaker is enabled")
        providers = []

        # Manifest based provider
        try:
            providers += parse_manifest(bv, find_wevt_template(bv, *find_segment(bv, ".rsrc")[0]))
        except ETWBreakerException as e:
            ETWBreaker.log(str(e))

        # Tracelogging
        for segment in find_segment(bv, ".rentries"):
            try:
                providers += parse_tracelogging(bv, find_tracelogging_meta(bv, *segment))
            except ETWBreakerException as e:
                ETWBreaker.log(str(e))

        ETWResultsForm(bv, providers).show()

    @staticmethod
    def log(message: str):
        log.log_info("[ETWBreaker] {:s}\n".format(message))


class Event:
    """
    An ETW event
    """
    def __init__(
        self,
        bv: binaryninja.binaryview.BinaryView,
        event_id: int,
        version: int,
        channel: int,
        level: int,
        opcode: int,
        task: int,
        keyword: int):
        self._bv = bv
        self.event_id = event_id
        self.version = version
        self.channel = channel
        self.level = level
        self.opcode = opcode
        self.task = task
        self.keyword = keyword

    def find_symbol(self) -> str:
        """
        Try to find a symbol associated to the event

        This is based on the event header signature
        Most of then are into .rentries segment and some of them have a name
        """
        pattern = struct.pack("<HBBBBHQ", self.event_id, self.version, self.channel, self.level, self.opcode, self.task, self.keyword)
        for start, end in find_segment(self._bv, ".rentries"):
            offset = self._bv.read(start, end - start).find(pattern)
            if offset == -1:
                continue

            symbol = self._bv.get_symbol_at(start + offset)
            if symbol is None:
                continue
            
            return symbol.name

        return None


class Channel:
    """
    Channel is a pure ETW concept
    """
    def __init__(self, identifier: int, name: str):
        """
        :ivar identifier: unique identifier of the channel
        :ivar name: name of the channel, generally include the provider name
        """
        self.identifier = identifier
        self.name = name

    def __str__(self):
        return self.name[:self.name.find("\x00")]


class Provider:
    """
    An ETW Provider is defined by a unique GUID
    and a list of event
    """
    def __init__(self, guid: Guid, events: List[Event], channels: List[Channel]):
        """
        :ivar guid: An unique global identifier
        :ivar events: A list of event that could be emitted  by the provider
        :ivar channels: A list of all channel identifier available
        """
        self.guid = guid
        self.events = events
        self.channels = channels

    def find_channel(self, identifier: int) -> Channel:
        """
        Try to find a channel from its identifier
        """
        return next((channel for channel in self.channels if channel.identifier == identifier), None)


class ManifestProvider(Provider):
    """
    Convenient class use to identify Manifest based providers
    """


class TraceLoggingProvider(Provider):
    """
     Convenient class use to identify TraceLogging providers
    """


class ETWResultsForm(object):
    def __init__(self, bv: binaryninja.binaryview.BinaryView, providers: List[Provider]):
        super().__init__()

        self._bv = bv
        self._providers = providers

    @property
    def providers(self):
        return self._providers

    @providers.setter
    def providers(self, providers: List[Provider]):
        self._providers = providers

    def show(self):
        content = """
        <style>
        table {
            font-family: arial, sans-serif;
            border-collapse: collapse;
            width: 100%;
        }

        td, th {
            border: 1px solid #dddddd;
            text-align: left;
            padding: 5px;
        }
        </style>
        <table>
            <tr>
                <th>Event Id</th>
                <th>Type</th>
                <th>Guid</th>
                <th>Channel</th>
                <th>Symbol</th>
            </tr>
        """
        results = []
        for provider in self.providers:
            results += [(provider, event) for event in provider.events]
        entries = []
        for r in results:
            entries.append("<tr>")
            entries.append("<td>{:d}</td><td>{:s}</td><td>{}</td><td>{:s}</td><td>{:s}</td>".format(
                r[1].event_id,
                r[0].__class__.__name__,
                r[0].guid,
                str(r[0].find_channel(r[1].channel)) or "Unknown channel",
                r[1].find_symbol() or "None"
            ))
            entries.append("</tr>")    
        
        content += "".join(entries) + "</table>"
        self._bv.show_html_report("ETWReport", content)


def find_segment(bv: binaryninja.binaryview.BinaryView, name: str) -> List[Tuple[int, int]]:
    """
    Try to find the segment from name

    :ivar name: name of segment
    :ret: Start ant end address
    """
    result = []
    for sn in bv.sections:
        sec = bv.get_section_by_name(sn)
        if sec.name == name:
            result.append((sec.start, sec.end))
    return result


def find_wevt_template(bv: binaryninja.binaryview.BinaryView, start: int, end: int) -> Stream:
    """
    This function try to retrieve the WEVT_TEMPLETE resource
    This resource start with the magic CRIM

    :ivar start: start address
    :ivar end: end address
    :ret: Stream use to parse Manifest based provider or raise an exception
    :raise: ETWBreakerWevtTemplateNotFound
    """
    resource = bv.read(start, end - start)
    result = resource.find(b"CRIM")
    if result == -1:
        raise ETWBreakerWevtTemplateNotFound()

    return Stream(resource[result:])


def find_tracelogging_meta(bv, start, end) -> Stream:
    """
    Try to find ETW0 magic

    :ivar start: start address
    :ivar end: end address
    :ret: Stream use to parse tracelogging or None if not found
    """
    entries = bv.read(start, end - start)
    result = entries.find(b"ETW0")
    if result == -1:
        raise ETWBreakerTLNotFound()

    return Stream(entries[result:])


def parse_tracelogging_event(bv: binaryninja.binaryview.BinaryView, stream: Stream) -> Event:
    """
    A tracelogging event is identified by its channel number_of_channel
    that are always 11. Actually we can't handle tracelogging event
    because the lonk between event and provider is made during code execution

    :ivar stream: current stream use to parse the event
    :ret: An event object for tracelogging
    """
    channel = stream.read_u8()
    if channel != 11:
        raise ETWBreakerUnexpectedToken(11, channel)
    level = stream.read_u8()
    opcode = stream.read_u8()
    keyword = stream.read_u64()
    size = stream.read_u16()
    stream.read(size - 2)
    return Event(bv, 0, 0, channel, level, opcode, 0, keyword)


def parse_tracelogging_provider(bv: binaryninja.binaryview.BinaryView, stream: Stream) -> Provider:
    """
    Create a default provider for tracelogging
    It will add a default event for this provider
    Because in traclogging all event have the event id set to 0

    :ivar stream: current stream use to parse the provider
    :ret: A provider object for tracelogging
    """
    guid = Guid(stream.read(16))
    size = stream.read_u16()
    payload = stream.read(size - 2)
    name = payload[:payload.find(b"\x00")].decode("ascii")

    return TraceLoggingProvider(guid, [Event(bv, 0, 0, 11, 0, 0, 0, 0)], [Channel(11, name)])


def parse_tracelogging(bv: binaryninja.binaryview.BinaryView, stream: Stream) -> List[Provider]:
    """
    Try to parse all tracelogging event and provider
    from an .rentries segmant

    Actually only provider are interesting. It's because the link
    between event and provider are made into the code dynamically.

    :ivar stream: current stream use to parse the event
    :ret: the list of all provider which are found
    """
    magic = stream.read(4)
    if magic != b"ETW0":
        raise ETWBreakerUnexpectedToken(b"ETW0", magic)

    stream.read(12)
    providers = []
    while True:
        prov_type = stream.read_u8()
        if prov_type == 6:
            providers.append(parse_tracelogging_event(bv, stream))
        elif prov_type == 4:
            providers.append(parse_tracelogging_provider(bv, stream))
        elif prov_type == 0:
            # padding
            continue
        else:
            print("Unknown Trace logging prov_type {0:d}, expect to be the end of trace logging block".format(prov_type))
            break

    return providers


def parse_event_elements(bv: binaryninja.binaryview.BinaryView, stream: Stream) -> List[Event]:
    """
    Parse an event element
    An event is defined by :
    * unique identifier
    * a channel
    * a set of keywords
    * a level

    :ivar stream: Input stream once read the EVNT magic and the size of the payload
    :ret: List of all event parsed
    """
    number_of_event = stream.read_u32()
    stream.read(4) # padding

    events = []
    for i in range(0, number_of_event):
        event_id = stream.read_u16()
        version = stream.read_u8()
        channel = stream.read_u8()
        level = stream.read_u8()
        opcode = stream.read_u8()
        task = stream.read_u16()
        keywords = stream.read_u64()
        message_identifier = stream.read_u32()
        template_offset = stream.read_u32()
        opcode_offset = stream.read_u32()
        level_offset = stream.read_u32()
        task_offset = stream.read_u32()
        stream.read(12)
        events.append(Event(bv, event_id, version, channel, level, opcode, task, keywords))

    return events


def parse_channel_element(stream: Stream) -> List[Channel] :
    number_of_channel = stream.read_u32()
    result = []
    for i in range(0, number_of_channel):
        unknown = stream.read_u32()
        offset = stream.read_u32()
        identifier = stream.read_u32()
        message_identifier = stream.read_u32()

        sub_stream = Stream(stream.getvalue())
        sub_stream.read(offset)
        size = sub_stream.read_u32()
        name = sub_stream.read(size-4).decode("utf-16le")
        result.append(Channel(identifier, name))

    return result


def parse_event_provider(bv: binaryninja.binaryview.BinaryView, guid: Guid, stream: Stream) -> Provider:
    """
    Parse an event provider
    An event provider is composed by a plenty of sort of element:
    * EVNT for event

    https://github.com/libyal/libfwevt/blob/master/libfwevt/fwevt_template.h

    :ivar guid: GUID of the provider
    :ivar stream: stream of the entire resource with offset set to the start of the provider
    """
    magic = stream.read(4)
    if magic != b"WEVT":
        raise ETWBreakerUnexpectedToken(b"WEVT", magic)

    size = stream.read_u32()
    message_table_id = stream.read_u32()

    number_of_element = stream.read_u32()
    number_of_unknown = stream.read_u32()

    element_descriptor = [(stream.read_u32(), stream.read_u32()) for i in range(0, number_of_element)]
    unknown = [stream.read_u32() for i in range(0, number_of_unknown)]

    events = []
    channels = []
    for offset, _ in element_descriptor:
        stream.seek(offset)
        magic = stream.read(4)
        size = stream.read_u32()

        # Event declaration
        if magic == b"EVNT":
            events = parse_event_elements(bv, stream)
        elif magic == b"CHAN":
            channels = parse_channel_element(stream)

    return ManifestProvider(guid, events, channels)


def parse_manifest(bv: binaryninja.binaryview.BinaryView, stream: Stream) -> List[Provider]:
    """
    An ETW Manifest is a binary serialized
    It start with CRIM magic

    Then list all providers
    For each providers we can parse GUID and Provider description

    """
    magic = stream.read(4)
    if magic != b"CRIM":
        raise ETWBreakerUnexpectedToken(b"CRIM", magic)

    size = stream.read_u32()

    major_version = stream.read_u16()
    minor_version = stream.read_u16()

    number_of_provider_descriptor = stream.read_u32()

    # Read provider meta informations
    providers_descriptor = [(Guid(stream.read(16)), stream.read_u32()) for i in range(0, number_of_provider_descriptor)]

    # Parse providers
    providers = []
    for guid, offset in providers_descriptor:
        stream.seek(offset)
        providers.append(parse_event_provider(bv, guid, stream))

    return providers


def add_breakpoint():
    """
    Add a software break point on ntdll!EtwEventWrite
    """
    raise NotImplementedError()


def delete_breakpoint():
    """
    Delete the breakpoint set on ntdll_EtwEventWrite
    """
    raise NotImplementedError()


def etw_breaker(bv):
    ETWBreaker().run(bv)


def check_platform(bv, *platforms):
    platform = bv.platform
    if platform is None:
        return False
    return platform.name in platforms


PluginCommand.register(
	"ETWBreaker",
	"Statically find ETW events in a PE file and show their properties",
	lambda bv: etw_breaker(bv),
	lambda bv: check_platform(bv, "windows-x86", "windows-x86_64")
)
