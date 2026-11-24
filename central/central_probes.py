"""Bounded, outbound-only Central inspection probes.

Targets are resolved once and connected by numeric IP, with the original host used
only for SNI and HTTP Host. Local, private and special-purpose addresses are not
probed. Redirects are never followed. Agent jobs use the existing Go probes.
"""
import http.client
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

KINDS = ('tcp', 'tls', 'https', 'dpi')
POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix='central-inspect')
TIMEOUT = 6
MIN_BYTES = 65536


def resolve_public(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for item in infos:
        address = item[4][0].split('%')[0]
        ip = ipaddress.ip_address(address)
        if ip.is_global and address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError('No public IP address available for central probes')
    return addresses


def result(status, started, *, byte_count=0, expected_bytes=0, http_code=None, error='', details=None):
    return {'status': status, 'bytes':byte_count, 'expected_bytes':expected_bytes,
            'duration_ms':int((time.monotonic()-started)*1000), 'http_code':http_code,
            'error':str(error)[:300], 'details':details or {}}


def run_probe(host, address, port, kind):
    start=time.monotonic()
    count=0
    expected=0
    http_code=None
    try:
        with socket.create_connection((address, port),timeout=TIMEOUT) as tcp:
            tcp.settimeout(TIMEOUT)
            if kind=='tcp':
                return result('OK_TCP',start,details={'remote_ip':address})
            server_name=host if not _is_ip(host) else None
            context=ssl.create_default_context()
            with context.wrap_socket(tcp,server_hostname=server_name or address) as connection:
                connection.settimeout(TIMEOUT)
                if kind=='tls':
                    return result('OK_TLS',start,details={'tls_version':connection.version()})
                host_header=host if ':' not in host else '['+host+']'
                if port!=443:host_header+=':'+str(port)
                request=('GET / HTTP/1.1\r\nHost: '+host_header+'\r\nUser-Agent: KVNRadar/0.7.0\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n')
                connection.sendall(request.encode('ascii'))
                response=http.client.HTTPResponse(connection)
                response.begin()
                http_code=response.status
                if not 200<=http_code<400:
                    return result('HTTP_STATUS',start,http_code=http_code,details={'remote_ip':address})
                if kind=='https':
                    return result('OK_HTTP',start,http_code=http_code,details={'remote_ip':address})
                content_length=response.getheader('Content-Length')
                if content_length and content_length.isdecimal():expected=int(content_length)
                while count<MIN_BYTES:
                    chunk=response.read(min(8192,MIN_BYTES-count))
                    if not chunk:break
                    count+=len(chunk)
                status='OK_FULL' if count>=MIN_BYTES else 'SHORT_RESPONSE'
                return result(status,start,byte_count=count,expected_bytes=expected,
                              http_code=http_code,details={'remote_ip':address})
    except (socket.timeout,TimeoutError) as exc:
        return result('TRANSFER_TIMEOUT' if kind=='dpi' else 'TCP_FAIL',start,
                      byte_count=count,expected_bytes=expected,http_code=http_code,error=exc.__class__.__name__)
    except (OSError,ssl.SSLError,http.client.HTTPException,ValueError) as exc:
        return result('HTTP_CONNECT_FAIL' if kind in ('https','dpi') else 'TLS_FAIL' if kind=='tls' else 'TCP_FAIL',start,
                      byte_count=count,expected_bytes=expected,http_code=http_code,error=exc.__class__.__name__)


def _is_ip(value):
    try:ipaddress.ip_address(value);return True
    except ValueError:return False


def run_all(host,port,save_result):
    """Worker callback receives one result per check, including failed resolutions."""
    try:
        addresses=resolve_public(host,port)
    except (OSError,ValueError) as exc:
        for kind in KINDS:
            save_result(kind,result('NOT_TESTABLE',time.monotonic(),error=str(exc)))
        return
    address=addresses[0]
    for kind in KINDS:
        try:
            output=run_probe(host,address,port,kind)
        except Exception as exc:
            output=result('NOT_TESTABLE',time.monotonic(),error=exc.__class__.__name__)
        save_result(kind,output)
