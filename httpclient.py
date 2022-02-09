#!/usr/bin/env python3
# coding: utf-8
# Copyright 2022 Dillon Allan
# Copyright 2016 Abram Hindle, https://github.com/tywtyw2002, and https://github.com/treedust
#
# Portions of the HTTP response parsing logic were based by my work
# for CMPUT 404 Assignment 1 (Web Server), accessed 2022-2-06
# at https://github.com/dlallan/CMPUT404-assignment-webserver
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Do not use urllib's HTTP GET and POST mechanisms.
# Write your own HTTP GET and POST
# The point is to understand what you have to send and get experience with it

import logging
import platform
import sys
import socket
import re
from typing import Optional, Tuple
# you may use urllib to encode data appropriately
import urllib.parse
from httpstatus import HttpStatus


def help():
    print("httpclient.py [GET/POST] [URL]\n")


class HTTPResponse(object):
    def __init__(self, code=200, body=""):
        self.code = code
        self.body = body

    def __str__(self) -> str:
        return f"{self.code}\n{self.body}"


class HTTPClient(object):
    '''A web server supporting a subset of the RFC 2616 HTTP/1.1 specification.'''
    ENCODING = 'UTF-8'
    HTTP_VERSION = b'HTTP/1.1'
    TCP_PORT = 80
    DEFAULT_PATH = b'/'

    # RFC 1123 Date Representation in Python? posted by Sebastian Rittau and answered by Florian Bösch is licensed under CC-BY-SA 2.5
    # https://stackoverflow.com/a/225106
    # Accessed 2022-02-06
    RFC_1123_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'

    # Common MIME types by Mozilla Contributors is licensed under CC-BY-SA 2.5
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types,
    # Accessed 2022-02-06
    DEFAULT_MIME_TYPE = b'application/octet-stream'
    DEFAULT_CHARSET = b'charset=utf-8'
    DEFAULT_FORM_ENCODING = b'www/x-form-urlencoded'

    CRLF = b'\r\n'
    CRLF_CRLF = CRLF*2
    SP = b' '
    COLON = b':'
    SEP = b'/'

    RECV_MAX_CHUNK_SIZE = 4096

    class HttpRequest:
        '''Helper class for crafting requests based on the design of HttpClient.'''

        def __init__(self):
            self.__logger = logging.getLogger(HTTPClient.HttpRequest.__name__)
            self.__encoding = HTTPClient.ENCODING
            self.__request_line = b''
            self.__header = {b'Connection': b'close',
                             b'User-Agent': bytes(f'{HTTPClient.__name__}/0.1 Python/{platform.python_version()}', encoding=self.__encoding),
                             b'Accept': b'*/*'}
            self.__message_body = b''

        def set_request_line(self, method: bytes, uri: bytes) -> 'HttpRequest':
            # TODO: add parse.urlencode support for POST data
            self.__request_line = HTTPClient.SP.join([
                method,
                uri,
                HTTPClient.HTTP_VERSION
            ])
            return self

        def update_header(self, fields_to_add: dict) -> 'HttpRequest':
            self.__header.update(fields_to_add)
            return self

        def set_body(self, body: bytes) -> 'HttpRequest':
            self.__message_body = body
            return self

        def to_bytes(self) -> bytes:
            # request_line = HTTPClient.SP.join(
            #     [HTTPClient.HTTP_VERSION, *self.__request_line])

            header_bytes = HTTPClient.CRLF.join(
                [b': '.join([name, val]) for name, val in self.__header.items()])
            header_bytes += HTTPClient.CRLF

            request_bytes = HTTPClient.CRLF.join(
                [self.__request_line, header_bytes, self.__message_body])

            self.__logger.info(f'Request:\n{request_bytes}')
            return request_bytes

    def __init__(self) -> None:
        self.__logger = logging.getLogger(HTTPClient.__name__)
        self.__request = HTTPClient.HttpRequest()

    def connect(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        return None

    def close(self):
        self.socket.close()

    def GET(self, url, args=None):
        '''Send a GET request to the url.'''

        # Validate url
        ok, parsed_url = self.__parse_url_str(url)
        if not ok:
            self.__logger.error(f'Invalid URL: {url}')
            return HTTPResponse(500, b'')

        if parsed_url.path:
            quoted_path = bytes(urllib.parse.quote_plus(
                parsed_url.path, safe=self.SEP), encoding=self.ENCODING)
        else:
            quoted_path = self.DEFAULT_PATH

        request_bytes = self.__request.set_request_line(b'GET', quoted_path) \
            .update_header({b'Host': bytes(parsed_url.netloc, encoding=self.ENCODING)}) \
            .to_bytes()

        # TODO: should args be considered? They aren't supposed to be acted upon by a server responding to a GET.

        # Send request to server
        host = parsed_url.hostname or parsed_url.path
        port = parsed_url.port or HTTPClient.TCP_PORT
        response_bytes = self.__send_request(host, port, request_bytes)
        self.__logger.info(f"response_bytes:\n{response_bytes}")

        # Parse the response
        return self.__parse_response(response_bytes)

    def POST(self, url, args=None):
        '''Send a POST request to the url.'''

        # Validate url
        ok, parsed_url = self.__parse_url_str(url)
        if not ok:
            self.__logger.error(f'Invalid URL: {url}')
            return HTTPResponse(500, b'')

        if parsed_url.path:
            quoted_path = bytes(urllib.parse.quote_plus(
                parsed_url.path, safe=self.SEP), encoding=self.ENCODING)
        else:
            quoted_path = self.DEFAULT_PATH

        self.__request = self.__request.set_request_line(b'POST', quoted_path) \
            .update_header({b'Host': bytes(parsed_url.netloc, encoding=self.ENCODING)})

        args_encoded = urllib.parse.urlencode(
            args or b'').encode(self.ENCODING)
        self.__request = self.__request.update_header({
            b'Content-Type': self.DEFAULT_FORM_ENCODING,
            b'Content-Length': str(len(args_encoded)).encode(self.ENCODING)
        }) \
            .set_body(args_encoded)

        # Send request to server
        request_bytes = self.__request.to_bytes()
        host = parsed_url.hostname or parsed_url.path
        port = parsed_url.port or HTTPClient.TCP_PORT
        response_bytes = self.__send_request(host, port, request_bytes)
        self.__logger.info(f"response_bytes:\n{response_bytes}")

        return self.__parse_response(response_bytes)

    def command(self, url, command="GET", args=None):
        if (command == "POST"):
            return self.POST(url, args)
        else:
            return self.GET(url, args)

    def __parse_url_str(self, url: str) -> Tuple:
        # Validate URI
        parsed_uri = None
        try:
            parsed_uri = urllib.parse.urlparse(url)
        except Exception as e:
            self.__logger.exception(e)
            return False, None

        return True, parsed_uri

    def __recvall(self, sock: socket.socket) -> bytes:
        '''Read everything from the socket'''
        buffer = bytearray()
        while True:
            part = sock.recv(self.RECV_MAX_CHUNK_SIZE)
            if part:
                buffer.extend(part)
            else:
                break
        return bytes(buffer)

    def __send_request(self, host: bytes, port: int, request_bytes: bytes) -> bytes:
        response_data = b''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((host, port))
            client_socket.sendall(request_bytes)
            client_socket.shutdown(socket.SHUT_WR)
            response_data = self.__recvall(client_socket)

        return response_data

    def __parse_response(self, response_bytes: bytes) -> HTTPResponse:
        response_line = b''
        header = {}
        body = b''

        # Only a rude webserver would send an empty response :(
        if not response_bytes:
            self.__logger.error("An empty response was received")
            return HTTPResponse(HttpStatus.INTERNAL_SERVER_ERROR)

        response_and_possibly_body = response_bytes.lstrip(
            self.CRLF).split(self.CRLF_CRLF)

        # There should be exactly two elements from splitting on CLRF_CLRF
        if len(response_and_possibly_body) > 2:
            self.__logger.error(
                f'Unexpected additional elements found in response:\n{response_and_possibly_body}')
            return HTTPResponse(HttpStatus.INTERNAL_SERVER_ERROR)

        if len(response_and_possibly_body) == 2:
            response_line_and_possibly_header, body = response_and_possibly_body

        # No body
        else:
            response_line_and_possibly_header = response_and_possibly_body[0]

        # Check header
        response_and_possibly_header_parts = response_line_and_possibly_header.split(
            self.CRLF, maxsplit=1)
        if len(response_and_possibly_header_parts) == 2:
            response_line, header_raw = response_and_possibly_header_parts
            ok, header = self.__parse_header(header_raw)
            if not ok:
                self.__logger.error(f'Invalid header:\n{header_raw}')
                return HTTPResponse(HttpStatus.INTERNAL_SERVER_ERROR)

        # No header
        else:
            response_line = response_and_possibly_header_parts[0]

        self.__logger.info(
            f'Response line:\n{response_line}\nHeader:\n{header}\nBody (if any):\n{body}')

        ok, code, _ = self.__get_response_code(response_line)
        if not ok:
            return HTTPResponse(HttpStatus.INTERNAL_SERVER_ERROR)

        # Note: assuming the body is a text document is a bad idea
        return HTTPResponse(code, str(body, encoding=self.ENCODING))

    def __parse_header(self, header: bytes) -> Tuple[bool, dict]:
        parsed_header_entries = []
        for entry in header.split(self.CRLF):
            entry_parts = [part.strip()
                           for part in entry.split(self.COLON, maxsplit=1)]

            # Each header name must have a corresponding value
            if len(entry_parts) != 2:
                return False, {}

            parsed_header_entries.append(entry_parts)

        return True, dict(parsed_header_entries)

    def __get_response_code(self, response_line: bytes) -> Tuple[bool, Optional[int], Optional[bytes]]:
        response_line_parts = response_line.split(self.SP, maxsplit=2)
        if len(response_line_parts) != 3:
            self.__logger.error((f'Incorrect number of tokens in response line: {response_line_parts}\n'
                                 f'Expected 3 and received {len(response_line_parts)}'))
            return False, None, None

        http_version, code, phrase = response_line_parts

        if http_version != self.HTTP_VERSION:
            self.__logger.warning(
                f'Server HTTP version is {http_version} which does not match request HTTP version {self.HTTP_VERSION}')

        if not code.isdigit():
            self.__logger.error(f'Code {code} is not a valid integer')
            return False, None, None

        return True, int(code), phrase


if __name__ == "__main__":
    client = HTTPClient()

    # Set log level to desired verbosity
    logging.basicConfig(
        level=logging.CRITICAL, format='[%(levelname)s - %(asctime)s - %(name)s] %(message)s')

    if (len(sys.argv) <= 1):
        help()
        sys.exit(1)
    elif (len(sys.argv) == 3):
        print(client.command(sys.argv[2], sys.argv[1]))
    else:
        print(client.command(sys.argv[1]))
