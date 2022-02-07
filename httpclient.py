#!/usr/bin/env python3
# coding: utf-8
# Copyright 2022 Dillon Allan
# Copyright 2016 Abram Hindle, https://github.com/tywtyw2002, and https://github.com/treedust
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
from typing import Tuple
# you may use urllib to encode data appropriately
import urllib.parse
from httpstatus import HttpStatus


def help():
    print("httpclient.py [GET/POST] [URL]\n")


class HTTPResponse(object):
    def __init__(self, code=200, body=""):
        self.code = code
        self.body = body


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

    # def get_host_port(self,url):

    def connect(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        return None

    def get_code(self, data):
        return None

    def get_headers(self, data):
        return None

    def get_body(self, data):
        return None

    def sendall(self, data):
        self.socket.sendall(data.encode(self.ENCODING))

    def close(self):
        self.socket.close()

    # read everything from the socket
    def recvall(self, sock):
        buffer = bytearray()
        done = False
        while not done:
            part = sock.recv(1024)
            if (part):
                buffer.extend(part)
            else:
                done = not part
        return buffer.decode('utf-8')

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
        code = 500
        body = ""
        return HTTPResponse(code, body)

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

    def __send_request(self, host: bytes, port: int, request_bytes: bytes) -> bytes:
        response_data = b''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((host, port))
            client_socket.sendall(request_bytes)
            client_socket.shutdown(socket.SHUT_WR)

            # Receive the full response
            response_data = b''
            while True:
                buffer = client_socket.recv(self.RECV_MAX_CHUNK_SIZE)
                if buffer:
                    response_data = b''.join((response_data, buffer))
                else:
                    break

        return response_data

    def __parse_response(self, response_bytes: bytes) -> HTTPResponse:
        pass


if __name__ == "__main__":
    client = HTTPClient()

    # Set log level to desired verbosity
    logging.basicConfig(
        level=logging.DEBUG, format='[%(levelname)s - %(asctime)s - %(name)s] %(message)s')

    if (len(sys.argv) <= 1):
        help()
        sys.exit(1)
    elif (len(sys.argv) == 3):
        print(client.command(sys.argv[2], sys.argv[1]))
    else:
        print(client.command(sys.argv[1]))
