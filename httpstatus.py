# Copyright 2022 Dillon Allan
#
# I originally wrote the source code in this file on 2022-01-26 for CMPUT 404 Assignment 1 (Web Server)
# available at https://github.com/dlallan/CMPUT404-assignment-webserver,
# and am reusing it for this assignment.
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

from enum import IntEnum


class HttpStatus(IntEnum):
    '''
    The few HTTP Status codes supported by HttpServer.

    Design inspired by http.HTTPStatus.

    class http.HTTPStatus by the Python Software foundation is licensed under the Python Software Foundation License Version 2.
    https://docs.python.org/3/library/http.html#http.HTTPStatus
    Accessed 2022-01-26.
    '''
    def __new__(cls, value, phrase):
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.phrase = phrase
        return obj

    OK = (200, 'OK')

    MOVED_PERMANENTLY = (301, 'Moved Permanently')

    BAD_REQUEST = (400, 'Bad Request')
    NOT_FOUND = (404, 'File not found')
    METHOD_NOT_ALLOWED = (405, 'Method Not Allowed')
    IM_A_TEAPOT = (418, "I'm a teapot")

    INTERNAL_SERVER_ERROR = (500, 'Internal Server Error')
    HTTP_VERSION_NOT_SUPPORTED = (505, 'HTTP Version Not Supported')
