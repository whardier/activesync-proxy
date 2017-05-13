#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import sys
import time
import copy

import pprint

import base64

import json
import wbxml

import urlparse

import ConfigParser

import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.web
import tornado.process
import tornado.options
import tornado.log
import tornado.escape
import tornado.httputil
import tornado.gen

from tornado.options import options
from tornado.options import define

_ = lambda s: s

##tornado.httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

## ┏━┓┏━┓╺┳╸╻┏━┓┏┓╻┏━┓
## ┃ ┃┣━┛ ┃ ┃┃ ┃┃┗┫┗━┓
## ┗━┛╹   ╹ ╹┗━┛╹ ╹┗━┛

def config_callback(config_path):
    options.parse_config_file(config_path, final=False)

define('config', default='server.conf', type=str, help='Path to config file', callback=config_callback, group='Config file')

define('debug', default=False, help='Debug', type=bool, group='Application')

define('listen_port', default=8000, help='Listen Port', type=int, group='HTTP Server')
define('listen_host', default='localhost', help='Listen Host', type=str, group='HTTP Server')

define('rewrite_json', default='rewrite.json', help='User based rewrite json configuration file', group='User/Client Management')

## ┏┓ ┏━┓┏━┓┏━╸╻ ╻┏━┓┏┓╻╺┳┓╻  ┏━╸┏━┓
## ┣┻┓┣━┫┗━┓┣╸ ┣━┫┣━┫┃┗┫ ┃┃┃  ┣╸ ┣┳┛
## ┗━┛╹ ╹┗━┛┗━╸╹ ╹╹ ╹╹ ╹╺┻┛┗━╸┗━╸╹┗╸

class BaseHandler(tornado.web.RequestHandler):
    def initialize(self, **kwargs):
        super(BaseHandler, self).initialize(**kwargs)
        self.kwargs = kwargs

class MicrosoftServerActiveSyncHandler(BaseHandler):

    @tornado.gen.coroutine
    def proxy(self, *args, **kwargs):

        ##Will be None for method OPTION
        userid = self.get_query_argument("UserId", base64.urlsafe_b64decode(self.request.headers.get('Authorization', '').split()[-1]).split(':')[0])
        deviceid = self.get_query_argument("DeviceId", None)
        cmd = self.get_query_argument("Cmd", None)

        ## Parse Authorization to determine route/rewrite
        rewrite = self.settings.get('rewrites').get(userid)
        rewrite_device = rewrite.get('device').get(deviceid)

        client_host_header = rewrite['url'].hostname
        client_uri = rewrite['url'].scheme + '://' + rewrite['url'].netloc + self.request.uri

        ## Replace Query Params
        if rewrite_device:
            for pair_match, pair_replace in rewrite_device.get('url', {}).get('query', []):
                client_uri = client_uri.replace(pair_match, pair_replace)

        client = tornado.httpclient.AsyncHTTPClient()

        client_headers = copy.copy(self.request.headers)

        if "Content-Length" in client_headers:
            del client_headers['Content-Length']

        if "Host" in client_headers:
            del client_headers['Host']

        if "Accept-Encoding" in client_headers:
            del client_headers['Accept-Encoding']

        client_headers.add('Host', client_host_header)

        if rewrite_device:
            for key, pairs in rewrite_device.get('headers', {}).items():
                for pair_match, pair_replace in pairs:
                    if client_headers.get(key, None) == pair_match:
                        client_headers[key] = pair_replace

        request_body = self.request.body

        if request_body:
            if cmd == 'Provision':
                rewrite_request_lines = rewrite_device.get('command', {}).get('provision', {}).get('request_lines')
                if rewrite_request_lines:
                    request_xml = wbxml.wbxml_to_xml(request_body, language=wbxml.WBXML_LANG_ACTIVESYNC, charset=wbxml.WBXML_CHARSET_UTF_8)
                    for pair_match, pair_replace in rewrite_request_lines:
                        request_xml = request_xml.replace(pair_match, pair_replace) #FIXME: Make this honor lines instead

                    request_body = wbxml.xml_to_wbxml(request_xml, disable_public_id=True, disable_string_table=True)

        client_request = tornado.httpclient.HTTPRequest(
            url=client_uri,
            headers=client_headers,
            body=request_body if request_body else None,
            method=self.request.method,
            allow_nonstandard_methods=True,
            decompress_response=False,
            connect_timeout=3600,
            request_timeout=3600,
        )

        server_response = yield tornado.gen.Task(client.fetch, client_request)

        self.set_status(server_response.code, server_response.reason)


        ## change this to use Update properly
        for server_header_name, server_header_value in server_response.headers.get_all():
            if server_header_name.lower() in ['content-length']:
                pass

            self.set_header(server_header_name, server_header_value)

        response_body = server_response.body

        if "Content-Length" in self._headers:
            del self._headers['Content-Length']

        if response_body:
            if cmd == 'Provision':
                rewrite_response_lines = rewrite_device.get('command', {}).get('provision', {}).get('response_lines')
                if rewrite_response_lines:
                    response_xml = wbxml.wbxml_to_xml(response_body, language=wbxml.WBXML_LANG_ACTIVESYNC, charset=wbxml.WBXML_CHARSET_UTF_8)
                    for pair_match, pair_replace in rewrite_response_lines:
                        response_xml = response_xml.replace(pair_match, pair_replace) #FIXME: Make this honor lines instead

                    response_body = wbxml.xml_to_wbxml(response_xml, disable_public_id=True, disable_string_table=True)

            self.write(response_body) ##seems legit.. even if there is none

        self.finish()

    get = proxy
    post = proxy
    options = proxy
    head = proxy

## ┏━┓╺┳╸╻ ╻┏┓ ╻ ╻┏━┓┏┓╻╺┳┓╻  ┏━╸┏━┓
## ┗━┓ ┃ ┃ ┃┣┻┓┣━┫┣━┫┃┗┫ ┃┃┃  ┣╸ ┣┳┛
## ┗━┛ ╹ ┗━┛┗━┛╹ ╹╹ ╹╹ ╹╺┻┛┗━╸┗━╸╹┗╸

class StubHandler(BaseHandler):
    def get(self, *args, **kwargs):
        self.write(dict(self.request.headers))

    def head(self, *args, **kwargs):
        self.write('')

    def post(self, *args, **kwargs):
        print(self.request.body)
        self.write(self.request.body)

    def patch(self, *args, **kwargs):
        self.write('')

    def delete(self, *args, **kwargs):
        self.write('')

    def options(self, *args, **kwargs):
        self.write('')

## ┏━┓┏━╸┏━┓╻ ╻┏━╸┏━┓
## ┗━┓┣╸ ┣┳┛┃┏┛┣╸ ┣┳┛
## ┗━┛┗━╸╹┗╸┗┛ ┗━╸╹┗╸

def main():

    tornado.options.parse_command_line()

    rewrites = json.load(open(options.rewrite_json))

    for userid, params in rewrites.items():
        params['url'] = urlparse.urlparse(params.get('url'))

    ## ┏━┓┏━╸╺┳╸╺┳╸╻┏┓╻┏━╸┏━┓
    ## ┗━┓┣╸  ┃  ┃ ┃┃┗┫┃╺┓┗━┓
    ## ┗━┛┗━╸ ╹  ╹ ╹╹ ╹┗━┛┗━┛

    handlers = [
        tornado.web.url(r'/Microsoft-Server-ActiveSync.*', MicrosoftServerActiveSyncHandler),
        tornado.web.url(r'/__stub__$', StubHandler),
    ]

    settings = dict(
        rewrites=rewrites,
        compress_response=False,
        xsrf_cookies=False,
        **options.as_dict()
    )

    tornado.log.gen_log.debug(pprint.pformat(settings))

    ## ┏━┓┏━┓┏━┓╻  ╻┏━╸┏━┓╺┳╸╻┏━┓┏┓╻
    ## ┣━┫┣━┛┣━┛┃  ┃┃  ┣━┫ ┃ ┃┃ ┃┃┗┫
    ## ╹ ╹╹  ╹  ┗━╸╹┗━╸╹ ╹ ╹ ╹┗━┛╹ ╹

    application = tornado.web.Application(handlers=handlers, **settings)

    http_server = tornado.httpserver.HTTPServer(application, xheaders=True)

    http_server.listen(options.listen_port, address=options.listen_host)

    ioloop = tornado.ioloop.IOLoop.instance()

    try:
        ioloop_status = ioloop.start()
    except KeyboardInterrupt:
        ioloop_status = ioloop.stop()

    return ioloop_status

## ┏┳┓┏━┓╻┏┓╻
## ┃┃┃┣━┫┃┃┗┫
## ╹ ╹╹ ╹╹╹ ╹

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass


