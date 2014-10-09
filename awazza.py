import sys
import os
import re
import time
import logging
import cPickle
import pprint
import numpy
import traceback
from collections import defaultdict

IGNORE_TAGS = ('Internal-Services',)
COMPRESSION_TAGS = ('SmartJpeg', 'StopGif')

def parse_log_name(path):
    num_ending_dots = 0
    user = False
    if path[-13:] == '.access.log.1':
        num_ending_dots = 3
    elif path[-5:] == '.user':
        num_ending_dots = 2
        user = True

    dirpath = os.path.split(path)[0]
    fields = os.path.basename(path).split('.')
    date = fields[0]
    machine = '.'.join(fields[1:-num_ending_dots])
    user = fields[-2] if user else None

    return dirpath, date, machine, user


class AwazzaLogRequestContainer(object):
    '''Encapuslates a set of request records and provides various access methods'''
    
    def __init__(self):
        self._requests = []
        self._requests_by_verb = defaultdict(list)  # verb -> list of requests
        self._requests_by_mime_category = defaultdict(list)  # category -> list of reqeusts
    
    def add_request(self, request):
        self._requests.append(request)
        self._requests_by_verb[request.verb].append(request)
        self._requests_by_mime_category[request.mime_category].append(request)
    
    def _get_requests(self):
        return self._requests
    requests = property(_get_requests)

    def get_requests_by_verb(self, verb):
        verb = verb.upper()
        if verb in self._requests_by_verb:
            return self._requests_by_verb[verb]
        else:
            return []

    def get_requests_by_mime_category(self, category):
        if category: category = category.lower()
        if category in self._requests_by_mime_category:
            return self._requests_by_mime_category[category]
        else:
            return []

    def _get_mime_categories(self):
        return self._requests_by_mime_category.keys()
    mime_categories = property(_get_mime_categories)

    def _get_gets(self):
        return self.get_requests_by_verb('GET')
    get_requests = property(_get_gets)
    
    def _get_heads(self):
        return self.get_requests_by_verb('HEAD')
    head_requests = property(_get_heads)

    def _get_puts(self):
        return self.get_requests_by_verb('PUT')
    put_requests = property(_get_puts)

    def _get_posts(self):
        return self.get_requests_by_verb('POST')
    post_requests = property(_get_posts)

    def _get_connects(self):
        return self.get_requests_by_verb('CONNECT')
    connect_requests = property(_get_connects)
    
    def _get_optionss(self):
        return self.get_requests_by_verb('OPTIONS')
    options_requests = property(_get_optionss)

    def _get_traces(self):
        return self.get_requests_by_verb('TRACE')
    trace_requests = property(_get_traces)

    def _get_deletes(self):
        return self.get_requests_by_verb('DELETE')
    delete_requests = property(_get_deletes)



class AwazzaLogUser(AwazzaLogRequestContainer):
    '''Encapuslates the AwazzaLogRequests made by one user'''

    def __init__(self, userid):
        super(AwazzaLogUser, self).__init__()
        self._userid = userid
        self._root_pages = []
        self._clear_stats()
        self._needs_recompute = False

    def _clear_stats(self):
        self._total_bytes_compressed = 0
        self._mean_compression_ratio = 1.0
        self._median_compression_ratio = 1.0
        self._total_bytes_cached = 0
        self._cache_hit_ratio = 0.0
        self._num_ssl_connects = 0
        self._mean_tcp_handshake = 0
        self._median_tcp_handshake = 0
        self._mean_appdata_tcp_handshake = 0
        self._median_appdata_tcp_handshake = 0

    def _compute_stats(self):
        if not self._needs_recompute: return

        self._clear_stats()

        compression_ratios = []
        cache_hits = 0
        tcp_handshakes = []
        appdata_tcp_handshakes = []
        for r in self.requests:
            if r.ssl_connect: self._num_ssl_connects += 1

            if r.verb == 'GET':
                self._total_bytes_compressed += r.bytes_compressed
                compression_ratios.append(r.compression_ratio)
                if r.cache_hit: 
                    cache_hits += 1
                    self._total_bytes_cached += r.bytes_cached
                if r.mime_category in ('json', 'xml'):
                    appdata_tcp_handshakes.append(r.tcp_handshake)

            if r.verb != 'CONNECT':
                tcp_handshakes.append(r.tcp_handshake)
                
                    

        if len(compression_ratios) == 0: compression_ratios = [1.0]
        self._mean_compression_ratio = numpy.mean(compression_ratios)
        self._median_compression_ratio = numpy.median(compression_ratios)
        self._mean_tcp_handshake = 0 if len(tcp_handshakes) == 0 else\
            numpy.mean(tcp_handshakes)
        self._median_tcp_handshake = 0 if len(tcp_handshakes) == 0 else\
            numpy.median(tcp_handshakes)
        self._mean_appdata_tcp_handshake = 0 if len(appdata_tcp_handshakes) == 0 else\
            numpy.mean(appdata_tcp_handshakes)
        self._median_appdata_tcp_handshake = 0 if len(appdata_tcp_handshakes) == 0 else\
            numpy.median(appdata_tcp_handshakes)

        self._cache_hit_ratio = 0 if len(self.get_requests) == 0\
            else cache_hits / float(len(self.get_requests))

        self._needs_recompute = False

    def add_request(self, request):
        super(AwazzaLogUser, self).add_request(request)

        if request.root_page:
            self._root_pages.append(request)
        
        self._needs_recompute = True


    def _get_total_bytes_compressed(self):
        self._compute_stats()
        return self._total_bytes_compressed
    total_bytes_compressed = property(_get_total_bytes_compressed)

    def _get_compression_ratios(self):
        compression_ratios = []
        for r in self.requests:
            if r.verb == 'GET':
                compression_ratios.append(r.compression_ratio)
        return compression_ratios
    compression_ratios = property(_get_compression_ratios)

    def _get_mean_compression_ratio(self):
        self._compute_stats()
        return self._mean_compression_ratio
    mean_compression_ratio = property(_get_mean_compression_ratio)
    
    def _get_median_compression_ratio(self):
        self._compute_stats()
        return self._median_compression_ratio
    median_compression_ratio = property(_get_median_compression_ratio)
    
    def _get_total_bytes_cached(self):
        self._compute_stats()
        return self._total_bytes_cached
    total_bytes_cached = property(_get_total_bytes_cached)

    def _get_cache_hit_ratio(self):
        self._compute_stats()
        return self._cache_hit_ratio
    cache_hit_ratio = property(_get_cache_hit_ratio)

    def _get_num_ssl_connects(self):
        self._compute_stats()
        return self._num_ssl_connects
    num_ssl_connects = property(_get_num_ssl_connects)

    def _get_root_pages(self):
        return self._root_pages
    root_pages = property(_get_root_pages)
    
    def _get_mean_tcp_handshake(self):
        self._compute_stats()
        return self._mean_tcp_handshake
    mean_tcp_handshake = property(_get_mean_tcp_handshake)
    
    def _get_median_tcp_handshake(self):
        self._compute_stats()
        return self._median_tcp_handshake
    median_tcp_handshake = property(_get_median_tcp_handshake)
    
    def _get_mean_appdata_tcp_handshake(self):
        self._compute_stats()
        return self._mean_appdata_tcp_handshake
    mean_appdata_tcp_handshake = property(_get_mean_appdata_tcp_handshake)
    
    def _get_median_appdata_tcp_handshake(self):
        self._compute_stats()
        return self._median_appdata_tcp_handshake
    median_appdata_tcp_handshake = property(_get_median_appdata_tcp_handshake)



class AwazzaLogRequest(object):
    '''Encapsulates an Awazza log entry.'''

    def __init__(self, record, machine=''):

        try:
            fields = record.split(' ')
            middle_fields = record.split('HTTP/')[1].split('" ')[1].strip().split(' ')  # FIXME: hacky -- use regex?
            final_fields = fields[-1][1:-1].split(',')  # the fields between parens
            
            # HTTP headers
            self.mime_type = None
            curly_brace_fields = re.split(r'[{}]', '"'.join(record.split('"')[4:])) # hack because some paths had curly braces
            request_headers = [x.split(': ') for x in curly_brace_fields[1].strip('&').split('&')]
            response_headers = [x.split(': ') for x in curly_brace_fields[3].strip('&').split('&')]
            self.transfer_encoding = ''
            self.request_host = ''
            self.user_agent = ''
            for header in response_headers:
                if header[0] == 'Content-Type':
                    self.mime_type = header[1]
                elif header[0] == 'Transfer-Encoding':
                    self.transfer_encoding = header[1]
            for header in request_headers:
                if header[0] == 'Host':
                    self.request_host = header[1]
                elif header[0] == 'User-Agent':
                    self.user_agent = header[1]
            
            # General information
            self.ts = int(time.mktime(time.strptime(fields[4], '[%d/%b/%Y:%H:%M:%S]')))
            self.origin = final_fields[12] if final_fields[12] != '' else\
                self.request_host
            self.client_ip = fields[2]
            self.path = fields[6]
            self.verb = fields[5][1:] # cut off the leading '"'
            self.http_referer = fields[8][:-1] # Cut of trailing '"'; FIXME: could have spaces?
	    self.response_code = int(fields[9])
            self.tag = final_fields[13]
            self.machine = machine
            self.url = '%s%s' % (self.origin, self.path)
            self.client_closed_connection_early = True if final_fields[15] == 'Y' else False
            
            # Caching
            self.cache_hit = 'Hit' in final_fields[10]

            # SIZES
            original_size = int(fields[-2])
            content_length = int(middle_fields[1])
            self.bytes_to_client = int(middle_fields[2])
                
            # Bytes actually fetched from origin
            # If not cache hit, try these fields in the following order:
            #   1) Content Length  (from Content-Length header)
            #   2) original size   (set by Awazza if compression)
            #   3) bytes to client
            if self.cache_hit:
                self.bytes_from_origin = 0
            else:
                if content_length > 0:
                    self.bytes_from_origin = content_length
                elif self.transfer_encoding == 'chunked':  # if chunked, there is no Content-Length header
                    self.bytes_from_origin = original_size if original_size > 0 else\
                        self.bytes_to_client  # not perfect, but decent guess
                else:
                    self.bytes_from_origin = 0

            # Original object size
            # Try these fields in the following order:
            #   1) original size  (set by Awazza if compression)
            #   2) content length (from Content-Length header)
            #   3) bytes to client
            if original_size > 0:
                self.original_size = original_size
            elif content_length > 0:
                self.original_size = content_length
            else:
                self.original_size = self.bytes_to_client

            # How many bytes did we avoid fetching from origin?
            self.bytes_cached = self.original_size if self.cache_hit else 0


            # SSL
            self.ssl_connect = self.verb == 'CONNECT' and self.path[-4:] == ':443'
            
            # Make a unique ID: <seconds since epoch><host><path>
            self.uid = '<%s><%s><%s>' % (self.ts, self.origin, self.path)

            # Make user ID from <UserSpace>-<Port>
            self.user_space = final_fields[18].strip()
            self.awazza_port = fields[-3].split('[:')[1].split(']')[0]
            self.user = '%s-%s' % (self.user_space, self.awazza_port)

            # Compression
            self.compression_tag = final_fields[0][1:-1]
            self.compressed = self.compression_tag in COMPRESSION_TAGS
            self.bytes_compressed = 0 if self.original_size == 0 or not self.compressed else\
                self.original_size - self.bytes_to_client
            self.compression_ratio = 1 if not self.compressed or\
                self.bytes_to_client == 0 else\
                self.original_size / float(self.bytes_to_client)

            # Handshake
            delta_with_origin_request = int(final_fields[5])
            self.tcp_handshake = delta_with_origin_request

            # Bandwidth
            self.ms_from_origin = int(final_fields[6])
            self.ms_to_client = int(final_fields[9])
            self.mbps_from_origin = 0 if self.ms_from_origin == 0 else\
                (self.bytes_from_origin * 8 / 1000000.0) / (self.ms_from_origin / 1000.0)
            self.mbps_to_client = 0 if self.ms_to_client == 0 else\
                (self.bytes_to_client * 8 / 1000000.0) / (self.ms_to_client / 1000.0)

            # Root page?
            # Heuristically decide if this request is a "root page",
            # i.e., an original page the user loaded as opposed to an
            # embedded resource loaded by a page or data loaded by an app.
            # Criteria:
            #   1) content type is HTML
            #   2) not tagged as an ad by Awazza
            self.root_page =\
                (self.mime_category == 'html' and self.tag == 'Default')

            # App data?
            # Heuristically decide if this request is a piece of app data.
            # Criteria:
            #   1) type is JSON or XML
            #   2) not tagged as an ad by Awazza
            # TODO: look at user agent?
            self.app_data =\
                (self.mime_category in ['json', 'xml'] and self.tag == 'Default')


        except Exception as e:
            logging.error('Error parsing record: %s\nRECORD:\n%s\nTRACEBACK\n%s',
                e, record, traceback.format_exc())
            raise e


    def _get_category(self):
        if not self.mime_type:
            return None
        elif 'image' in self.mime_type:
            return 'image'
        elif 'audio' in self.mime_type:
            return 'audio'
        elif 'video' in self.mime_type:
            return 'video'
        elif 'css' in self.mime_type:
            return 'css'
        elif 'html' in self.mime_type:
            return 'html'
        elif 'javascript' in self.mime_type:
            return 'javascript'
        elif any(t in self.mime_type for t in ['text/plain', 'text/rtf']):
            return 'text'
        elif 'flash' in self.mime_type:
            return 'flash'
        elif any(t in self.mime_type for t in ['text/xml', 'application/xml']):
            return 'xml'
        elif 'json' in self.mime_type:
            return 'json'
        elif 'font' in self.mime_type:
            return 'font'
        elif 'octet-stream' in self.mime_type:
            return 'binary'
        else:
            return 'unknown'
    mime_category = property(_get_category)

    def _get_seconds_saved_by_awazza(self):
        # How much time did Awazza save for this object?
        # Components:
        #   1) object size / bandwidth from origin  (if cache hit)
        #   2) compressed bytes / bandwidth to client  (if compressed)
        # We (conservatively) don't include SSL handshake because we don't
        # know whether or not the browser would have had a connection open
        # and, if not, how long the RTT would have been.
        estimated_mbps_from_origin = self.mbps_from_origin\
            if self.mbps_from_origin > 0 else 20  # TODO: better guess?
        seconds_saved_by_cache = (self.original_size*8.0) / (estimated_mbps_from_origin*1000000.0)\
            if self.cache_hit else 0

        estimated_mbps_to_client = self.mbps_to_client\
            if self.mbps_to_client > 0 else 3   # TODO: better guess?
        seconds_saved_by_compression = (self.bytes_compressed*8.0) / (estimated_mbps_to_client*1000000.0)

        return seconds_saved_by_cache + seconds_saved_by_compression
    seconds_saved_by_awazza = property(_get_seconds_saved_by_awazza)


    def sanity_check(self):
        ok = True

        if self.bytes_compressed > 0 and self.compression_tag == 'No_Compression':
            logging.debug('No compression but delivered fewer bytes: %i/%i, %s',\
                self.bytes_from_origin, self.bytes_to_client, self.compression_tag)
            ok = False

        if self.bytes_compressed < 0 and self.verb == 'GET':
            logging.debug('Expanded content (%i to %i).',\
                self.original_size, self.bytes_to_client)
            ok = False

        if self.request_host != self.origin and\
            self.verb != 'CONNECT' and\
            not self.cache_hit and\
            not any(t in self.tag for t in IGNORE_TAGS):
            logging.debug('Host header and origin do not match: %s, %s',\
                self.request_host, self.origin)
            ok = False
        
        #if self.ms_from_origin == 0 and self.verb == 'GET':
        #    logging.debug('ms_from_origin is 0')

        #if self.ms_to_client == 0 and self.verb == 'GET':
        #    logging.debug('ms_to_client is 0')

        return ok


    def __str__(self):
        return pprint.pformat(self.__dict__)
    def __repr__(self):
        return self.__str__()
    def __gt__(self, other):
        return self.ts > other.ts



class AwazzaLog(AwazzaLogRequestContainer):
    '''Encapsulates an Awazza log; resulting object can be pickled.'''

    def __init__(self, log=None):
        super(AwazzaLog, self).__init__()
        self._root_pages = []
        self._users = {}
        self._log_paths = []  # original Awazza log files
        
        if log: self.add_log_file(log)

    def add_log_file(self, log):
        self._log_paths.append(log)

        with open(log, 'r') as f:
            i = 0
            for line in f:
                request = AwazzaLogRequest(line.strip())

                if not any(t in request.tag for t in IGNORE_TAGS):
                    self.add_request(request)
                    if request.user not in self._users:
                        self._users[request.user] = AwazzaLogUser(request.user)
                    self._users[request.user].add_request(request)

                    # Print some stats, maybe
                    #request.sanity_check()
                    #logging.debug('Raw record %i:\n%s', i, line.strip())
                    #logging.debug('Processed record:\n%s\n', request)
        f.closed


    @classmethod
    def load(cls, pickle_path):
        '''Return an AwazzaLog instance from the supplied pickle file.'''
        a = None
        try:
            with open(pickle_path, 'r') as f:
                a = cPickle.load(f)
            f.closed
        except Exception as e:
            logging.error('Error loading AwazzaLog: %s', e)
        return a


    def save(self, path):
        '''Save this AwazzaLog instance to a pickle file'''

        try:
            with open(path, 'w') as f:
                cPickle.dump(self, f)
            f.closed
        except Exception as e:
            logging.error('Error saving AwazzaLog instance: %s' % e)

    def _get_log_paths(self):
        return self._log_paths
    original_logs = property(_get_log_paths)

    def _get_users(self):
        return self._users.values()
    users = property(_get_users)

    def __str__(self):
        return pprint.pformat(self.__dict__)
    def __repr__(self):
        return self.__str__()
