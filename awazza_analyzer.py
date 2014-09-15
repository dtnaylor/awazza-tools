#!/usr/bin/env python
import os
import sys
import glob
import time
import logging
import argparse
import pprint
import cPickle
import resource
from multiprocessing import Pool
from awazza import AwazzaLog, AwazzaLogRequest, AwazzaLogUser
from collections import defaultdict
from operator import itemgetter

sys.path.append('../../tools/myplot')
import myplot

# returns this process' current memory usage in KB
def get_mem_usage():
    return float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

def hist_string(array):
    counts = defaultdict(int)
    for item in array:
        counts[item] += 1
    return pprint.pformat(dict(counts))

def merge_dicts(d1, d2, dest=None, merge_func=lambda x,y: x+y):
    if dest == None: dest = {}

    for key in set(d1.keys()) | set(d2.keys()):
        dest[key] = merge_func(d1[key], d2[key])

    return dest

def sort_by_value(d, reverse=True):
    return sorted(d.iteritems(), key=itemgetter(1), reverse=reverse)
            

class AwazzaLogAnalyzer(object):
    # For plots
    CDFS = (
        {   'filename': 'user_compression_ratios',
            'data': lambda a: [a._user_lists['median-compression-ratios'], 
                     a._user_lists['mean-compression-ratios']],
            'xlabel': 'Compression Ratio (per user)',
            'numbins': 10000,
            'kwargs': {},
            'labels': ['Median', 'Mean']    },
        {   'filename': 'tcp_handshakes',
            'data': lambda a: [a._user_lists['median-tcp-handshake'], 
                     a._user_lists['mean-tcp-handshake']],
            'xlabel': 'TCP Handshake Latency (ms) (per user)',
            'numbins': 10000,
            'kwargs': {'xscale':'log'},
            'labels': ['Median', 'Mean']    },
        {   'filename': 'appdata_tcp_handshakes',
            'data': lambda a: [a._user_lists['median-appdata-tcp-handshake'], 
                     a._user_lists['mean-appdata-tcp-handshake']],
            'xlabel': 'TCP Handshake Latency for App Data (ms) (per user)',
            'numbins': 10000,
            'kwargs': {'xscale':'log'},
            'labels': ['Median', 'Mean']    },
        {   'filename': 'user_kb_compressed',
            'data': lambda a: [a._user_lists['kb-compressed']],
            'xlabel': 'Total KB Compressed (per user)',
            'numbins': 10000,
            'kwargs': {'xscale':'log'},
            'labels': None },
        {   'filename': 'user_num_ssl_connects',
            'data': lambda a: [a._user_lists['num-ssl-connects']],
            'xlabel': 'Number of SSL connections (per user)',
            'numbins': 10000,
            'kwargs': {},
            'labels': None },
        {   'filename': 'user_cache_hit_ratio',
            'data': lambda a: [a._user_lists['cache-hit-ratio']],
            'xlabel': 'Cache Hit Ratio (per user)',
            'numbins': 10000,
            'kwargs': {},
            'labels': None },
        {   'filename': 'user_kb_cached',
            'data': lambda a: [a._user_lists['kb-cached']],
            'xlabel': 'Total KB Cached (per user)',
            'numbins': 10000,
            'kwargs': {},
            'labels': None },
        {   'filename': 'user_num_root_pages',
            'data': lambda a: [a._user_lists['num-root-pages']],
            'xlabel': 'Number of Root Pages Loaded (per user)',
            'numbins': 10000,
            'kwargs': {},#{'xscale':'log'},
            'labels': None },
    )

    def __init__(self):
        # per log
        self._log_ints = defaultdict(int)  # for saving a running total
        self._log_mime_category_counts = defaultdict(int)

        # per machine
        #self._machine_user_spaces = defaultdict(set)
        #self._machine_ports = defaultdict(set)
        #self._machine_client_ips = defaultdict(set)

        # per request
        self._request_lists = defaultdict(list)  # for saving a list of individual values
        self._request_ints = defaultdict(int)  # for saving a running total
        self._object_popularity_histogram = defaultdict(int)
        
        # per user
        self._user_lists = defaultdict(list)  # for saving a list of individual values


    def _analyze_request(self, r):
        if r.ssl_connect: self._request_ints['num-ssl-connects'] += 1
        self._request_ints['kb-from-origin'] += r.bytes_from_origin / 1000.0
        self._request_ints['kb-cached'] += r.bytes_cached / 1000.0
        self._request_ints['kb-to-client'] += r.bytes_to_client / 1000.0
        self._request_ints['kb-compressed'] += r.bytes_compressed / 1000.0
        if r.client_closed_connection_early and r.bytes_from_origin > r.bytes_to_client:
            self._request_ints['kb-lost-client-closed'] += (r.bytes_from_origin - r.bytes_to_client) / 1000.0

        self._request_lists['tag'].append(r.tag)
        self._request_lists['ms-from-origin'].append(r.ms_from_origin)
        self._request_lists['ms-to-client'].append(r.ms_to_client)
        self._request_lists['tcp-handshake'].append(r.tcp_handshake)

        if not r.cache_hit:
            self._request_lists['tcp-handshake-cache-miss'].append(r.tcp_handshake)

        if r.verb == 'GET':
            # hack: tag url as appdata or rootpage
            tags = ''
            if r.root_page: tags += ',rootpage'
            if r.app_data: tags += ',appdata'
            self._object_popularity_histogram['%s^%s' % (tags, r.url)] += 1

        #self._machine_user_spaces[r.machine].add(r.user_space)
        #self._machine_ports[r.machine].add(r.awazza_port)
        #self._machine_client_ips[r.machine].add('.'.join(r.client_ip.split('.')[0:3]))


    def _analyze_log(self, l):
        self._log_ints['num-users'] += len(l.users)
        self._log_ints['num-gets'] += len(l.get_requests)
        self._log_ints['num-puts'] += len(l.put_requests)
        self._log_ints['num-posts'] += len(l.post_requests)
        self._log_ints['num-heads'] += len(l.head_requests)
        self._log_ints['num-connects'] += len(l.connect_requests)
        self._log_ints['num-optionss'] += len(l.options_requests)
        self._log_ints['num-traces'] += len(l.trace_requests)
        self._log_ints['num-deletes'] += len(l.delete_requests)
        self._log_ints['num-requests'] += len(l.requests)

        for category in l.mime_categories:
            self._log_mime_category_counts[category]\
                += len(l.get_requests_by_mime_category(category))


    def _analyze_user(self, u):
        self._user_lists['median-compression-ratios'].append(u.median_compression_ratio)
        self._user_lists['mean-compression-ratios'].append(u.mean_compression_ratio)
        self._user_lists['kb-compressed'].append(u.total_bytes_compressed / 1000.0)
        self._user_lists['num-ssl-connects'].append(u.num_ssl_connects)
        self._user_lists['cache-hit-ratio'].append(u.cache_hit_ratio)
        self._user_lists['kb-cached'].append(u.total_bytes_cached / 1000.0)
        self._user_lists['num-root-pages'].append(len(u.root_pages))
        self._user_lists['median-tcp-handshake'].append(u.median_tcp_handshake)
        self._user_lists['mean-tcp-handshake'].append(u.mean_tcp_handshake)
        self._user_lists['median-appdata-tcp-handshake'].append(u.median_appdata_tcp_handshake)
        self._user_lists['mean-appdata-tcp-handshake'].append(u.mean_appdata_tcp_handshake)


    def analyze_log(self, a):
        '''Analyze AwazzaLog a, incorporating the results into those we've
           already accumulated.'''

        logging.info('Analyzing log (mem usage: %f MB)', get_mem_usage()/1024.0)
        self._analyze_log(a)

        logging.info('Analyzing users (mem usage: %f MB)', get_mem_usage()/1024.0)
        for user in a.users:
            self._analyze_user(user)

        logging.info('Analyzing requests (mem usage: %f MB)', get_mem_usage()/1024.0)
        for request in a.requests:
            self._analyze_request(request)


    def print_results(self):
        print pprint.pformat(dict(self._log_ints))
        print pprint.pformat(dict(self._log_mime_category_counts))
        print pprint.pformat(dict(self._request_ints))
        #print pprint.pformat(dict(self._machine_user_spaces))
        #print pprint.pformat(dict(self._machine_client_ips))
        #print '<DeltaWithUserResponse>:\n%s' % hist_string(self._request_lists['ms-to-client'])
        #print '<DeltaWithOriginResponse>:\n%s' % hist_string(self._request_lists['ms-from-origin'])
        #print '<DeltaWithOriginConnect>:\n%s' % hist_string(self._request_lists['tcp-handshake'])
        #print '<DeltaWithOriginConnect> (cache miss):\n%s' % hist_string(self._request_lists['tcp-handshake-cache-miss'])
        #print pprint.pformat(sort_by_value(self._object_popularity_histogram))
        #print 'user_num_root_pages:\n%s' % hist_string(self._user_lists['num-root-pages'])
        #print 'user_mean_tcp_handshake:\n%s' % hist_string(self._user_lists['mean-tcp-handshake'])
        #print 'user_median_tcp_handshake:\n%s' % hist_string(self._user_lists['median-tcp-handshake'])
        #print 'user_mean_appdata_tcp_handshake:\n%s' % hist_string(self._user_lists['mean-appdata-tcp-handshake'])
        #print 'user_median_appdata_tcp_handshake:\n%s' % hist_string(self._user_lists['median-appdata-tcp-handshake'])
        #print 'user_mean_compression_ratios:\n%s' % hist_string(self._user_lists['mean-compression-ratios'])
        #print 'user_median_compression_ratios:\n%s' % hist_string(self._user_lists['median-compression-ratios'])

    def save_plots(self, outdir, tag=None):
        # CDFs
        for cdf in AwazzaLogAnalyzer.CDFS:
            myplot.cdf(cdf['data'](self), numbins=cdf['numbins'],\
                xlabel=cdf['xlabel'],\
                labels=cdf['labels'],\
                filename=os.path.join(outdir, '%s_%s.pdf' % (tag, cdf['filename'])),\
                **cdf['kwargs'])

        # Data usage bar chart
        bar_labels = ('From Origin', 'To Client', 'Cached', 'Compressed', 'Closed Early')
        bar_values = (self._request_ints['kb-from-origin'] / 1000000.0,\
                       self._request_ints['kb-to-client'] / 1000000.0,\
                       self._request_ints['kb-cached'] / 1000000.0,\
                       self._request_ints['kb-compressed'] / 1000000.0,\
                       self._request_ints['kb-lost-client-closed'] / 1000000.0)
        myplot.plot([bar_labels], [bar_values], type='bar', label_bars=True,\
            ylabel='Data (GB)', bar_padding=0.5, barwidth=0.5,\
            filename=os.path.join(outdir, '%s_%s.pdf' % (tag, 'data_usage')))

    def save_object_popularity_histogram(self, outdir, tag=None, threshold=0,\
                                            include_count=True):
        object_path = os.path.join(outdir, '%s_object_histogram.txt' % tag)
        page_path = os.path.join(outdir, '%s_page_histogram.txt' % tag)
        appdata_path = os.path.join(outdir, '%s_appdata_histogram.txt' % tag)
        with open(object_path, 'w') as objectf:
            with open(page_path, 'w') as pagef:
                with open(appdata_path, 'w') as appdataf:
                    for url, count in sort_by_value(self._object_popularity_histogram):
                        if count < threshold:
                            break

                        # break off tags we prepended to URL
                        fields = url.split('^')
                        tags = fields[0]
                        url = '^'.join(fields[1:])

                        root_page = 'rootpage' in tags
                        app_data = 'appdata' in tags

                        # prepare line of output text
                        if include_count:
                            line = '%i\t%s\n' % (count, url)
                        else:
                            line = '%s\n' % url

                        # write record to file(s)
                        objectf.write(line)
                        if root_page:
                            pagef.write(line)
                        if app_data:
                            appdataf.write(line)
                appdataf.closed
            pagef.closed
        objectf.closed

    def purge_unpopular_content(self, threshold=2):
        '''Remove objects requested threshold times or fewer'''
        temp = defaultdict(int)
        for obj, count in self._object_popularity_histogram.iteritems():
            if count >= threshold:
                temp[obj] = count

        self._object_popularity_histogram = temp

    def clear(self):
        for key in self.__dict__:
            self.__dict__[key] = None

    def save(self, path):
        '''Save a pickled instance of this analyzer'''
        try:
            with open(path, 'w') as f:
                cPickle.dump(self, f)
            f.closed
        except Exception as e:
            logging.error('Error pickling Awazza analyzer: %s', e)

    @classmethod
    def load(cls, path):
        analyzer = None
        try:
            with open(path, 'r') as f:
                analyzer = cPickle.load(f)
            f.closed
        except Exception as e:
            logging.error('Error loading pickled Awazza analyzer: %s', e)
        return analyzer

    def merge(self, other):
        if type(other) is not AwazzaLogAnalyzer:
            raise TypeError('Cannot merge type %s with AwazzaLogAnalyzer' % type_as_str(other))

        merge_dicts(self._log_ints, other._log_ints, dest=self._log_ints)
        merge_dicts(self._log_mime_category_counts,\
            other._log_mime_category_counts, dest=self._log_mime_category_counts)
        merge_dicts(self._request_ints, other._request_ints, dest=self._request_ints)
        merge_dicts(self._request_lists, other._request_lists, dest=self._request_lists)
        merge_dicts(self._user_lists, other._user_lists, dest=self._user_lists)
        merge_dicts(self._object_popularity_histogram, other._object_popularity_histogram,
            dest=self._object_popularity_histogram)


    def __add__(self,right):
        if type(right) is not AwazzaLogAnalyzer:
            raise TypeError('unsupported operand type(s) for +'+
                    ': \''+type_as_str(self)+'\' and \''+type_as_str(right)+'\'')

        result = AwazzaLogAnalyzer()
        result.merge(self)
        result.merge(right)
        return result


def analyze_log_wrapper(log):
    logging.info('Loading log (pid=%s): %s', os.getpid(), log)
    a = AwazzaLog.load(log)
    analyzer = AwazzaLogAnalyzer()
    analyzer.analyze_log(a)
    return analyzer


def main():

    if args.readfile:
        logging.info('Loading pickled analyzer: %s' % args.readfile)
        master_analyzer = AwazzaLogAnalyzer.load(args.readfile)
    else:
        if args.directory:
            args.logs = glob.glob(args.directory + '/*' + args.extension)

        # process logs individually in separate processes
        pool = Pool()
        try:
            analyzers = pool.map_async(analyze_log_wrapper, args.logs).get(0xFFFF)
        except KeyboardInterrupt:
            sys.exit()

        # collapse the returned analyzers into a single analyzer
        master_analyzer = AwazzaLogAnalyzer()
        for analyzer in analyzers:
            #master_analyzer += analyzer
            master_analyzer.merge(analyzer)
            analyzer.clear()
            if get_mem_usage() / (1024.0 * 1024.0) > 50:  # 50 GB limit
                logging.warn('Memory usage: %f GB.' % get_mem_usage() / (1024.0*1024.0))
                #master_analyzer.purge_unpopular_content()
        master_analyzer.purge_unpopular_content()
        pickle_path = os.path.join(os.path.split(args.logs[0])[0], 'pickled_analyzer.analyzer')
        master_analyzer.save(pickle_path)


    master_analyzer.print_results()
    master_analyzer.save_plots(args.outdir, args.tag)
    master_analyzer.save_object_popularity_histogram(args.outdir, args.tag, 10)
    master_analyzer.save_object_popularity_histogram(args.outdir,\
        args.tag+'_no_count', 10, include_count=False)


if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Analyze Awazza logs.')
    parser.add_argument('logs', nargs='*', help='Pickled Awazza log files')
    parser.add_argument('-d', '--directory', help='Directory containing log files')
    parser.add_argument('-e', '--extension', default='', help='Only read log files with the specified extension (for use with --directory option).')
    parser.add_argument('-r', '--readfile', help='Load a pickled Awazza analyzer instead of analyzing Awazza logs')
    parser.add_argument('-t', '--tag', default='', help='String prefix for plot file names.')
    parser.add_argument('-l', '--filter', default=[], nargs='+', help='Only print records of the specified verb type.')
    parser.add_argument('-o', '--outdir', default='.', help='Output directory (for plots, etc.)')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()
    
    if not os.path.isdir(args.outdir):
        try:
            os.makedirs(args.outdir)
        except Exception as e:
            logging.error('Error making output directory: %s' % args.outdir)
            sys.exit(-1)

    # set up logging
    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno) -7s %(message)s",
        level = level
    )

    main()
