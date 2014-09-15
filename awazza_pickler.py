#!/usr/bin/env python
import os
import logging
import argparse
import resource
import pprint
import glob
import awazza
from multiprocessing import Pool
from awazza import AwazzaLog
from collections import defaultdict

# returns this process' current memory usage in KB
def get_mem_usage():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

def pickle_user_wrapper(user_logs_tuple):
    user = user_logs_tuple[0]
    logs = user_logs_tuple[1]

    a = AwazzaLog()
    for log in logs:
        logging.info('Processing Awazza log (pid=%s): %s  (mem usage: %f MB)',\
            os.getpid(), log, get_mem_usage()/1024.0)

        if get_mem_usage() > 1024*1024*1024:  # 1 GB
            logging.error('Out of memory, exiting. (Memory usage: %f MB)', get_mem_usage()/1024.0)
            sys.exit(-1)

        a.add_log_file(log)
    
    pickle_path = os.path.join(os.path.split(a.original_logs[0])[0],
        '%s.user.pickle' % user)
    if os.path.isfile(pickle_path) and not args.force:
        logging.warn('%s already exists. Use "-f" to overwrite.' % pickle_path)
        return
    logging.info('Saving pickled Awazza log: %s', pickle_path)
    a.save(pickle_path)


def main():

    if args.directory:
        args.logs = glob.glob(args.directory + '/*' + args.extension)

    # group logs by user
    logs_by_user = defaultdict(list)
    for log in args.logs:
        _,_,_,user = awazza.parse_log_name(log)
        logs_by_user[user].append(log)
        
    # pickle users in multiple threads
    pool = Pool()
    try:
        analyzers = pool.map_async(pickle_user_wrapper, logs_by_user.items()).get(0xFFFF)
    except KeyboardInterrupt:
        sys.exit()


if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Preprocess Awazza logs.')
    parser.add_argument('logs', nargs='*', help='Awazza log files')
    parser.add_argument('-d', '--directory', help='Directory containing log files')
    parser.add_argument('-e', '--extension', default='', help='Only read log files with the specified extension (for use with --directory option).')
    parser.add_argument('-f', '--force', action='store_true', default=False, help='Overwrite pickled log files if they already exist.')
    parser.add_argument('-l', '--filter', default=[], nargs='+', help='Only print records of the specified verb type.')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print debug info. --quiet wins if both are present')
    args = parser.parse_args()

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
