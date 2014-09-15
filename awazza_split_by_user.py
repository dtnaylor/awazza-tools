#!/usr/bin/env python
import os
import glob
import logging
import argparse
import awazza
import traceback
from multiprocessing import Pool
from awazza import AwazzaLogRequest


def split_log_wrapper(log):
    dirpath, date, machine, _ = awazza.parse_log_name(log)
    logging.info('Splitting log file (pid=%s): %s\n\t\t\t\t\t\t\t\t\t(Date: %s, Machine: %s)',\
        os.getpid(), log, date, machine)

    user_to_fd = {}

    try:
        with open(log, 'r') as logf:
            for line in logf:
                # make an AwazzaLogRequest to handle parsing the user id
                try:
                    user = AwazzaLogRequest(line).user
                except Exception as e:
                    logging.error('Error parsing line: %s\n%s', e, line)
                    continue  # skip this line

                # if we need to open a file for this user, do it
                if not user in user_to_fd:
                    user_path = os.path.join(dirpath,\
                        '%s.%s.%s.user' % (date, machine, user))
                    f = open(user_path, 'w')
                    user_to_fd[user] = f
                else:
                    f = user_to_fd[user]

                # write the record to the corresponding user's file
                f.write(line)
        logf.closed
    except Exception as e:
        logging.error('Error splitting log files: %s\n%s',\
            e, traceback.format_exc())
    finally:
        for fd in user_to_fd.values():
            fd.close()
    

def main():
        
    if args.directory:
        args.logs = glob.glob(args.directory + '/*' + args.extension)

    # use multiple processes to split logs
    pool = Pool()
    try:
        analyzers = pool.map_async(split_log_wrapper, args.logs).get(0xFFFF)
    except KeyboardInterrupt:
        sys.exit()
                


if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Split each Awazza log into one file per user.')
    parser.add_argument('logs', nargs='*', help='Awazza log files')
    parser.add_argument('-d', '--directory', help='Directory containing log files')
    parser.add_argument('-e', '--extension', default='', help='Only read log files with the specified extension (for use with --directory option).')
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
