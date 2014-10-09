#!/usr/bin/env python
import os
import glob
import logging
import argparse
import awazza
import traceback
import gzip
from awazza import AwazzaLogRequest
    
# Splits multiple awazza logs into single per-user logs

def parse_logs(logs):
    try:
      for log in sorted(logs):

      	dirpath, date, machine, _ = awazza.parse_log_name(log)
    	logging.info('Splitting log file (pid=%s): %s\n\t\t\t\t\t\t\t\t\t(Date: %s, Machine: %s)',\
           os.getpid(), log, date, machine)

	if log.endswith('.gz'):  # Check if the files are gzip or not and uncompress if needed
	   logf = gzip.open(log, 'rb')
	else:
	   logf = open(log, 'r')

	for line in logf:
	   # make an AwazzaLogRequest to handle parsing the user id
           try:
               alr = AwazzaLogRequest(line)
           except Exception as e:
               logging.error('Error parsing line: %s\n%s', e, line)
               continue  # skip this line

	   # Ignore bad requests
	   if alr.response_code > 400:
		continue

	   user = alr.user
           user_path = os.path.join(dirpath,\
       	       '%s.user.fix' % user)
	   # Repeatedly opening slows down the process, but prevents 'too many handles' type errors
           # write the record to the corresponding user's file
	   with open(user_path, 'a') as userf:
	       # Output time, user, and user agent string only
               userf.write(str(alr.ts) + ' ' + alr.user + ' ' + alr.user_agent + '\n')

	logf.close()
    except Exception as e:
        logging.error('Error splitting log files: %s\n%s',\
            e, traceback.format_exc())


def main():
        
    if args.directory:
        args.logs = glob.glob(args.directory + '/*' + args.extension)

    # Switch to single thread so output is ordered
    # Again, slow, but time isn't really a factor
    # Alternatively, could sort by timestamp after split
    parse_logs(args.logs)                


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
