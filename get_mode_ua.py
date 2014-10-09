#!/usr/bin/env python
import os
import sys
import glob
import logging
import argparse
import traceback
import re
from multiprocessing import Pool
from collections import defaultdict
from datetime import date
    
RE_DICT = []

def parse_logs(log):
    result = '?? ?? ?? ?? ??\n'
    try:
    	logging.info('Parsing log file (pid=%s): %s', os.getpid(), log)

	with open(log, 'r') as logf:
	   ua_store = defaultdict(int)
	   # Collect user agent strings in dictionary
	   for line in logf:
           	try:
			# File format: <timestamp> <user id> <user agent string (may contain whitespace)>
			chunks = line.rstrip().split(' ', 2)			
			user = chunks[1]
			ua = chunks[2]
			ua_store[ua] += 1		
           	except Exception as e:
			logging.info('Invalid log entry: %s\n%s', e, line)

	result = user +' ?? ?? ?? '+ ua +'\n'
	max_ua = ''
	max_date = date(1970, 1, 1)
	min_date = date(2100, 1, 1)
	for ua in ua_store.keys():
	   # Compare user agent string against regex dictionary
	   found = False
	   for regex in RE_DICT:
		m = re.search(regex[0], ua)
		if m:
			found = True
			break
	   if not found:
		continue

	   # Convert date string to date class
	   m = re.match('(\d+)-(\d+)-(\d+)', regex[1])
	   if m:
		dd = date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
	   else:
		continue

	   if ua_store[ua] > ua_store[max_ua]:
		max_ua = ua
		max_regex = regex
	   if dd > max_date:
		max_date = dd
	   if dd < min_date:
		min_date = dd

   	if max_ua != '':
	   result = user +' '+ max_date.strftime('%d-%m-%Y') +' '+ min_date.strftime('%d-%m-%Y') +' '+ max_regex[1] +' '+ max_regex[0] +'\n'
    except Exception as e:
        logging.error('Error parsing log files: %s\n%s',\
            e, traceback.format_exc())
    return result


def get_all_matching(log):
    result = "Error\n"
    try:
    	logging.info('Parsing log file (pid=%s): %s', os.getpid(), log)

	with open(log, 'r') as logf:
	   ua_store = defaultdict(int)
	   # Collect user agent strings in dictionary
	   for line in logf:
           	try:
			# File format: <timestamp> <user id> <user agent string (may contain whitespace)>
			chunks = line.rstrip().split(' ', 2)			
			user = chunks[1]
			result = user+'\n'
			ua = chunks[2]
			ua_store[ua] += 1		
           	except Exception as e:
			logging.info('Invalid log entry: %s\n%s', e, line)

	matching = set()
	for ua in ua_store.keys():
	   # Compare user agent string against regex dictionary
	   found = False
	   for regex in RE_DICT:
		m = re.search(regex[0], ua)
		if m:
			matching.add(regex[0])
			break

	result =  user+" "+" ".join(matching)+'\n'
    except Exception as e:
        logging.error('Error parsing log files: %s\n%s',\
            e, traceback.format_exc())
    return result

def get_releasedates(log, outfile):
    logging.info('Parsing log file (pid=%s): %s', os.getpid(), log)

    with open(log, 'r') as logf:
	ua_store = defaultdict(int)
	for line in logf:
	   try:
	      # File format: <timestamp> <user id> <user agent string (may contain whitespace)>
	      chunks = line.rstrip().split(' ', 2)			
	      ua = chunks[2]
	      ua_store[ua] += 1
           except Exception as e:
	      logging.info('Invalid log entry: %s\n%s', e, line)
	      continue

	for ua in ua_store:
	   for regex in RE_DICT:
	      m = re.search(regex[0], ua)
	      if m:
		 [outfile.write(regex[1] +' '+ ua +'\n') for _ in range(ua_store[ua])]
	         break

def main():
    vfiles = glob.glob(args.version_directory + '/*' + args.version_extension)
    logs = glob.glob(args.log_directory + '/*' + args.log_extension)

    for vfile in vfiles:
	with open(vfile, 'r') as vfilef:
		for line in vfilef:
			# File format: <regex> <timestamp>
			chunks = line.rstrip().split()
			RE_DICT.append([chunks[0], chunks[1]])        
	
    # use multiple processes to split logs
    pool = Pool()
    try:
	if args.all:
	    args.outfile.write('Date UA\n')
	    for log in logs:
            	get_releasedates(log, args.outfile)
	else:
            results = pool.imap_unordered(get_all_matching, logs)#parse_logs

#	    args.outfile.write('User Max Min Mode Mode_UA\n')
            for result in results:
	        args.outfile.write(result)	
    except KeyboardInterrupt:	
        sys.exit()


if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Crunch user agent strings to find OS release dates.')
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    parser.add_argument('-d', '--log_directory', help='Directory containing user log files')
    parser.add_argument('-e', '--log_extension', default='', help='Only read user log files with the specified extension.')
    parser.add_argument('-i', '--version_directory', help='Directory containing version files')
    parser.add_argument('-x', '--version_extension', default='', help='Only read version files with the specified extension.')
    parser.add_argument('-a', '--all', action='store_true', default=False, help='report release dates for all user agent strings')
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
