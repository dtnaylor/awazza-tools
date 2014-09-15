Awazza Log Processing Scripts
=============================

* `awazza.py`

	Implements classes used by the other Awazza processing scripts:

	* `AwazzaLog`
	* `AwazzaLogRequest`
	* `AwazzaLogUser`

* `awazza_split_user.py`

	Splits Awazza log files into one file per user (per original log file).

* `awazza_pickler.py`

	Combines per-user per-log Awazza logs into a single file per user. Each of
	these files is a pickled `AwazzaLogUser` object (defined in `awazza.py`).

* `awazza_analyzer.py`

	Analyzes and reports statistics about one or more pickled AwazzaLogs.

Workflow
--------

Assuming raw Awazza logs are stored in `logdir`, the scripts can be used
together as follows:

	./awazza_split_user.py logdir/*.log.1
	./awazza_pickler.py logdir/*.user
	./awazza_analyzer.py logdir/*.user.pickle

If there are many .user files, you may get a "Too many arguments" error. In
this case, use the `-d` and `-e` (directory and extension) flags:

	./awazza_pickler.py -d logdir -e .user


