# minilog
Leveled execution logs for Go.

This is an efficient pure Go implementation of leveled logs

Basic examples:
		l := InitLogger()
		defer CloseLogger()
		l.SetLogLevel("trace")
		l.SetLogMode(ToStderr)
		l.SetLogDir("/tmp")
		
		Ltrace("hello world")
		Lerror("this is a test")
