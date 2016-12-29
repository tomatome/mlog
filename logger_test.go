// logger_test
package minilog

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func myLogHeader(level string) string {
	now := time.Now()
	_, month, day := now.Date()
	hour, minute, second := now.Clock()

	funcName, _, _ := GetLogFileLine(1)
	// yy-mm-dd hh:mm:ss.uuuuuu level threadid file[line]:
	header := fmt.Sprintf("%s %02d %02d:%02d:%02d %d %s %s",
		month.String()[0:3], day, hour, minute, second,
		os.Getpid(), level, funcName)

	return header
}

func TestUserDefConfig(t *testing.T) {
	l := InitLogger()
	defer CloseLogger()
	l.SetLogLevel("trace")
	l.SetLogMode(ToStderr)
	l.SetLogHeader(myLogHeader)
	Ltrace("hello world")
}

func TestMaxFileNum(t *testing.T) {
	l := InitLogger()
	defer CloseLogger()
	l.SetLogLevel("trace")
	l.SetLogMode(ToFile)
	l.SetMaxFileNum(2)
	l.SetFileMaxSize(4)
	l.PrintLogger()
	for i := 0; i < 100; i++ {
		Lwarn("this is the i=%d", i)
	}
	Lerror("this is the ok")

}

func BenchmarkLog(b *testing.B) {
	InitLogger()
	defer CloseLogger()
	for i := 0; i < b.N; i++ {
		Lerror("this is log num %d", i)
	}
}
