package workspaceone

import (
	"fmt"
	"time"
)

// syslogPRI is the syslog priority emitted for every record: facility LOG_USER
// (1) shifted left 3 and OR'd with severity LOG_INFO (6) yields 14. The level is
// always INFO, so this is constant.
const syslogPRI = "<14>"

// syslogTimeLayout is the "%Y-%m-%d %H:%M:%S" timestamp layout the receiver
// expects in the framing prefix.
const syslogTimeLayout = "2006-01-02 15:04:05"

// frameInput carries the values frame needs. now is passed in (local time from
// the sender) so framing stays deterministic and testable.
type frameInput struct {
	cef        string
	now        time.Time
	threadName string
}

// frame wraps a CEF payload in the exact wire framing the receiver expects: the
// syslog PRI, a prefix (timestamp, logger name, left-justified thread name and
// level), the CEF payload, and a trailing NUL. There is no newline and no length
// prefix. This framing must not change, or the receiver will fail to parse it.
func frame(in frameInput) []byte {
	record := fmt.Sprintf("%s ws1 %-10s %-8s %s",
		in.now.Format(syslogTimeLayout), in.threadName, "INFO", in.cef)
	return []byte(syslogPRI + record + "\x00")
}
