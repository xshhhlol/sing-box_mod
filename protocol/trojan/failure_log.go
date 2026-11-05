package trojan

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
)

// for v2bx: failureLog keeps scanners, which reach every exposed port, from
// writing one error line per connection. The first failure in each interval
// is logged at error level and the rest at debug level; the next error line
// reports how many were suppressed in between and the last of them.
type failureLog struct {
	access     sync.Mutex
	interval   time.Duration
	windowEnd  time.Time
	suppressed int
	since      time.Time
	lastErr    error
}

const failureLogInterval = time.Minute

func (l *failureLog) log(ctx context.Context, logger log.ContextLogger, err error) {
	now := time.Now()
	l.access.Lock()
	if now.Before(l.windowEnd) {
		if l.suppressed == 0 {
			l.since = now
		}
		l.suppressed++
		l.lastErr = err
		l.access.Unlock()
		logger.DebugContext(ctx, err)
		return
	}
	suppressed, since, lastErr := l.suppressed, l.since, l.lastErr
	interval := l.interval
	if interval == 0 {
		interval = failureLogInterval
	}
	l.windowEnd, l.suppressed, l.lastErr = now.Add(interval), 0, nil
	l.access.Unlock()
	if suppressed > 0 {
		logger.Error("suppressed ", suppressed, " similar connection failures since ", since.Format(time.TimeOnly), ", last: ", lastErr)
	}
	logger.ErrorContext(ctx, err)
}
