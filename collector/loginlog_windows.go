// +build windows

package collector

import (
	"fmt"
	"os"
	"sec_check/models"

	"github.com/olekukonko/tablewriter"
)

/*const (
	// renderBufferSize is the size in bytes of the buffer used to render events.
	renderBufferSize   = 1 << 14
	winodwsEvtxFile    = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
	winodwsEvtxFilex32 = "C:\\Windows\\Sysnative\\winevt\\Logs\\Security.evtx"
)

var localAddress = []string{"-", "127.0.0.1", "::1"}

type Record struct {
	sys.Event
	API string // The event log API type used to read the record.
	XML string // XML representation of the event.
}

// EventLog is an interface to a Windows Event Log.
type EventLog interface {
	// Open the event log. recordNumber is the last successfully read event log
	// record number. Read will resume from recordNumber + 1. To start reading
	// from the first event specify a recordNumber of 0.
	Open(recordNumber uint64) error

	// Read records from the event log.
	Read() ([]Record, error)

	// Close the event log. It should not be re-opened after closing.
	Close() error
}

// query contains parameters used to customize the event log data that is
// queried from the log.
type query struct {
	IgnoreOlder time.Duration // Ignore records older than this period of time.
	EventID     string        // White-list and black-list of events.
	Level       string        // Severity level.
	Provider    []string      // Provider (source name).
}

// Validate that winEventLog implements the EventLog interface.
var _ EventLog = &winEventLog{}
var first = true

// winEventLog implements the EventLog interface for reading from the Windows
// Event Log API.
type winEventLog struct {
	// config       winEventLogConfig
	query        string
	channelName  string        // Name of the channel from which to read.
	subscription wineventlog.EvtHandle // Handle to the subscription.
	maxRead      int           // Maximum number returned in one Read.
	lastRead     uint64        // Record number of the last read event.

	render    func(event wineventlog.EvtHandle, out io.Writer) error // Function for rendering the event to XML.
	renderBuf []byte                                         // Buffer used for rendering event.
	outputBuf *sys.ByteBuffer                                // Buffer for receiving XML
	// cache     *messageFilesCache                             // Cached mapping of source name to event message file handles.

	logPrefix string // String to prefix on log messages.
}

func (l *winEventLog) Open(recordNumber uint64) error {
	bookmark, err := wineventlog.CreateBookmark(l.channelName, recordNumber)
	if err != nil {
		return err
	}
	defer wineventlog.Close(bookmark)

	// Using a pull subscription to receive events. See:
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa385771(v=vs.85).aspx#pull
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil
	}

	subscriptionHandle, err := wineventlog.Subscribe(
		0, // Session - nil for localhost
		signalEvent,
		"",       // Channel - empty b/c channel is in the query
		l.query,  // Query - nil means all events
		bookmark, // Bookmark - for resuming from a specific event
		wineventlog.EvtSubscribeStartAfterBookmark)
	if err != nil {
		return err
	}

	l.subscription = subscriptionHandle
	return nil
}

func (l *winEventLog) Read() ([]Record, error) {
	handles, _, err := l.eventHandles(l.maxRead)
	if err != nil || len(handles) == 0 {
		return nil, err
	}
	defer func() {
		for _, h := range handles {
			wineventlog.Close(h)
		}
	}()

	var records []Record
	for _, h := range handles {
		l.outputBuf.Reset()
		err := l.render(h, l.outputBuf)
		if bufErr, ok := err.(sys.InsufficientBufferError); ok {
			l.renderBuf = make([]byte, bufErr.RequiredSize)
			l.outputBuf.Reset()
			err = l.render(h, l.outputBuf)
		}
		if err != nil && l.outputBuf.Len() == 0 {
			continue
		}

		r, err := l.buildRecordFromXML(l.outputBuf.Bytes(), err)
		if err != nil {
			continue
		}
		records = append(records, r)
		l.lastRead = r.RecordID
	}
	return records, nil
}

func (l *winEventLog) Close() error {
	return wineventlog.Close(l.subscription)
}

func (l *winEventLog) eventHandles(maxRead int) ([]wineventlog.EvtHandle, int, error) {
	handles, err := wineventlog.EventHandles(l.subscription, maxRead)
	switch err {
	case nil:
		return handles, maxRead, nil
	case wineventlog.ERROR_NO_MORE_ITEMS:
		return nil, maxRead, nil
	case wineventlog.RPC_S_INVALID_BOUND:
		if err := l.Close(); err != nil {
			return nil, 0, err
		}
		if err := l.Open(l.lastRead); err != nil {
			return nil, 0, err
		}
		return l.eventHandles(maxRead / 2)
	default:
		return nil, 0, err
	}
}

func (l *winEventLog) buildRecordFromXML(x []byte, recoveredErr error) (Record, error) {
	e, err := sys.UnmarshalEventXML(x)
	if err != nil {
		return Record{}, fmt.Errorf("Failed to unmarshal XML='%s'. %v", x, err)
	}

	sys.PopulateAccount(&e.User)

	if e.RenderErrorCode != 0 {
		// Convert the render error code to an error message that can be
		// included in the "message_error" field.
		e.RenderErr = syscall.Errno(e.RenderErrorCode).Error()
	} else if recoveredErr != nil {
		e.RenderErr = recoveredErr.Error()
	}

	if e.Level == "" {
		// Fallback on LevelRaw if the Level is not set in the RenderingInfo.
		e.Level = wineventlog.EventLevel(e.LevelRaw).String()
	}

	r := Record{
		Event: e,
	}
	return r, nil
}

func newWinEventLog(eventID string) (EventLog, error) {
	var ignoreOlder time.Duration
	if first {
		ignoreOlder = time.Hour * 17520
		first = false
	} else {
		ignoreOlder = time.Second * 60
	}
	query, err := wineventlog.Query{
		Log:         "Security",
		IgnoreOlder: ignoreOlder,
		Level:       "",
		EventID:     eventID,
		Provider:    []string{},
	}.Build()
	if err != nil {
		return nil, err
	}

	l := &winEventLog{
		query:       query,
		channelName: "Security",
		maxRead:     1000,
		renderBuf:   make([]byte, renderBufferSize),
		outputBuf:   sys.NewByteBuffer(renderBufferSize),
	}

	l.render = func(event wineventlog.EvtHandle, out io.Writer) error {
		return wineventlog.RenderEvent(event, 0, l.renderBuf, nil, out)
	}
	return l, nil
}*/

// GetLoginLog 获取系统登录日志
func GetLoginLog() (resultData []models.LoginLog) {
	/*var loginFile string
	var timestamp int64
	LastTime := "all"
	if LastTime == "all" {
		timestamp = 615147123
	} else {
		ti, _ := time.Parse("2006-01-02T15:04:05Z07:00", LastTime)
		timestamp = ti.Unix()
	}
	if runtime.GOARCH == "386" {
		loginFile = winodwsEvtxFilex32
	} else {
		loginFile = winodwsEvtxFile
	}
	if _, err := os.Stat(loginFile); err != nil {
		// 不支持2003
		log.Println(err.Error())
		return
	}
	resultData = getSuccessLog(timestamp)
	resultData = append(resultData, getFailedLog(timestamp)...)*/
	return resultData
}
/*
func getSuccessLog(timestamp int64) (resultData []models.LoginLog) {
	l, err := newWinEventLog("4624")
	if err != nil {
		return
	}
	err = l.Open(0)
	if err != nil {
		return
	}
	reList, _ := l.Read()
	for _, rec := range reList {
		// rec.EventData.Pairs[10].Value != "5" &&
		if rec.TimeCreated.SystemTime.Local().Unix() > timestamp {
			if lib.InArray(localAddress, rec.EventData.Pairs[18].Value, false) {
				continue
			}
			m := models.LoginLog{}
			m.Status = true
			m.Username = rec.EventData.Pairs[5].Value
			m.Remote = rec.EventData.Pairs[18].Value
			m.Time = rec.TimeCreated.SystemTime.Local().Format("2006-01-02T15:04:05Z07:00")
			resultData = append(resultData, m)
		}
	}
	return
}
func getFailedLog(timestamp int64) (resultData []models.LoginLog) {
	l, err := newWinEventLog("4625")
	if err != nil {
		return
	}
	err = l.Open(0)
	if err != nil {
		return
	}
	reList, _ := l.Read()
	for _, rec := range reList {
		// rec.EventData.Pairs[8].Value != "5" &&
		if rec.TimeCreated.SystemTime.Local().Unix() > timestamp {
			if lib.InArray(localAddress, rec.EventData.Pairs[18].Value, false) {
				continue
			}
			m := models.LoginLog{}
			m.Status = false
			m.Username = rec.EventData.Pairs[5].Value
			m.Remote = rec.EventData.Pairs[18].Value
			m.Time = rec.TimeCreated.SystemTime.Local().Format("2006-01-02T15:04:05Z07:00")
			resultData = append(resultData, m)
		}
	}

	return resultData
}*/

func DisplayLoginLog(loginLog []models.LoginLog) {
	data := make([][]string, 0)
	for _, item := range loginLog {
		record := make([]string, 0)
		record = append(record, item.Time, item.Username, item.Remote, fmt.Sprintf("%v", item.Status))
		data = append(data, record)
	}

	tableLogin := tablewriter.NewWriter(os.Stdout)
	tableLogin.SetHeader([]string{"time", "username", "remote", "status"})
	tableLogin.SetBorder(true)
	tableLogin.SetRowLine(true)
	// tableLogin.SetAutoMergeCells(true)
	tableLogin.AppendBulk(data)
	tableLogin.SetCaption(true, "login log record")
	tableLogin.Render()
}
