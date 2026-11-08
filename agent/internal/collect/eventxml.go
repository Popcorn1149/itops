package collect

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"itops/agent/pkg/protocol"
)

// Cấu trúc XML của một sự kiện Windows (EvtRender) – tách riêng để test được trên mọi hệ điều hành.
type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		RecordID string `xml:"EventRecordID"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner struct {
			Items []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
}

var levelName = map[string]string{"1": "critical", "2": "error", "3": "warning", "4": "info", "0": "info", "5": "verbose"}

// ParseEventXML: XML sự kiện → protocol.Event. Data không có tên được đặt param1, param2… (như Event Viewer).
func ParseEventXML(s string) (protocol.Event, bool) {
	var x xmlEvent
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return protocol.Event{}, false
	}
	id, err := strconv.Atoi(strings.TrimSpace(x.System.EventID))
	if err != nil {
		return protocol.Event{}, false
	}
	rec, _ := strconv.ParseInt(strings.TrimSpace(x.System.RecordID), 10, 64)
	ts, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	if err != nil {
		ts = time.Now().UTC()
	}
	data := map[string]string{}
	for i, d := range x.EventData.Data {
		k := d.Name
		if k == "" {
			k = "param" + strconv.Itoa(i+1)
		}
		data[k] = strings.TrimSpace(d.Value)
	}
	for _, it := range x.UserData.Inner.Items {
		data[it.XMLName.Local] = strings.TrimSpace(it.Value)
	}
	return protocol.Event{Channel: x.System.Channel, Provider: x.System.Provider.Name, EventID: id,
		Level: levelName[strings.TrimSpace(x.System.Level)], RecordID: rec, TS: ts.UTC(), Data: data}, true
}

// buildXPath: truy vấn event log Windows – chỉ các Event ID trong chính sách, từ sau mốc đã đọc.
func buildXPath(ids []int, bookmark int64, backfillHours int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = "EventID=" + strconv.Itoa(id)
	}
	cond := "(" + strings.Join(parts, " or ") + ")"
	if bookmark > 0 {
		cond += fmt.Sprintf(" and EventRecordID > %d", bookmark)
	} else {
		cond += fmt.Sprintf(" and TimeCreated[timediff(@SystemTime) <= %d]", int64(backfillHours)*3600*1000)
	}
	return "*[System[" + cond + "]]"
}
