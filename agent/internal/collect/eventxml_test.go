package collect

import "testing"

// Mẫu XML đúng định dạng EvtRender(EvtRenderEventXml) của Windows.
const x4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-11-08T03:12:44.1234567Z'/><EventRecordID>184467</EventRecordID><Correlation ActivityID='{0}'/><Execution ProcessID='812' ThreadID='9020'/><Channel>Security</Channel><Computer>PC-KT01.cty.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>lan.nt</Data><Data Name='TargetDomainName'>CTY</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>10</Data><Data Name='WorkstationName'>PC-LA</Data><Data Name='IpAddress'>10.10.9.99</Data></EventData></Event>`

const x1102 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-08T04:00:00.0000000Z'/><EventRecordID>5</EventRecordID><Channel>Security</Channel><Computer>PC</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>hacker</SubjectUserName><SubjectDomainName>CTY</SubjectDomainName></LogFileCleared></UserData></Event>`

const x7031 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='49152'>7031</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-08T05:00:00.5Z'/><EventRecordID>9001</EventRecordID><Channel>System</Channel><Computer>PC</Computer></System><EventData><Data Name='param1'>Print Spooler</Data><Data Name='param2'>1</Data></EventData></Event>`

const xDisk = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Disk'/><EventID Qualifiers='49156'>7</EventID><Level>2</Level><TimeCreated SystemTime='2026-11-08T05:00:00Z'/><EventRecordID>42</EventRecordID><Channel>System</Channel><Computer>PC</Computer></System><EventData><Data>\Device\Harddisk0\DR0</Data><Binary>0300</Binary></EventData></Event>`

func TestParseEventXML(t *testing.T) {
	e, ok := ParseEventXML(x4625)
	if !ok || e.EventID != 4625 || e.RecordID != 184467 || e.Channel != "Security" || e.Provider != "Microsoft-Windows-Security-Auditing" {
		t.Fatalf("4625 sai: %+v", e)
	}
	if e.Data["TargetUserName"] != "lan.nt" || e.Data["IpAddress"] != "10.10.9.99" || e.Data["SubStatus"] != "0xc000006a" {
		t.Fatalf("EventData sai: %v", e.Data)
	}
	if e.TS.Format("15:04:05") != "03:12:44" {
		t.Fatalf("giờ sai %v", e.TS)
	}
	e, ok = ParseEventXML(x1102)
	if !ok || e.Data["SubjectUserName"] != "hacker" || e.Provider != "Microsoft-Windows-Eventlog" {
		t.Fatalf("UserData sai: %+v", e)
	}
	e, ok = ParseEventXML(x7031)
	if !ok || e.EventID != 7031 || e.Data["param1"] != "Print Spooler" || e.Level != "error" {
		t.Fatalf("7031 (EventID có Qualifiers) sai: %+v", e)
	}
	e, ok = ParseEventXML(xDisk)
	if !ok || e.Data["param1"] != `\Device\Harddisk0\DR0` {
		t.Fatalf("Data không tên phải thành param1: %+v", e.Data)
	}
	if _, ok := ParseEventXML("<rac>"); ok {
		t.Fatal("XML hỏng phải bị bỏ")
	}
}

func TestBuildXPath(t *testing.T) {
	if got := buildXPath([]int{4625, 4740}, 123, 24); got != "*[System[(EventID=4625 or EventID=4740) and EventRecordID > 123]]" {
		t.Fatal(got)
	}
	if got := buildXPath([]int{41}, 0, 2); got != "*[System[(EventID=41) and TimeCreated[timediff(@SystemTime) <= 7200000]]]" {
		t.Fatal(got)
	}
}
