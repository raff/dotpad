package dotpad

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"
)

const (
	GraphicLen = 300
	TextLen    = 20

	GraphicLines = 10 // 10 lines, 1 to 10
	GraphicCells = 30 // 30 cells per lines, 0 to 29

	LP = "0"
	F1 = "1"
	F2 = "2"
	F3 = "3"
	F4 = "4"
	RP = "5"
)

type deviceEntry struct {
	service        bluetooth.DeviceService
	characteristic *bluetooth.DeviceCharacteristic
}

var (
	deviceMapMu sync.Mutex
	deviceMap   = map[bluetooth.Address]*deviceEntry{}
)

type DotPadSDK struct {
	DotPadPrefix         string
	DotPadService        string
	DotPadCharacteristic string

	ackPattern  *regexp.Regexp
	notiPattern *regexp.Regexp
}

func NewDotPadSDK() *DotPadSDK {
	return &DotPadSDK{
		DotPadPrefix:         "DotPad",
		DotPadService:        "49535343-fe7d-4ae5-8fa9-9fafd205e455",
		DotPadCharacteristic: "49535343-1e4d-4bd9-ba61-23c647249616",
		ackPattern:           regexp.MustCompile(`aa550006(..)0201(..)00.*`),
		notiPattern:          regexp.MustCompile(`aa550006(..)0202(..)00.*`),
	}
}

// Request scans for a DotPad device and connects to it.
// The adapter must be enabled before calling this method.
func (s *DotPadSDK) Request(adapter *bluetooth.Adapter, timeout time.Duration) (bluetooth.Device, error) {
	if adapter == nil {
		return bluetooth.Device{}, errors.New("adapter is nil")
	}

	ch := make(chan bluetooth.ScanResult, 1)
	err := adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
		name := result.LocalName()
		if !strings.HasPrefix(name, s.DotPadPrefix) {
			return
		}
		_ = adapter.StopScan()
		select {
		case ch <- result:
		default:
		}
	})
	if err != nil {
		return bluetooth.Device{}, err
	}

	var result bluetooth.ScanResult
	if timeout > 0 {
		select {
		case result = <-ch:
		case <-time.After(timeout):
			_ = adapter.StopScan()
			return bluetooth.Device{}, errors.New("scan timeout")
		}
	} else {
		result = <-ch
	}

	return s.Connect(adapter, result.Address)
}

func (s *DotPadSDK) Connect(adapter *bluetooth.Adapter, addr bluetooth.Address) (bluetooth.Device, error) {
	if adapter == nil {
		return bluetooth.Device{}, errors.New("adapter is nil")
	}
	device, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		return bluetooth.Device{}, err
	}

	serviceUUID, err := bluetooth.ParseUUID(s.DotPadService)
	if err != nil {
		return bluetooth.Device{}, err
	}
	services, err := device.DiscoverServices([]bluetooth.UUID{serviceUUID})
	if err != nil {
		return bluetooth.Device{}, err
	}
	if len(services) == 0 {
		return bluetooth.Device{}, errors.New("dotpad service not found")
	}

	charUUID, err := bluetooth.ParseUUID(s.DotPadCharacteristic)
	if err != nil {
		return bluetooth.Device{}, err
	}
	chars, err := services[0].DiscoverCharacteristics([]bluetooth.UUID{charUUID})
	if err != nil {
		return bluetooth.Device{}, err
	}
	if len(chars) == 0 {
		return bluetooth.Device{}, errors.New("dotpad characteristic not found")
	}

	deviceMapMu.Lock()
	deviceMap[device.Address] = &deviceEntry{service: services[0], characteristic: &chars[0]}
	deviceMapMu.Unlock()

	return device, nil
}

func (s *DotPadSDK) Disconnect(dev bluetooth.Device) error {
	deviceMapMu.Lock()
	delete(deviceMap, dev.Address)
	deviceMapMu.Unlock()
	return dev.Disconnect()
}

func (s *DotPadSDK) DisplayGraphicData(dev bluetooth.Device, hexData string) error {
	return s.DisplayFullData(dev, hexData, "graphic")
}

func (s *DotPadSDK) DisplayGraphicLineData(dev bluetooth.Device, lineID, startCell int, hexData string) error {
	return s.DisplayLineData(dev, lineID, startCell, hexData, "graphic")
}

func (s *DotPadSDK) ResetGraphicData(dev bluetooth.Device) error {
	data := DotPadDataGetResetData(GraphicLen)
	return s.DisplayGraphicData(dev, data)
}

func (s *DotPadSDK) DisplayTextData(dev bluetooth.Device, hexData string) error {
	entry := getDeviceEntry(dev.Address)
	if entry == nil || entry.characteristic == nil {
		return errors.New("device is not connected or characteristic not found")
	}
	wrapped := NewBrailleWordWrap(TextLen, hexData).ToWrapHex()
	DotPadSendModuleSetBrailleWordWrapList(wrapped)
	return DotPadSendModuleSendBrailleWordWrap(entry.characteristic, 1)
}

func (s *DotPadSDK) ResetTextData(dev bluetooth.Device) error {
	entry := getDeviceEntry(dev.Address)
	if entry == nil || entry.characteristic == nil {
		return errors.New("device is not connected or characteristic not found")
	}
	data := DotPadDataGetResetData(TextLen)
	lineData, err := DotPadDataGetRequestLineData(0, 0, data, true)
	if err != nil {
		return err
	}
	_, err = entry.characteristic.WriteWithoutResponse(lineData)
	return err
}

func (s *DotPadSDK) DisplayFullData(dev bluetooth.Device, hexData string, mode string) error {
	entry := getDeviceEntry(dev.Address)
	if entry == nil || entry.characteristic == nil {
		return errors.New("device is not connected or characteristic not found")
	}

	var list [][]byte
	var err error
	switch mode {
	case "graphic":
		list, err = DotPadDataGetRequestData(hexData, false)
	case "text":
		list, err = DotPadDataGetRequestData(hexData, true)
	default:
		return fmt.Errorf("unknown display mode: %s", mode)
	}
	if err != nil {
		return err
	}
	id := 1
	for _, chunk := range list {
		DotPadSendModuleSetSendData(id, chunk, false)
		id++
	}
	return DotPadSendModuleSendNextLine(entry.characteristic)
}

func (s *DotPadSDK) DisplayLineData(dev bluetooth.Device, lineID, startCell int, hexData string, mode string) error {
	entry := getDeviceEntry(dev.Address)
	if entry == nil || entry.characteristic == nil {
		return errors.New("device is not connected or characteristic not found")
	}

	var line []byte
	var err error
	switch mode {
	case "graphic":
		line, err = DotPadDataGetRequestLineData(lineID, startCell, hexData, false)
	case "text":
		line, err = DotPadDataGetRequestLineData(lineID, startCell, hexData, true)
	default:
		return fmt.Errorf("unknown display mode: %s", mode)
	}
	if err != nil {
		return err
	}
	DotPadSendModuleSetSendData(lineID, line, false)
	return DotPadSendModuleSendNextLine(entry.characteristic)
}

func (s *DotPadSDK) AddListenerKeyEvent(dev bluetooth.Device, handler func(code string)) error {
	entry := getDeviceEntry(dev.Address)
	if entry == nil || entry.characteristic == nil {
		return errors.New("device is not connected or characteristic not found")
	}
	return entry.characteristic.EnableNotifications(func(value []byte) {
		noti := NewDotPadNotifyModule(value, entry.characteristic)
		_ = noti.SetAckProcess()
		noti.SetPanningKeyEvent(handler)
		noti.SetFunctionKeyEvent(handler)
	})
}

func getDeviceEntry(addr bluetooth.Address) *deviceEntry {
	deviceMapMu.Lock()
	defer deviceMapMu.Unlock()
	return deviceMap[addr]
}

type DotPadNotifyModule struct {
	ackPattern       *regexp.Regexp
	notiPattern      *regexp.Regexp
	panningKey       string
	functionKey      string
	characteristic   *bluetooth.DeviceCharacteristic
	receiveHexPacket string
}

func NewDotPadNotifyModule(value []byte, characteristic *bluetooth.DeviceCharacteristic) *DotPadNotifyModule {
	return &DotPadNotifyModule{
		ackPattern:       regexp.MustCompile(`aa550006(..)0201(..)00.*`),
		notiPattern:      regexp.MustCompile(`aa550006(..)0202(..)00.*`),
		panningKey:       "aa55000900031200",
		functionKey:      "aa55000900033200",
		characteristic:   characteristic,
		receiveHexPacket: strings.ToLower(hex.EncodeToString(value)),
	}
}

func (n *DotPadNotifyModule) SetAckProcess() error {
	m := n.ackPattern.FindStringSubmatch(n.receiveHexPacket)
	if len(m) > 0 {
		lineID, err := parseHexByte(m[1])
		if err != nil {
			return err
		}
		DotPadSendModuleSetAckData(int(lineID), true)
		return DotPadSendModuleSendNextLine(n.characteristic)
	}
	return nil
}

func (n *DotPadNotifyModule) SetPanningKeyEvent(handler func(code string)) {
	if !strings.HasPrefix(n.receiveHexPacket, n.panningKey) {
		return
	}
	key, err := parseHexNibble(n.receiveHexPacket, 19)
	if err != nil {
		return
	}
	page := DotPadSendModuleWordWrapPageNo()
	total := DotPadSendModuleWordWrapListLen()

	if key == 4 {
		if page > 0 && total > 0 {
			next := page
			if page > 1 {
				next = page - 1
			}
			_ = DotPadSendModuleSendBrailleWordWrap(n.characteristic, next)
		}
		handler("0")
	} else if key == 2 {
		if page > 0 && total > 0 {
			next := page
			if page < total {
				next = page + 1
			}
			_ = DotPadSendModuleSendBrailleWordWrap(n.characteristic, next)
		}
		handler("5")
	}
}

func (n *DotPadNotifyModule) SetFunctionKeyEvent(handler func(code string)) {
	if !strings.HasPrefix(n.receiveHexPacket, n.functionKey) {
		return
	}
	key, err := parseHexNibble(n.receiveHexPacket, 16)
	if err != nil {
		return
	}
	switch key {
	case 8:
		handler("1")
	case 4:
		handler("2")
	case 2:
		handler("3")
	case 1:
		handler("4")
	}
}

type sendEntry struct {
	commandData []byte
	isAck       bool
}

var (
	sendMapMu        sync.Mutex
	sendMapData      = map[int]*sendEntry{}
	sendWordWrapList [][]byte
	wordWrapPageNo   = -1
)

func DotPadSendModuleSetBrailleWordWrapList(list []string) {
	sendWordWrapList = nil
	for _, item := range list {
		line, err := DotPadDataGetRequestLineData(0, 0, item, true)
		if err != nil {
			continue
		}
		sendWordWrapList = append(sendWordWrapList, line)
	}
	wordWrapPageNo = -1
}

func DotPadSendModuleSendBrailleWordWrap(ch *bluetooth.DeviceCharacteristic, page int) error {
	if page <= 0 || page > len(sendWordWrapList) {
		return nil
	}
	wordWrapPageNo = page
	_, err := ch.WriteWithoutResponse(sendWordWrapList[page-1])
	return err
}

func DotPadSendModuleSetSendData(id int, data []byte, isAck bool) {
	sendMapMu.Lock()
	defer sendMapMu.Unlock()
	sendMapData[id] = &sendEntry{commandData: data, isAck: isAck}
}

func DotPadSendModuleSetAckData(id int, isAck bool) {
	sendMapMu.Lock()
	defer sendMapMu.Unlock()
	if entry := sendMapData[id]; entry != nil {
		entry.isAck = isAck
	}
}

func DotPadSendModuleSendNextLine(ch *bluetooth.DeviceCharacteristic) error {
	id := dotPadSendModuleGetNextLineID()
	if id <= -1 {
		return nil
	}
	sendMapMu.Lock()
	entry := sendMapData[id]
	sendMapMu.Unlock()
	if entry == nil {
		return nil
	}
	_, err := ch.WriteWithoutResponse(entry.commandData)
	return err
}

func dotPadSendModuleGetNextLineID() int {
	sendMapMu.Lock()
	defer sendMapMu.Unlock()
	for id, entry := range sendMapData {
		if entry != nil && entry.isAck == false {
			return id
		}
	}
	return -1
}

func DotPadSendModuleWordWrapPageNo() int {
	return wordWrapPageNo
}

func DotPadSendModuleWordWrapListLen() int {
	return len(sendWordWrapList)
}

// DotPadData

func DotPadDataGetResetData(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.Repeat("00", count)
}

func DotPadDataGetRequestData(hexData string, textMode bool) ([][]byte, error) {
	bytes, err := DotDataUtilHexToBytes(hexData)
	if err != nil {
		return nil, err
	}
	chunks := dotPadDataGetRequestDataChunkList(bytes, 30)
	return dotPadDataGetCommandChunkList(chunks, textMode), nil
}

func DotPadDataGetRequestLineData(destID, startCell int, hexData string, textMode bool) ([]byte, error) {
	bytes, err := DotDataUtilHexToBytes(hexData)
	if err != nil {
		return nil, err
	}
	return dotPadDataGetCommandChunkLine(destID, startCell, bytes, textMode), nil
}

func dotPadDataGetRequestDataChunkList(data []byte, size int) [][]byte {
	if size <= 0 {
		return nil
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += size {
		end := i + size
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func dotPadDataGetCommandChunkList(chunks [][]byte, textMode bool) [][]byte {
	var list [][]byte
	id := 1
	for _, chunk := range chunks {
		list = append(list, dotPadDataGetCommandChunkLine(id, 0, chunk, textMode))
		id++
	}
	return list
}

func dotPadDataGetCommandChunkLine(destID, startCell int, data []byte, textMode bool) []byte {
	syncBytes := dotPadProtocolGetSync()
	length := dotPadProtocolGetLength(data)
	dest := dotPadProtocolGetDestID(destID)
	cmd := dotPadProtocolGetCommandType()
	display := dotPadProtocolGetDisplayMode(textMode)
	start := dotPadProtocolGetStartCell(startCell)
	body := dotPadProtocolGetDataBody(data)
	checksum := dotPadProtocolGetCheckSum(dest, cmd, display, start, body)

	out := make([]byte, 0, len(syncBytes)+len(length)+len(dest)+len(cmd)+len(display)+len(start)+len(body)+1)
	out = append(out, syncBytes...)
	out = append(out, length...)
	out = append(out, dest...)
	out = append(out, cmd...)
	out = append(out, display...)
	out = append(out, start...)
	out = append(out, body...)
	out = append(out, checksum)
	return out
}

// DotPadProtocol

func dotPadProtocolGetSync() []byte {
	return []byte{0xAA, 0x55}
}

func dotPadProtocolGetLength(body []byte) []byte {
	return []byte{0x00, byte(len(body) + 6)}
}

func dotPadProtocolGetDestID(id int) []byte {
	return []byte{byte(id)}
}

func dotPadProtocolGetCommandType() []byte {
	return []byte{0x02, 0x00}
}

func dotPadProtocolGetDisplayMode(textMode bool) []byte {
	if textMode {
		return []byte{0x80}
	}
	return []byte{0x00}
}

func dotPadProtocolGetStartCell(start int) []byte {
	return []byte{byte(start)}
}

func dotPadProtocolGetDataBody(data []byte) []byte {
	return data
}

func dotPadProtocolGetCheckSum(dest, cmd, display, start, body []byte) byte {
	x := byte(0xA5)
	for _, b := range dest {
		x ^= b
	}
	for _, b := range cmd {
		x ^= b
	}
	for _, b := range display {
		x ^= b
	}
	for _, b := range start {
		x ^= b
	}
	for _, b := range body {
		x ^= b
	}
	return x
}

// DotDataUtil

func DotDataUtilBytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func DotDataUtilBytesToHexList(data []byte) []string {
	out := make([]string, len(data))
	for i, b := range data {
		out[i] = fmt.Sprintf("%02x", b)
	}
	return out
}

func DotDataUtilDecimalToHex(value int) string {
	return fmt.Sprintf("%02x", value)
}

func DotDataUtilHexToBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return nil, errors.New("odd number of hex digits")
	}
	out, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("expected hex string")
	}
	return out, nil
}

// BrailleWordWrap

type BrailleWordWrap struct {
	cellSizeHex    int
	brailleHexData string
}

func NewBrailleWordWrap(cellSize int, brailleHexData string) *BrailleWordWrap {
	return &BrailleWordWrap{
		cellSizeHex:    2 * cellSize,
		brailleHexData: brailleHexData,
	}
}

func (b *BrailleWordWrap) ToWrapHex() []string {
	segments := b.processHexData()
	return b.generateWrappedHexList(segments)
}

func (b *BrailleWordWrap) processHexData() []string {
	const doubleZero = "00"
	trimmed := strings.TrimSpace(b.brailleHexData)
	endsWithDoubleZero := strings.HasSuffix(trimmed, doubleZero)
	parts := strings.Split(trimmed, doubleZero)

	out := make([]string, len(parts))
	for i := 0; i < len(parts); i++ {
		out[i] = strings.ReplaceAll(parts[i], " ", "") + doubleZero
	}
	if !endsWithDoubleZero && len(out) > 0 {
		last := len(out) - 1
		out[last] = b.removeTrailingDoubleZero(out[last])
	}
	return out
}

func (b *BrailleWordWrap) generateWrappedHexList(parts []string) []string {
	var result []string
	var segment []string
	for _, part := range parts {
		b.appendDataToSegment(part, &segment, &result)
	}
	if len(segment) > 0 {
		result = append(result, b.padSegment(strings.Join(segment, "")))
	}
	return result
}

func (b *BrailleWordWrap) appendDataToSegment(part string, segment *[]string, result *[]string) {
	if len(strings.Join(*segment, ""))+len(part) > b.cellSizeHex {
		if len(*segment) > 0 {
			*result = append(*result, b.padSegment(strings.Join(*segment, "")))
			*segment = (*segment)[:0]
		}
	}
	*segment = append(*segment, part)
}

func (b *BrailleWordWrap) padSegment(s string) string {
	for len(s) < b.cellSizeHex {
		s += "0"
	}
	return s
}

func (b *BrailleWordWrap) removeTrailingDoubleZero(s string) string {
	if len(s) < 2 {
		return s
	}
	return s[:len(s)-2]
}

func (b *BrailleWordWrap) AddSpacesBetweenEveryTwoCharacters(list []string) string {
	joined := strings.Join(list, "")
	var parts []string
	for i := 0; i < len(joined); i += 2 {
		if i > 0 {
			parts = append(parts, " ")
		}
		end := i + 2
		if end > len(joined) {
			end = len(joined)
		}
		parts = append(parts, joined[i:end])
	}
	return strings.Join(parts, "")
}

func parseHexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, errors.New("expected 2 hex chars")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1 {
		return 0, errors.New("invalid hex byte")
	}
	return b[0], nil
}

func parseHexNibble(packet string, idx int) (int, error) {
	if idx < 0 || idx >= len(packet) {
		return 0, errors.New("index out of range")
	}
	value, err := strconvParseHex(packet[idx : idx+1])
	if err != nil {
		return 0, err
	}
	return value, nil
}

func strconvParseHex(s string) (int, error) {
	val, err := strconv.ParseInt(s, 16, 8)
	if err != nil {
		return 0, err
	}
	return int(val), nil
}
