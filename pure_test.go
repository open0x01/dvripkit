package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	// testDVRIPRealm 是设备 challenge 里 "Realm:" 之后的**原文**, 含
	// "Login to " 前缀。NetSDK 拼 HA1 时用的就是这一整段, 剥掉前缀算出来的
	// 摘要设备不认。
	testDVRIPRealm  = "Login to TEST"
	testDVRIPRandom = "0123456789ABCDEF"
	// 由已验证的 DVRIP 哈希公式对 admin/admin123 + 上述 realm/random 算出。
	testDVRIPHash = "admin&&739D0CEED89B505B9B0996EEECDDEE35B3A15AC81A4D62B11F1EBE73260D9180"
)

type dvripTestRequest struct {
	command uint32
	magic   uint64
	body    []byte
}

func TestDahuaGen1Hash(t *testing.T) {
	if got := dahuaGen1Hash("admin123"); got != "Ny2SRZzv" {
		t.Fatalf("dahuaGen1Hash(admin123) = %q, want Ny2SRZzv", got)
	}
}

func TestDVRIPLoginHash(t *testing.T) {
	if got := dvripLoginHash("admin", "admin123", testDVRIPRealm, testDVRIPRandom); got != testDVRIPHash {
		t.Fatalf("dvripLoginHash() = %q, want %q", got, testDVRIPHash)
	}
}

// TestDVRIPLoginHashGroundTruth 用真机/改写代理抓到的 NetSDK 实际登录体
// 逐条校验哈希公式。
//
// 这些期望值是 NetSDK 自己算出来并发给设备的字节(经 TCP 代理抓包),
// 覆盖 2 个口令 / 3 个 realm / 3 个 random。realm 一律是设备 challenge 的
// 原文(含 "Login to " 前缀)。
func TestDVRIPLoginHashGroundTruth(t *testing.T) {
	cases := []struct {
		user, pass, realm, random, want string
	}{
		// 改写代理(固定 realm/random)抓到的 NetSDK 登录体。
		{"admin", "admin123", "Login to AAAABBBBCCCCDDDD", "0123456789a",
			"admin&&6B737D383E957CA607DB9FABC000A7FBE4692C3BBEADA75C5A5B0BF504B5E38C"},
		{"admin", "admin123", "Login to 1111111111111111", "0123456789a",
			"admin&&E963438A5DF9B77471BF0E042DE43D35E4692C3BBEADA75C5A5B0BF504B5E38C"},
		{"admin", "admin123", "Login to AAAABBBBCCCCDDDD", "9999999999z",
			"admin&&48C0EBE92A4BC24F71F2CA54461BB27F18851E43C26F38FBB9FC8C0D304613BF"},
		{"admin", "wrongpw", "Login to AAAABBBBCCCCDDDD", "0123456789a",
			"admin&&7030D23F7B65CB9C8018554711087358A4E5B6278A3382029E07A78ED1194DDA"},

		// 真机上抓到的 NetSDK 登录体。
		{"admin", "admin123", "Login to 107FF8439AEE329B", "3293389030d",
			"admin&&C9759CDC23D89732A1AB3BA1FD3A3DED4A6E938CA2802F66922F0FBA66C8A0A4"},
		{"admin", "admin123", "Login to 107FF8439AEE329B", "771282815d",
			"admin&&C662DC815EACF0D1CB56F7E01C9397A155A5087F7ACACBA6B96234AAC59CC68F"},
		{"admin", "wrongpass", "Login to 107FF8439AEE329B", "75479003d",
			"admin&&78481368A7E0E02141D3E3C23E26364DB4F1809432F0D2045659B52144B7C154"},
		{"admin", "admin123", "Login to 107FF8439AEE329B", "548277357d",
			"admin&&A2C9527614F18EAD5FBBFF2C239B4690B4891C25D88665DE9BA3192C361FB8D6"},
	}
	for _, c := range cases {
		got := dvripLoginHash(c.user, c.pass, c.realm, c.random)
		if got != c.want {
			t.Errorf("dvripLoginHash(%q, %q, %q, %q)\n got %q\nwant %q",
				c.user, c.pass, c.realm, c.random, got, c.want)
		}
	}
}

// TestParseDVRIPRealmKeepsLoginPrefix 保证 realm 保留 "Login to " 前缀。
//
// 剥掉前缀会导致 HA1 输入与 NetSDK 不一致, 设备必然拒绝登录。
func TestParseDVRIPRealmKeepsLoginPrefix(t *testing.T) {
	body := []byte("Realm:Login to 107FF8439AEE329B\r\nRandom:3293389030d\r\n\r\n")
	realm, random, ok := parseDVRIPRealm(body)
	if !ok {
		t.Fatal("parseDVRIPRealm returned !ok")
	}
	if realm != "Login to 107FF8439AEE329B" {
		t.Fatalf("realm = %q, want %q", realm, "Login to 107FF8439AEE329B")
	}
	if random != "3293389030d" {
		t.Fatalf("random = %q, want %q", random, "3293389030d")
	}
}

func TestParseDVRIPRealm(t *testing.T) {
	body := []byte("Realm:Login to TEST\r\nSome-Header: value\r\nRandom:" + testDVRIPRandom + "\r\n\r\n")
	realm, random, ok := parseDVRIPRealm(body)
	if !ok {
		t.Fatal("parseDVRIPRealm returned !ok")
	}
	if realm != testDVRIPRealm {
		t.Fatalf("realm = %q, want %q", realm, testDVRIPRealm)
	}
	if random != testDVRIPRandom {
		t.Fatalf("random = %q, want %q", random, testDVRIPRandom)
	}
}

func TestDVRIPLoginSuccess(t *testing.T) {
	port, requests, done := startDVRIPServer(t, 0x0008, 0)
	r := Scan(Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "admin123",
		Timeout:  2 * time.Second,
	})
	if !r.Success || r.Locked || r.Unreachable {
		t.Fatalf("Scan() = %+v, want success", r)
	}

	reqs := <-requests
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	if reqs[0].command != dvripRealmCommand || reqs[0].magic != dvripRealmMagic {
		t.Fatalf("realm request command=%#x magic=%#x", reqs[0].command, reqs[0].magic)
	}
	if reqs[1].command != dvripLoginCommand || reqs[1].magic != dvripLoginMagic {
		t.Fatalf("login request command=%#x magic=%#x", reqs[1].command, reqs[1].magic)
	}
	if got := string(reqs[1].body); got != testDVRIPHash {
		t.Fatalf("login hash = %q, want %q", got, testDVRIPHash)
	}
	<-done
}

func TestDVRIPLoginWrongPassword(t *testing.T) {
	port, _, done := startDVRIPServer(t, 0x0100, 3)
	r := Scan(Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "bad",
		Timeout:  2 * time.Second,
	})
	if r.Success || r.Locked || r.Unreachable {
		t.Fatalf("Scan() = %+v, want ordinary auth failure", r)
	}
	<-done
}

func TestDVRIPLoginLocked(t *testing.T) {
	port, _, done := startDVRIPServer(t, 0x0104, 0)
	r := Scan(Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "bad",
		Timeout:  2 * time.Second,
	})
	if r.Success || !r.Locked || r.Unreachable {
		t.Fatalf("Scan() = %+v, want locked", r)
	}
	if !strings.Contains(r.StopReason, "锁定") {
		t.Fatalf("StopReason = %q, want 锁定原因", r.StopReason)
	}
	<-done
}

func TestDVRIPLoginUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	target := Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "admin123",
		Timeout:  300 * time.Millisecond,
	}

	// 单次连接失败只算"这次没打中":引擎继续跑该设备剩余字典,
	// 连续失败达阈值才判不可达,避免一次网络抖动丢掉整台设备。
	for i := 1; i < unreachableThreshold; i++ {
		r := Scan(target)
		if r.Unreachable || r.Success || r.Locked {
			t.Fatalf("第 %d 次连接失败 Scan() = %+v, 不应判不可达", i, r)
		}
	}
	r := Scan(target)
	if !r.Unreachable || r.Success || r.Locked {
		t.Fatalf("连续 %d 次连接失败 Scan() = %+v, want unreachable", unreachableThreshold, r)
	}

	// 计数按设备归集:换端口即换设备,不受上面的计数影响。
	ClearDeviceState()
	r = Scan(target)
	if r.Unreachable {
		t.Fatalf("ClearDeviceState 后 Scan() = %+v, 不应判不可达", r)
	}
}

// 设备回瞬态错误(0x0107 连接超时)按连接失败累计,连续达阈值判不可达。
func TestDVRIPLoginTransientDeviceError(t *testing.T) {
	port, _, done := startDVRIPServer(t, 0x0107, 0)
	target := Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "admin123",
		Timeout:  2 * time.Second,
	}

	// 第一次拿到设备的瞬态错误,按连接失败计一次,仍不判不可达。
	r := Scan(target)
	if r.Success || r.Locked || r.Unreachable {
		t.Fatalf("瞬态错误 Scan() = %+v, want 普通失败", r)
	}
	// mock server 只服务一次连接,后续都是连接失败,累计到阈值后判不可达。
	for i := 0; i < unreachableThreshold && !r.Unreachable; i++ {
		r = Scan(target)
	}
	if !r.Unreachable {
		t.Fatalf("连续连接失败 Scan() = %+v, want unreachable", r)
	}
	<-done
}

// 设备回锁定错误(0x0104)时立即停止该设备剩余字典,不计入连接失败阈值。
func TestDVRIPLoginLockedNotCountedAsUnreachable(t *testing.T) {
	port, _, done := startDVRIPServer(t, 0x0104, 0)
	target := Target{
		Ip:       "127.0.0.1",
		Port:     uint(port),
		Username: "admin",
		Password: "bad",
		Timeout:  2 * time.Second,
	}
	r := Scan(target)
	if !r.Locked || r.Success || r.Unreachable {
		t.Fatalf("锁定响应 Scan() = %+v, want locked", r)
	}
	if r.StopReason == "" {
		t.Fatal("锁定响应应带停止原因")
	}
	<-done
}

// startDVRIPServer accepts one connection and answers the realm and login
// requests. The login reply carries loginCode in the error-code field.
func startDVRIPServer(t *testing.T, loginCode uint16, triesLeft uint16) (port int, requests <-chan []dvripTestRequest, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = ln.Addr().(*net.TCPAddr).Port
	reqCh := make(chan []dvripTestRequest, 1)
	doneCh := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(doneCh)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

		realmReq, err := readTestDVRIPRequest(conn)
		if err != nil {
			errCh <- err
			return
		}
		// 真机实测的 challenge 响应体格式: "Realm:" 和 "Random:" 两行。
		realmBody := "Realm:" + testDVRIPRealm + "\r\nRandom:" + testDVRIPRandom + "\r\n\r\n"
		if err := writeTestDVRIPResponse(conn, nil, []byte(realmBody), 0, 0); err != nil {
			errCh <- err
			return
		}

		loginReq, err := readTestDVRIPRequest(conn)
		if err != nil {
			errCh <- err
			return
		}
		if err := writeTestDVRIPResponse(conn, nil, nil, loginCode, triesLeft); err != nil {
			errCh <- err
			return
		}
		reqCh <- []dvripTestRequest{realmReq, loginReq}
	}()

	t.Cleanup(func() {
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("mock DVRIP server: %v", err)
			}
		default:
		}
	})
	return port, reqCh, doneCh
}

func readTestDVRIPRequest(r io.Reader) (dvripTestRequest, error) {
	var req dvripTestRequest
	header := make([]byte, dvripHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return req, err
	}
	req.command = binary.BigEndian.Uint32(header[0:4])
	// 真机实测: body 长度在 offset 4, 小端。
	n := binary.LittleEndian.Uint32(header[4:8])
	if n > dvripMaxBody {
		return req, fmt.Errorf("request body too large: %d", n)
	}
	req.magic = binary.BigEndian.Uint64(header[24:32])
	if n > 0 {
		req.body = make([]byte, n)
		if _, err := io.ReadFull(r, req.body); err != nil {
			return req, err
		}
	}
	return req, nil
}

func writeTestDVRIPResponse(w io.Writer, header []byte, body []byte, code uint16, triesLeft uint16) error {
	if header == nil {
		header = make([]byte, dvripHeaderLen)
		header[0] = 0xb0
		header[1] = 0x00
		// 真机实测: body 长度在 offset 4, 小端; 错误码在 offset 8-9, 大端。
		binary.LittleEndian.PutUint32(header[4:8], uint32(len(body)))
		binary.BigEndian.PutUint16(header[8:10], code)
		binary.BigEndian.PutUint16(header[28:30], triesLeft)
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}
