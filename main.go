// Command dvripkit 验证大华 DVRIP 纯 Go 登录能否认证成功。
//
// 这是一个独立的验证程序, 不接入主扫描流程:
//   - 不加载 NetSDK 或任何 so 资产, 全部逻辑在纯 Go 里;
//   - 走 DVRIP 二进制流程(A0 05 取 challenge + A0 05 登录), 该流程的
//     报文与哈希公式已在 8 组真机抓包上逐字节复现;
//   - 默认只跑本地假设备的离线用例。
//
// 用法:
//
//	# 离线自测(不碰任何真实目标)
//	go test . -v
//
//	# 真机: 经典 DVRIP 二进制流程(位置参数 / 短选项 / 长选项均可)
//	go run . 192.168.1.108 admin admin123
//	go run . -t 192.168.1.108:37777 -u admin -p admin123
//	go run . -target 192.168.1.108:37777 -user admin -pass admin123
//
// Pure Go implementation of the Dahua DVRIP login handshake (TCP 37777).
//
// The handshake is:
//
//  1. send an A0 05 realm/challenge request (32-byte header, empty body);
//  2. device returns a "Realm:Login to <realm>" / "Random:<random>" text body;
//  3. derive the DVRIP hash from username, password, realm and random;
//  4. send an A0 05 login request and inspect the error code in the reply.
//
// No NetSDK shared library is loaded by this file.
//
// The framing below was recovered byte-for-byte from NetSDK traffic against a
// real device (captured through a TCP proxy), so a pure Go client produces
// exactly the same bytes on the wire as libdhnetsdk does.
package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dvripHeaderLen = 32
	dvripMaxBody   = 1 << 20

	// dvripRealmCommand / dvripLoginCommand 是请求头 offset 0-3 的命令字。
	//
	// 真机抓包(NetSDK 经 TCP 代理打到真设备)实测: 取 challenge 和登录
	// **用的是同一个命令字** 0xa0050060, 没有"A0 01 取 realm"这一步。
	// 之前写成 0xa0010000 时设备根本不回 challenge, 登录必然失败。
	dvripRealmCommand = 0xa0050060
	dvripLoginCommand = 0xa0050060

	// dvripRealmMagic / dvripLoginMagic 是请求头 offset 24-31。
	//
	// 实测: 末 4 字节恒为 0x0000a1aa, offset 24-27 的 "04 02 00 01" 是
	// challenge、"04 02 00 08" 是登录(即 8 = 登录态标志)。
	dvripRealmMagic = 0x040200010000a1aa
	dvripLoginMagic = 0x040200080000a1aa

	dvripDefaultPort    = 37777
	dvripDefaultTimeout = 5 * time.Second

	// LoginDefaultPort 是大华私有协议默认端口(对外暴露名)。
	LoginDefaultPort = dvripDefaultPort

	// dvripLoginOK 是 A0 05 登录响应里的成功码。
	dvripLoginOK = 0x0008
	// dvripErrFlag 是登录错误码的高位标志:0x01xx 的低位是"相对 NetSDK
	// lastErr 码 100 的偏移"(0x0104→104 账号锁定),换算后可以复用
	// ClassifyCode 做三态划分。
	dvripErrFlag = 0x0100
	// dvripErrBase 是 DVRIP 错误码低字节到 NetSDK lastErr 码的偏移基数。
	dvripErrBase = 100
)

// Target is one login check.
type Target struct {
	Ip       string
	Port     uint
	Username string
	Password string
	Timeout  time.Duration
}

// Result is the outcome of a DVRIP login check.
type Result struct {
	Success     bool
	Locked      bool
	StopReason  string
	Unreachable bool
}

// version 由构建时通过 -ldflags "-X main.version=v0.1.0" 注入, 源码默认为 dev。
var version = "dev"

// ---------- 命令行入口 ----------

// usage 打印用法。短选项与位置参数是长选项的便捷写法, 三者优先级为:
// 长选项 > 短选项 > 位置参数 > 环境变量。
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprint(out, `dvripkit - 大华 DVRIP 登录校验器 (纯 Go)

用法:
  dvripkit <target> [user] [pass]
  dvripkit -t <target> -u <user> -p <pass>
  dvripkit -target <target> -user <user> -pass <pass>

示例:
  dvripkit 192.168.1.108 admin admin123
  dvripkit -t 192.168.1.108:37777 -u admin -p admin123
  dvripkit -v

选项:
`)
	flag.PrintDefaults()
}

func main() {
	var (
		target  = flag.String("target", os.Getenv("DAHUA_DVRIP_TARGET"), "目标地址 host 或 host:port")
		user    = flag.String("user", os.Getenv("DAHUA_DVRIP_USER"), "用户名")
		pass    = flag.String("pass", os.Getenv("DAHUA_DVRIP_PASS"), "密码")
		timeout = flag.Int("timeout", 5, "单次连接超时(秒)")
		showVer = flag.Bool("version", false, "打印版本号后退出")

		// 短选项。与长选项分开注册, 避免默认值互相覆盖。
		shortTarget = flag.String("t", "", "同 -target")
		shortUser   = flag.String("u", "", "同 -user")
		shortPass   = flag.String("p", "", "同 -pass")
		shortVer    = flag.Bool("v", false, "同 -version")
	)
	flag.Usage = usage
	flag.Parse()

	// 位置参数: dvripkit <target> [user] [pass]。
	// flag 包在遇到第一个非选项参数时停止解析, 因此位置参数必须写在选项之后。
	args := flag.Args()
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	pick := func(long, short string, longVal *string, shortVal string, pos int) string {
		switch {
		case set[long]:
			return *longVal
		case set[short]:
			return shortVal
		case pos < len(args):
			return args[pos]
		default:
			return *longVal // 环境变量默认值或空串
		}
	}

	targetVal := pick("target", "t", target, *shortTarget, 0)
	userVal := pick("user", "u", user, *shortUser, 1)
	passVal := pick("pass", "p", pass, *shortPass, 2)

	if *showVer || *shortVer {
		fmt.Printf("dvripkit %s\n", version)
		return
	}

	if strings.TrimSpace(targetVal) == "" {
		fmt.Fprintln(os.Stderr, "缺少目标地址: dvripkit <target> [user] [pass] 或 -t/-target")
		usage()
		os.Exit(2)
	}
	if strings.TrimSpace(userVal) == "" {
		fmt.Fprintln(os.Stderr, "缺少用户名: 或 -u/-user")
		usage()
		os.Exit(2)
	}

	host, port := splitTarget(targetVal)
	tmo := time.Duration(*timeout) * time.Second

	fmt.Printf("==> DVRIP 二进制流程 %s:%d user=%s\n", host, port, userVal)
	r := Scan(Target{
		Ip:       host,
		Port:     uint(port),
		Username: userVal,
		Password: passVal,
		Timeout:  tmo,
	})
	switch {
	case r.Success:
		fmt.Println("结果: 认证成功")
	case r.Locked:
		fmt.Printf("结果: 账号锁定/禁止登录 (%s)\n", r.StopReason)
	case r.Unreachable:
		fmt.Println("结果: 设备不可达(连续连接失败达阈值)")
	default:
		fmt.Println("结果: 认证失败(口令错或用户不存在)")
	}
}

// splitTarget 拆 host[:port], 端口缺省 37777。
func splitTarget(target string) (string, int) {
	target = strings.TrimSpace(target)
	host, portStr, found := strings.Cut(target, ":")
	if !found {
		return host, LoginDefaultPort
	}
	port := LoginDefaultPort
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 {
		port = LoginDefaultPort
	}
	return host, port
}

// ---------- 登录检查 ----------

// Available reports whether the in-process Go implementation can be used.
// It is always available: there is no worker binary or shared library to locate.
func Available() (bool, string) {
	return true, ""
}

// Scan performs a Dahua DVRIP login check without loading NetSDK.
//
// Success means the device accepted the username/password. A failed login is
// returned as Success=false, Locked=false and is not treated as unreachable.
//
// Transport failures (dial/write/read) are counted per device: only after
// unreachableThreshold consecutive failures is the device reported as
// Unreachable, so a single network hiccup does not silently drop the rest of
// the dictionary for that device.
func Scan(t Target) Result {
	ip := strings.TrimSpace(t.Ip)
	if ip == "" {
		return Result{}
	}
	port := t.Port
	if port == 0 {
		port = dvripDefaultPort
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = dvripDefaultTimeout
	}

	key := fmt.Sprintf("%s:%d", ip, port)
	result, transportFailed := scanOnce(ip, port, t.Username, t.Password, timeout)
	if transportFailed {
		if recordConnectFail(key) {
			return Result{Unreachable: true}
		}
		return Result{}
	}
	// 设备有响应即视为在线,清零连续连接失败计数。
	resetConnectFail(key)
	return result
}

// scanOnce 执行一次完整的 DVRIP 登录握手。
//
// 第二个返回值为 true 表示失败发生在传输层(拨号/读写),调用方据此累计
// 设备级连接失败计数;协议层的失败(口令错/锁定)不算连接失败。
func scanOnce(ip string, port uint, username, password string, timeout time.Duration) (Result, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return Result{}, true
	}
	defer conn.Close()

	// One deadline covers the two request/response exchanges. This mirrors the
	// SDK's per-login timeout closely enough for a credential check and avoids
	// a half-open device holding a worker slot for an unbounded time.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	realm, random, ok, err := requestDVRIPChallenge(conn)
	if err != nil {
		return Result{}, true
	}
	if !ok {
		return Result{}, false
	}

	hash := dvripLoginHash(username, password, realm, random)
	if err := writeDVRIPRequest(conn, dvripLoginCommand, []byte(hash), dvripLoginMagic); err != nil {
		return Result{}, true
	}
	loginHeader, loginBody, err := readDVRIPResponse(conn)
	if err != nil {
		return Result{}, true
	}
	if !isDVRIPResponse(loginHeader) {
		return Result{}, false
	}

	res, transient := classifyLoginResponse(binary.BigEndian.Uint16(loginHeader[8:10]))
	// 设备在锁定时会额外回 "LockLeftTime:NNN", 把它带进 StopReason,
	// 便于上层知道还要等多久。
	if res.Locked {
		if sec := parseLockLeftTime(loginBody); sec > 0 {
			res.StopReason = fmt.Sprintf("%s(剩余%v秒)", res.StopReason, sec)
		}
	}
	return res, transient
}

// parseLockLeftTime 从响应体里取 "LockLeftTime:NNN" 的秒数。
//
// 真机实测响应体形如 "LockLeftTime:235\r\n"。
func parseLockLeftTime(body []byte) int {
	s := string(body)
	i := strings.Index(s, "LockLeftTime:")
	if i < 0 {
		return 0
	}
	rest := s[i+len("LockLeftTime:"):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}

// classifyLoginResponse 把 A0 05 响应里的错误码映射成结果。
//
// 真机实测: 响应头 offset 8-9 是 DVRIP 错误码, 高位 0x01 是"错误"标志,
// 低位是**相对 NetSDK lastErr 码 100 的偏移**:
//   - 0x0100 → 100 口令错   (实测: 口令错误时返回 0x0100)
//   - 0x0104 → 104 账号锁定 (实测: 账号被锁时返回 0x0104, body 附带
//     "LockLeftTime:NNN")
//   - 0x0101 → 101 用户不存在, 0x0105 → 105 黑名单, 0x0107 → 107 连接超时,
//     0x0108 → 108 网络连接失败, 0x010A → 110 连接数超限, 0x010D → 113 IP
//     无权限, 0x0112 → 118 未初始化。
//
// 换算成 NetSDK 码后复用 ClassifyCode 做三态划分:
//   - 锁定类(104/105/113/118):停止该设备剩余字典;
//   - 瞬态类(107/108/110 等):按连接失败累计,连续失败达阈值判不可达;
//   - 其余(100 口令错、101 用户不存在等):普通失败,继续跑字典。
func classifyLoginResponse(code uint16) (Result, bool) {
	if code == dvripLoginOK {
		return Result{Success: true}, false
	}
	if code&0xff00 != dvripErrFlag {
		// 非 0x01xx 的码(未初始化/未实现/已登录等)按普通失败处理。
		return Result{}, false
	}

	sdkCode := int32(code&0xff) + dvripErrBase
	switch ClassifyCode(sdkCode) {
	case AttemptLocked:
		return Result{Locked: true, StopReason: fmt.Sprintf("设备账号锁定/禁止登录(nError=%d)", sdkCode)}, false
	case AttemptTransient:
		// 设备明确回了连接类错误,等价于这次连接失败。
		return Result{}, true
	default:
		return Result{}, false
	}
}

// ---------- 报文编解码 ----------

// requestDVRIPChallenge 发一条取 challenge 的请求, 并读回 realm/random。
//
// challenge 请求与 NetSDK 逐字节一致: 命令字 0xa0050060, header[8:24] 填
// 16 字节随机数, body 为空。
func requestDVRIPChallenge(conn net.Conn) (realm, random string, ok bool, err error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", false, err
	}
	if err := writeDVRIPRequestNonce(conn, dvripRealmCommand, nil, dvripRealmMagic, nonce); err != nil {
		return "", "", false, err
	}
	header, body, err := readDVRIPResponse(conn)
	if err != nil {
		return "", "", false, err
	}
	if !isDVRIPResponse(header) {
		return "", "", false, nil
	}
	realm, random, ok = parseDVRIPRealm(body)
	if !ok {
		return "", "", false, nil
	}
	return realm, random, true, nil
}

// writeDVRIPRequest 写一条 DVRIP 请求。
//
// 字节序是实测出来的: 设备按**小端**读 body 长度(真机响应头 offset 4 的
// "37 00 00 00" 即 55 字节)。命令字按大端写, 长度按小端写。
//
// header[8:24] 是 16 字节的会话随机区: 取 challenge 时 NetSDK 会填随机
// 字节(实测每次连接都不同), 发登录时填全 0。
func writeDVRIPRequest(w io.Writer, command uint32, body []byte, magic uint64) error {
	return writeDVRIPRequestNonce(w, command, body, magic, nil)
}

// writeDVRIPRequestNonce 同 writeDVRIPRequest, 但可指定 header[8:24] 的
// 16 字节会话随机区。nonce 为 nil 时该区域填 0。
func writeDVRIPRequestNonce(w io.Writer, command uint32, body []byte, magic uint64, nonce []byte) error {
	if len(body) > dvripMaxBody {
		return fmt.Errorf("dahua dvrip body too large: %d", len(body))
	}
	var header [dvripHeaderLen]byte
	binary.BigEndian.PutUint32(header[0:4], command)
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(body)))
	binary.BigEndian.PutUint64(header[24:32], magic)
	if len(nonce) > 16 {
		return fmt.Errorf("dahua dvrip nonce too large: %d", len(nonce))
	}
	copy(header[8:24], nonce)

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

func readDVRIPResponse(r io.Reader) (header []byte, body []byte, err error) {
	header = make([]byte, dvripHeaderLen)
	if _, err = io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}
	if !isDVRIPResponse(header) {
		return header, nil, nil
	}
	// 长度字段是小端(实测: 响应头 offset 4 的 "37 00 00 00" = 55 字节)。
	n := binary.LittleEndian.Uint32(header[4:8])
	if n > dvripMaxBody {
		return nil, nil, errors.New("dahua dvrip response body too large")
	}
	if n == 0 {
		return header, nil, nil
	}
	body = make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	return header, body, nil
}

// isDVRIPResponse accepts the two binary reply headers used by the login
// handshake. A JSON (F6) reply is not part of this exchange.
func isDVRIPResponse(header []byte) bool {
	if len(header) < 2 {
		return false
	}
	return (header[0] == 0xb0 && header[1] == 0x00) ||
		(header[0] == 0xb0 && header[1] == 0x01)
}

// parseDVRIPRealm extracts the realm line and the random value from the text
// body returned for the A0 05 challenge request.
//
// A typical body is:
//
//	Realm:Login to 107FF8439AEE329B\r\n
//	Random:2868712580d\r\n
//	\r\n
//
// realm 是 "Realm:" 之后的**整段文本**(含 "Login to " 前缀), random 是
// "Random:" 之后到行尾那一段。
//
// 注意: realm 必须保留 "Login to " 前缀。NetSDK 拼 HA1 时的输入实测是
// "admin:Login to AAAABBBBCCCCDDDD:admin123", 之前把前缀剥掉只取
// "AAAABBBBCCCCDDDD" 算出来的摘要和设备期望的完全对不上, 登录必失败。
func parseDVRIPRealm(body []byte) (realm, random string, ok bool) {
	s := string(body)

	// 按行解析, 避免被正文里其它冒号带偏。
	realm, random = "", ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "Realm:"):
			realm = strings.TrimSpace(strings.TrimPrefix(line, "Realm:"))
		case strings.HasPrefix(line, "Random:"):
			random = strings.TrimSpace(strings.TrimPrefix(line, "Random:"))
		}
	}
	if realm == "" || random == "" {
		// 兼容没有 "Realm:"/"Random:" 前缀的老格式: 整段文本即 realm,
		// 最后一个冒号之后即 random。
		if start := strings.Index(s, "Login to"); start >= 0 {
			lineEnd := strings.Index(s[start:], "\r\n")
			if lineEnd < 0 {
				lineEnd = strings.IndexByte(s[start:], '\n')
			}
			if lineEnd >= 0 {
				realm = strings.TrimSpace(s[start : start+lineEnd])
			}
		}
		if colon := strings.LastIndex(s, ":"); colon >= 0 && colon+1 < len(s) {
			rest := strings.TrimLeft(s[colon+1:], " \t")
			end := len(rest)
			for i := 0; i < len(rest); i++ {
				if rest[i] == '\r' || rest[i] == '\n' || rest[i] == ' ' || rest[i] == '\t' {
					end = i
					break
				}
			}
			random = strings.TrimSpace(rest[:end])
		}
	}
	if realm == "" || random == "" {
		return "", "", false
	}
	return realm, random, true
}

// ---------- 摘要计算 ----------

// dvripLoginHash builds "username&&<h1><h2>" exactly as the DVRIP login flow
// expects.
//
// 公式由 NetSDK 实际行为还原(用 LD_PRELOAD 拦截 SDK 内部的 std::string
// 构造, 读到摘要输入原文):
//
//	HA1 = UPPER(MD5(user + ":" + realm + ":" + password))
//	H1  = UPPER(MD5(user + ":" + random + ":" + HA1))
//	H2  = UPPER(MD5(user + ":" + random + ":" + gen1(password)))
//	body = user + "&&" + H1 + H2
//
// 其中 realm 是设备 challenge 的原文(含 "Login to " 前缀), gen1 是大华的
// 8 位老摘要。H1/H2 各自 32 位大写 hex, 拼接后共 64 位。
//
// 该公式在 8 组独立抓包(2 个口令 / 3 个 realm / 3 个 random, 含真机)上
// 逐字节复现成功。
func dvripLoginHash(username, password, realm, random string) string {
	ha1 := md5Upper(username + ":" + realm + ":" + password)
	h1 := md5Upper(username + ":" + random + ":" + ha1)
	gen1 := dahuaGen1Hash(password)
	h2 := md5Upper(username + ":" + random + ":" + gen1)
	return username + "&&" + h1 + h2
}

func md5Upper(s string) string {
	sum := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// dahuaGen1Hash is the 8-character Dahua old-digest password hash. It maps
// adjacent MD5 bytes into the [0-9A-Za-z] alphabet.
func dahuaGen1Hash(password string) string {
	sum := md5.Sum([]byte(password))
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		v := (int(sum[2*i]) + int(sum[2*i+1])) % 62
		switch {
		case v < 10:
			v += 48 // '0'..'9'
		case v < 36:
			v += 55 // 'A'..'Z'
		default:
			v += 61 // 'a'..'z'
		}
		out[i] = byte(v)
	}
	return string(out)
}

// ---------- 错误码三态划分 ----------

// AttemptClass 与 dahuasdk worker 的 attemptClass 语义一致。
type AttemptClass int

const (
	AttemptFail      AttemptClass = iota // 普通失败, 继续字典
	AttemptTransient                     // 连接/资源类失败
	AttemptLocked                        // 账号锁定/禁止登录, 停止该设备
)

// 与 cmd/sdk/dahuasdk/run_linux.go 对齐的错误码。
const (
	ErrPwdNotCorrect  int32 = 100
	ErrAccountNoExist int32 = 101
	ErrTimeout        int32 = 102
	ErrAccountLocked  int32 = 104
	ErrBlocklist      int32 = 105
	ErrConnectTimeout int32 = 107
	ErrNetConnectFail int32 = 108
	ErrExceedMaxConn  int32 = 110
	ErrIPNoAuthorized int32 = 113
	ErrNotInit        int32 = 118

	ErrAccountLockedN int32 = 5
	ErrBlocklistN     int32 = 6
	ErrDeviceBusyN    int32 = 7
	ErrSubConnectN    int32 = 8
	ErrHostConnectN   int32 = 9
	ErrMaxConnectN    int32 = 10
	ErrNoAuthorizedN  int32 = 13
	ErrNotInitN       int32 = 18
	ErrLoginTimeoutN  int32 = 3
)

// ClassifyCode 复刻 classifyErrorCode 的三态划分。
func ClassifyCode(code int32) AttemptClass {
	switch code {
	case ErrAccountLockedN, ErrBlocklistN, ErrNoAuthorizedN, ErrNotInitN,
		ErrAccountLocked, ErrBlocklist, ErrIPNoAuthorized, ErrNotInit:
		return AttemptLocked
	case ErrLoginTimeoutN, ErrDeviceBusyN, ErrSubConnectN, ErrHostConnectN, ErrMaxConnectN,
		ErrTimeout, ErrConnectTimeout, ErrNetConnectFail, ErrExceedMaxConn:
		return AttemptTransient
	default:
		return AttemptFail
	}
}

// ---------- 设备级状态:连续连接失败计数 ----------

// 语义与被替换掉的 dahuasdk(NetSDK worker)包保持一致:
//   - 单次连接失败只算"这次没打中",引擎继续跑该设备剩余字典;
//   - 连续 unreachableThreshold 次连接失败才判 Unreachable,引擎静默收掉该设备。
//
// 直接把单次失败判成 Unreachable 会让一次网络抖动/设备瞬断被误判成
// "设备不可达",从而丢掉该设备后续的字典命中(假阴性)。
//
// 计数按 "ip:port" 归集,跨凭据组合累计,任务之间由 ClearDeviceState 清理。
const unreachableThreshold = 3

// deviceState key "ip:port" → *int32 连续连接失败计数。
var deviceState sync.Map

// recordConnectFail 记一次连接失败,连续失败达阈值返回 true(设备判定 Unreachable)。
func recordConnectFail(key string) bool {
	v, _ := deviceState.LoadOrStore(key, new(int32))
	n := atomic.AddInt32(v.(*int32), 1)
	return int(n) >= unreachableThreshold
}

// resetConnectFail 清零该设备的连续连接失败计数(登录有响应即视为设备在线)。
func resetConnectFail(key string) {
	deviceState.Delete(key)
}

// ClearDeviceState 清空设备状态缓存,peaker clearScanCache 调用,避免跨任务污染。
func ClearDeviceState() {
	deviceState.Range(func(k, _ any) bool {
		deviceState.Delete(k)
		return true
	})
}
