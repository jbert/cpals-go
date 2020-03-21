package diffie

import (
	"fmt"
	"math/big"

	"github.com/jbert/cpals-go"
	"github.com/jbert/cpals-go/cbig"
)

var nistP = cbig.BigFromHex("25")

/*
var nistP = cbig.BigFromHex(`
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
`)
*/

var nistG = big.NewInt(2)

type Request struct {
	p *big.Int
	g *big.Int

	A *big.Int
}

type Reply struct {
	B *big.Int
}

type Client interface {
	Connect(Server)
}

type Server interface {
	Handshake(Request) Reply
	Call([]byte) []byte
}

type Cryptor struct {
	g, p, a, A, B *big.Int
	role          string
}

func (c Cryptor) String() string {
	return fmt.Sprintf("C: a %s A %s B %s p %s g %s",
		cbig.BigStr(c.a), cbig.BigStr(c.A), cbig.BigStr(c.B), cbig.BigStr(c.p), cbig.BigStr(c.g))
}

func bigIntToKey(n *big.Int) []byte {
	hashN := cpals.SHA1(n.Bytes())
	if len(hashN) < 16 {
		panic(fmt.Sprintf("Unexpected hash key length: %d", len(hashN)))
	}
	key := hashN[0:16]
	//log.Printf("bigIntToKey %s -> %v", n, key)
	return key
}

func (c Cryptor) SessionKey(purpose string) []byte {
	s := cbig.BigExpMod(c.B, c.a, c.p)
	key := bigIntToKey(s)
	//log.Printf("%s: B %s a %s p %s s %s: %v\n", purpose, c.B, c.a, c.p, s, key)
	return key
}

func (c Cryptor) Encrypt(s string) []byte {
	msg := []byte(s)
	key := c.SessionKey(fmt.Sprintf("%s ENC", c.role))
	iv := cpals.RandomKey()
	buf := cpals.AESCBCEncrypt(key, iv, msg)
	return append(buf, iv...)
}

func splitIV(buf []byte, n int) ([]byte, []byte) {
	iv := buf[len(buf)-n:]
	buf = buf[:len(buf)-len(iv)]
	return iv, buf
}

func (c Cryptor) Decrypt(buf []byte) (smsg string) {
	defer func() {
		if r := recover(); r != nil {
			smsg = fmt.Sprintf("Can't decrypt: %s", r)
		}
	}()

	key := c.SessionKey(fmt.Sprintf("%s DEC", c.role))
	iv, buf := splitIV(buf, len(key))
	msg := cpals.AESCBCDecrypt(key, iv, buf)
	return string(msg)
}

type HonestClient struct {
	Cryptor
	server Server
}

func NewHonestClient() *HonestClient {
	p := nistP
	g := nistG

	a := cbig.BigRand(p)
	A := cbig.BigExpMod(g, a, p)

	hc := &HonestClient{
		Cryptor: Cryptor{
			g:    g,
			p:    p,
			a:    a,
			A:    A,
			role: "HC",
		},
	}
	return hc
}

func (hc *HonestClient) Connect(server Server) {
	hc.server = server
	req := Request{
		p: hc.p,
		g: hc.g,
		A: hc.A,
	}
	resp := server.Handshake(req)
	hc.B = resp.B
}

func (hc *HonestClient) Send(buf []byte) []byte {
	return hc.server.Call(buf)
}

type HonestServer struct {
	Cryptor
	Replies map[string]string
}

func NewHonestServer() *HonestServer {
	hs := &HonestServer{
		// Set up cryptor in Handshake
		Replies: map[string]string{
			"default": "Not initialised :-(",
		},
		Cryptor: Cryptor{
			role: "HS",
		},
	}
	return hs
}

func (hs *HonestServer) Handshake(hello Request) Reply {
	// Use negotiated values. That will be safe.
	hs.g = hello.g
	hs.p = hello.p
	// My remote pubkey is your local pubkey
	hs.B = hello.A

	hs.a = cbig.BigRand(hs.p)
	hs.A = cbig.BigExpMod(hs.g, hs.a, hs.p)

	//log.Printf("HS: %s", hs)

	// I reply with my pubkey (A) as the remote pubkey (B)
	return Reply{
		B: hs.A,
	}
}

func (hs *HonestServer) Call(buf []byte) []byte {
	msg := hs.Decrypt(buf)
	reply, ok := hs.Replies[msg]
	if !ok {
		reply, ok = hs.Replies["default"]
		if !ok {
			panic("Replies not initialised....")
		}
	}
	replyBuf := hs.Encrypt(reply)
	return replyBuf
}

type MITM interface {
	Client
	Server
	SnoopedMessages() []string
}

type EvilMITM struct {
	Cryptor
	server Server

	aSavedMessages [][]byte
	bSavedMessages [][]byte
}

func NewEvilMITM() *EvilMITM {
	return &EvilMITM{}
}

func (mitm *EvilMITM) Connect(server Server) {
	mitm.server = server
}

func (mitm *EvilMITM) Handshake(hello Request) Reply {
	mitm.g = hello.g
	mitm.p = hello.p
	mitm.A = hello.A

	evilHandshake := Request{
		p: mitm.p,
		g: mitm.g,
		A: mitm.p,
	}

	reply := mitm.server.Handshake(evilHandshake)
	mitm.B = reply.B
	evilReply := Reply{
		B: mitm.p,
	}
	return evilReply
}

func (mitm *EvilMITM) Call(msg []byte) []byte {
	mitm.aSavedMessages = append(mitm.aSavedMessages, msg)
	reply := mitm.server.Call(msg)
	mitm.bSavedMessages = append(mitm.bSavedMessages, reply)
	return reply
}

func (mitm *EvilMITM) SnoopedMessages() []string {
	var msgs []string
	// Both sides are using pubkey == p
	// key is (B ** a) %p == (p**a) %p == 0
	s := big.NewInt(0)
	key := bigIntToKey(s)

	for _, buf := range mitm.aSavedMessages {
		iv, buf := splitIV(buf, len(key))
		msg := cpals.AESCBCDecrypt(key, iv, buf)
		msgs = append(msgs, string(msg))
	}
	for _, buf := range mitm.bSavedMessages {
		iv, buf := splitIV(buf, len(key))
		msg := cpals.AESCBCDecrypt(key, iv, buf)
		msgs = append(msgs, string(msg))
	}
	return msgs
}

type EvilMITMG struct {
	Cryptor
	server Server

	snoopedMsgs []string
}

func NewEvilMITMG(g *big.Int) *EvilMITMG {
	return &EvilMITMG{Cryptor: Cryptor{g: g, role: "MITMG"}}
}

func (mitm *EvilMITMG) Zero() *big.Int {
	return big.NewInt(0)
}

func (mitm *EvilMITMG) One() *big.Int {
	return big.NewInt(1)
}

func (mitm *EvilMITMG) P() *big.Int {
	return cbig.BigCopy(nistP)
}

func (mitm *EvilMITMG) PMinus1() *big.Int {
	return big.NewInt(0).Sub(nistP, big.NewInt(1))
}

func (mitm *EvilMITMG) Connect(server Server) {
	mitm.server = server
}

func (mitm *EvilMITMG) Handshake(hello Request) Reply {
	mitm.p = hello.p
	mitm.A = hello.A

	evilHandshake := Request{
		p: hello.p,
		g: mitm.g,
		A: hello.A,
	}

	reply := mitm.server.Handshake(evilHandshake)
	mitm.B = reply.B
	//log.Printf("MITMG: A %s B %s", mitm.A, mitm.B)
	return reply
}

func (mitm *EvilMITMG) Call(wireMsg []byte) []byte {
	msg := mitm.aDecryptor()(wireMsg)
	mitm.snoopedMsgs = append(mitm.snoopedMsgs, msg)
	buf := mitm.bEncryptor()(msg)

	wireReply := mitm.server.Call(buf)
	reply := mitm.bDecryptor()(wireReply)
	mitm.snoopedMsgs = append(mitm.snoopedMsgs, reply)
	buf = mitm.aEncryptor()(reply)
	return buf
}

func (mitm *EvilMITMG) decryptor(sessionKeyInt *big.Int) func(buf []byte) string {
	return func(buf []byte) (smsg string) {
		defer func() {
			if r := recover(); r != nil {
				smsg = fmt.Sprintf("Can't decrypt: %s", r)
			}
		}()

		iv, buf := splitIV(buf, 16)
		key := bigIntToKey(sessionKeyInt)
		msg := cpals.AESCBCDecrypt(key, iv, buf)
		return string(msg)
	}
}

func (mitm *EvilMITMG) encryptor(sessionKeyInt *big.Int) func(msg string) []byte {
	return func(msg string) []byte {
		iv := cpals.RandomKey()
		key := bigIntToKey(sessionKeyInt)
		buf := cpals.AESCBCEncrypt(key, iv, []byte(msg))
		buf = append(buf, iv...)
		return buf
	}
}

func (mitm *EvilMITMG) aSessionKey() *big.Int {
	switch {
	case cbig.BigEqual(mitm.g, mitm.One()):
		// B is using g==1
		// so b == B == 1
		// so A's session key is B^a == 1^a == 1
		// B's session key is A^b and we don't know b
		return mitm.One()
	case cbig.BigEqual(mitm.g, mitm.P()):
		// g == p, so B == 0
		return mitm.Zero()
	case cbig.BigEqual(mitm.g, mitm.PMinus1()):
		// g == -1, so all modexp == p == +1 or -1
		return mitm.One()
	default:
		panic("unsupported g")
	}
}

func (mitm *EvilMITMG) bSessionKey() *big.Int {
	switch {
	case cbig.BigEqual(mitm.g, mitm.One()):
		// Dunno
		return mitm.One()
	case cbig.BigEqual(mitm.g, mitm.P()):
		// Dunno
		return mitm.One()
	case cbig.BigEqual(mitm.g, mitm.PMinus1()):
		// Dunno
		return mitm.One()
	default:
		panic("unsupported g")
	}
}

func (mitm *EvilMITMG) aDecryptor() func([]byte) string {
	sessionKey := mitm.aSessionKey()
	//log.Printf("MITM DEC aSessionKey %s", sessionKey)
	return mitm.decryptor(sessionKey)
}

func (mitm *EvilMITMG) aEncryptor() func(string) []byte {
	sessionKey := mitm.aSessionKey()
	//log.Printf("MITM ENC aSessionKey %s", sessionKey)
	return mitm.encryptor(sessionKey)
}

func (mitm *EvilMITMG) bDecryptor() func([]byte) string {
	sessionKey := mitm.bSessionKey()
	//log.Printf("MITM DEC bSessionKey %s", sessionKey)
	return mitm.decryptor(sessionKey)
}

func (mitm *EvilMITMG) bEncryptor() func(string) []byte {
	sessionKey := mitm.bSessionKey()
	//log.Printf("MITM ENC bSessionKey %s", sessionKey)
	return mitm.encryptor(sessionKey)
}

func (mitm *EvilMITMG) SnoopedMessages() []string {
	return mitm.snoopedMsgs
}
