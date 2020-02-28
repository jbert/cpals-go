package diffie

import (
	"fmt"
	"math/big"

	"github.com/jbert/cpals-go"
	cbig "github.com/jbert/cpals-go/big"
)

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

var nistG = big.NewInt(2)

type Request struct {
	p *big.Int
	g *big.Int

	A *big.Int
}

type Reply struct {
	B *big.Int
}

type Server interface {
	Handshake(Request) Reply
	Call([]byte) []byte
}

type Cryptor struct {
	g, p, a, A, B *big.Int
}

func (c Cryptor) SessionKey() []byte {
	s := cbig.BigExpMod(c.a, c.B, c.p)
	hashS := cpals.SHA1(s.Bytes())
	if len(hashS) < 16 {
		panic(fmt.Sprintf("Unexpected hash key length: %d", len(hashS)))
	}
	return hashS[0:16]
}

func (c Cryptor) Encrypt(s string) []byte {
	msg := []byte(s)
	key := c.SessionKey()
	iv := cpals.RandomKey()
	fmt.Printf("ENC: key [%s] iv [%s]", cpals.EnHex(key), cpals.EnHex(iv))
	buf := cpals.AESCBCEncrypt(key, iv, msg)
	return append(buf, iv...)
}

func (c Cryptor) Decrypt(buf []byte) string {
	key := c.SessionKey()
	iv := buf[len(buf)-len(key):]
	buf = buf[:len(buf)-len(iv)]
	fmt.Printf("DEC: key [%s] iv [%s]", cpals.EnHex(key), cpals.EnHex(iv))
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

	return &HonestClient{
		Cryptor: Cryptor{
			g: g,
			p: p,
			a: a,
			A: A,
		},
	}
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
	p := nistP
	g := nistG

	a := cbig.BigRand(p)
	A := cbig.BigExpMod(g, a, p)

	return &HonestServer{
		Cryptor: Cryptor{
			a: a,
			A: A,
		},
		Replies: map[string]string{
			"default": "Not initialised :-(",
		},
	}
}

func (hs *HonestServer) Handshake(hello Request) Reply {
	hs.g = hello.g
	hs.p = hello.p
	// My remote pubkey is your local pubkey
	hs.B = hello.A
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
