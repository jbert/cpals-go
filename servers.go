package cpals

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jbert/cpals-go/hmac"
	"github.com/jbert/cpals-go/sha1"
)

type C31Server struct {
	*http.Server
	key   []byte
	files map[string][]byte
}

func NewC31Server(port int) *C31Server {
	cs := C31Server{
		key:   RandomKey(),
		files: make(map[string][]byte),
	}
	sm := http.NewServeMux()
	sm.HandleFunc("/", cs.C31Handler)
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        sm,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	cs.Server = s
	cs.addFiles()
	return &cs
}

func (cs *C31Server) ListFiles() []string {
	var fnames []string
	for k, _ := range cs.files {
		fnames = append(fnames, k)
	}
	return fnames
}

func (cs *C31Server) addFiles() {
	cs.files["hamlet"] = Hamlet
	cs.files["ice"] = []byte("ICE ICE BABY")
}

func (cs *C31Server) C31Handler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fs := r.Form["file"]
	ss := r.Form["signature"]

	h := hmac.New(sha1.New, cs.key)
	fileContents, ok := cs.files[fs[0]]
	if !ok {
		http.Error(w, "File not found", http.StatusInternalServerError)
		return
	}
	h.MustWrite(fileContents)
	d := h.Sum(nil)
	sigStr, err := DeHex(HexStr(ss[0]))
	if err != nil {
		http.Error(w, fmt.Sprintf("Bad hex sig: %s", err), http.StatusBadRequest)
		return
	}
	//	fmt.Printf("Compare %s - %s\n", EnHex(d), EnHex(sigStr))
	signatureGood := InsecureCompare(d, sigStr)
	if signatureGood {
		http.Error(w, "All is good", http.StatusOK)
		return
	} else {
		http.Error(w, "Bad sig", http.StatusInternalServerError)
		return
	}
}

func (cs *C31Server) MustStart() {
	go func() {
		err := cs.ListenAndServe()
		if err != http.ErrServerClosed {
			panic(fmt.Sprintf("Server error: %s", err))
		}
	}()
}
