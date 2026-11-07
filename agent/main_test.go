package main

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestContentTransferProbes(t *testing.T) {
 payload := strings.Repeat("ABCDEFGH",8192)
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/short" { w.Write([]byte(payload[:16384]));return }
  if r.URL.Path=="/partial" {
   w.Header().Set("Content-Length","65536")
   w.WriteHeader(200)
   w.Write([]byte(payload[:16384]));return
  }
  w.Write([]byte(payload))
 }))
 defer srv.Close()
 for _,tc := range []struct{path,status string;bytes int64}{
  {"/full","OK_FULL",65536},{"/short","SHORT_RESPONSE",16384},{"/partial","PARTIAL_TRANSFER",16384},
 }{
  t.Run(tc.status,func(t *testing.T){
   e:=probe(Target{ID:"test",Type:"http",URL:srv.URL+tc.path,MinBytes:65536,TimeoutSec:5})
   if e.Status!=tc.status || e.Bytes!=tc.bytes { t.Fatalf("got status=%s bytes=%d error=%q",e.Status,e.Bytes,e.Error) }
  })
 }
}
