package main

import (
	"context"
	"flag"
	"log"
	"net"
	"path/filepath"

	sigma "github.com/markuskont/go-sigma-rule-engine"
	"google.golang.org/grpc"
	_"google.golang.org/grpc/encoding/gzip"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

/* MapEvent — go-sigma-rule-engine Event 인터페이스 래퍼 */
type MapEvent map[string]interface{}

func (m MapEvent) Keywords() ([]string, bool)           { return nil, false }
func (m MapEvent) Select(key string) (interface{}, bool) { v, ok := m[key]; return v, ok }

type server struct {
	collectortracepb.UnimplementedTraceServiceServer
	ruleset *sigma.Ruleset
}

func main() {
	rulesDir := flag.String("rules", "rules/rules/linux", "Sigma 룰 디렉터리")
	listen   := flag.String("listen", ":55680", "OTLP gRPC 수신 주소")
	flag.Parse()

	/* Sigma 룰 로드 */
	rs, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{filepath.Clean(*rulesDir)},
	})
	if err != nil {
		log.Fatalf("Sigma 룰셋 로드 실패: %v", err)
	}
	log.Printf("✅ Sigma 룰 %d개 로드 완료", len(rs.Rules))

	/* gRPC 서버 기동 */
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("리스너 생성 실패: %v", err)
	}
	s := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(s, &server{ruleset: rs})

	log.Printf("🛰️  OTLP Trace 수신 대기 중 → %s", *listen)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("gRPC Serve 오류: %v", err)
	}
}

/* Trace RPC 핸들러 */
func (s *server) Export(
	_ context.Context,
	req *collectortracepb.ExportTraceServiceRequest,
) (*collectortracepb.ExportTraceServiceResponse, error) {
	    if len(req.ResourceSpans) > 0 &&
       len(req.ResourceSpans[0].ScopeSpans) > 0 &&
       len(req.ResourceSpans[0].ScopeSpans[0].Spans) > 0 {
        attrs := req.ResourceSpans[0].ScopeSpans[0].Spans[0].Attributes
        log.Printf("[DEBUG] Incoming attributes: %v", attrs)
    }
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				event := spanToEvent(sp)

				/* 반환값 두 개: results, matched */
				results, matched := s.ruleset.EvalAll(event)
				if matched && len(results) > 0 {
					log.Printf("⚠️  Sigma 매칭!: %s", results[0].Title)
				}
			}
		}
	}
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

/* Span Attributes → MapEvent */
func spanToEvent(sp *tracepb.Span) MapEvent {
	out := make(MapEvent, len(sp.Attributes))
	for _, kv := range sp.Attributes {
		if v := kv.GetValue().GetStringValue(); v != "" {
			out[kv.Key] = v
		}
	}
	return out
}

