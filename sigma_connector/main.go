package main

import (
    "context"
    "log"
    "net"

    // Sigma 룰 엔진 (go-sigma-rule-engine)
    sigma "github.com/markuskont/go-sigma-rule-engine" // :contentReference[oaicite:4]{index=4}

    // OTLP Trace 프로토 정의
    tracepb  "go.opentelemetry.io/proto/otlp/collector/trace/v1"
    commonpb "go.opentelemetry.io/proto/otlp/common/v1"

    "google.golang.org/grpc"
)

// MapEvent은 go-sigma-rule-engine의 Event 인터페이스를 구현하기 위한 래퍼입니다.
// 내부적으로 map[string]interface{} 을 가지고, selection 룰용 Select 메서드를 제공합니다.
type MapEvent map[string]interface{}

func (m MapEvent) Keywords() ([]string, bool) {
    // 우리는 키워드(keyword) 룰을 사용하지 않으므로 무조건 false를 반환합니다.
    return nil, false
}

func (m MapEvent) Select(key string) (interface{}, bool) {
    // selection 룰이 key→value를 조회할 때 사용됩니다.
    val, ok := m[key]
    return val, ok
}

// server는 OTLP Trace gRPC 서버를 구현하며, 수신된 스팬을 Sigma 룰 엔진에 전달합니다.
type server struct {
    tracepb.UnimplementedTraceServiceServer

    // ruleset: 디렉터리 단위로 로드된 Sigma 룰셋 전체
    ruleset *sigma.Ruleset
}

// Export 메서드: OTLP Trace 요청이 들어올 때마다 호출됩니다.
func (s *server) Export(ctx context.Context, req *tracepb.ExportTraceServiceRequest) (*tracepb.ExportTraceServiceResponse, error) {
    for _, resourceSpans := range req.ResourceSpans {
        for _, scopeSpans := range resourceSpans.ScopeSpans {
            for _, span := range scopeSpans.Spans {
                // 1) span.Attributes를 map[string]interface{}로 변환
                eventMap := make(map[string]interface{})
                for _, attr := range span.Attributes {
                    if x, ok := attr.Value.Value.(*commonpb.AnyValue_StringValue); ok {
                        eventMap[attr.Key] = x.StringValue
                    }
                }

		log.Printf("[DEBUG] Connector received eventMap: %+v\n", eventMap)

                // 2) MapEvent로 래핑
                evt := MapEvent(eventMap)

                // 3) Sigma 룰셋 전체에 대해 매칭 평가 (EvalAll)
                results, matched := s.ruleset.EvalAll(evt)
                if matched {
                    // results는 []sigma.Result 타입 (즉, 매칭된 Rule 정보가 담긴 슬라이스)
                    // 아래 예시에서는 첫 번째 매칭된 룰만 로그에 남깁니다.
                    firstMatch := results[0] // 최소 하나 이상 존재
                    log.Printf("✅ Falco 이벤트 [%v] 가 Sigma 룰 [%s] 과 매칭됨\n",
                        eventMap["falco.rule"], firstMatch.Title)
                }
            }
        }
    }
    return &tracepb.ExportTraceServiceResponse{}, nil
}

func main() {
    // ── 1) Sigma 룰 디렉터리 경로 (로컬 환경에 맞게 수정) ──
    ruleDir := "/home/shlee/Desktop/falco-sigma-pipeline/sigma_connector/rules/rules/linux"

    // ── 2) Sigma 룰셋 전체 로드 ──
    //    Config.Directory는 []string 타입이므로 반드시 슬라이스로 넘겨야 합니다. :contentReference[oaicite:5]{index=5}
    ruleset, err := sigma.NewRuleset(sigma.Config{
        Directory: []string{ruleDir},
    })
    if err != nil {
        log.Fatalf("Sigma 룰셋 로드 실패: %v\n", err)
    }
    log.Printf("✅ Sigma 룰셋 로드 완료: 총 %d개 파일 중 정상 파싱된 룰 %d개 (실패 %d, 지원 안 함 %d)\n",
        ruleset.Total, ruleset.Ok, ruleset.Failed, ruleset.Unsupported)

	// ── 로드된 개별 룰 목록 출력 ──
	for _, tree := range ruleset.Rules {
	// tree.Rule 는 sigma.Tree 내부의 Rule 구조체로, ID와 Title 필드를 가지고 있습니다.
		log.Printf("• Loaded rule → ID: %-20s | Title: %s\n", tree.Rule.ID, tree.Rule.Title)
	}

    // ── 3) gRPC 서버 리스너 생성: 0.0.0.0:55680 ──
    lis, err := net.Listen("tcp", "0.0.0.0:55680")
    if err != nil {
        log.Fatalf("gRPC 리스너 생성 실패: %v\n", err)
    }

    grpcServer := grpc.NewServer()
    // ruleset을 server 구조체에 주입
    tracepb.RegisterTraceServiceServer(grpcServer, &server{ruleset: ruleset})

    log.Println("🚀 Sigma Connector: OTLP(Trace) 서버 기동 중 (0.0.0.0:55680)")
    if serveErr := grpcServer.Serve(lis); serveErr != nil {
        log.Fatalf("gRPC 서버 종료: %v\n", serveErr)
    }
}

