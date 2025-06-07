package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"

    // Falco Modern BPF Go 클라이언트
    "github.com/falcosecurity/client-go/pkg/api/outputs"
    "github.com/falcosecurity/client-go/pkg/client"

    // OpenTelemetry Tracing API·SDK + OTLP Tracing 익스포터
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
    otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/trace" // ← WithAttributes를 위해 import

    // gRPC 연결(insecure)
)

func main() {
    // ── 1) Falco Modern BPF(Unix 소켓) 구독 설정 ──
    falcoSocket := "unix:///run/falco/falco.sock"

    ctxDial, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancelDial()

    falcoClient, err := client.NewForConfig(ctxDial, &client.Config{
        UnixSocketPath: falcoSocket,
    })
    if err != nil {
        log.Fatalf("Falco 클라이언트 연결 실패: %v\n", err)
    }
    defer falcoClient.Close()

    outputsClient, err := falcoClient.Outputs()
    if err != nil {
        log.Fatalf("Falco Outputs 클라이언트 생성 실패: %v\n", err)
    }
    falcoStream, err := outputsClient.Get(context.Background(), &outputs.Request{})
    if err != nil {
        log.Fatalf("Falco 이벤트 구독 실패: %v\n", err)
    }

    // ── 2) OTLP(Tracing) 전송 엔드포인트 ──
    otlpEndpoint := "localhost:55680"

    // ── 3) OpenTelemetry TracerProvider 초기화 (OTLP Tracing 익스포터) ──
    tp, err := initTracerProvider(otlpEndpoint)
    if err != nil {
        log.Fatalf("OTLP Tracing TracerProvider 초기화 실패: %v\n", err)
    }
    // 프로그램 종료 시 반드시 Shutdown을 호출하여 모든 스팬이 전송되도록 함
    defer func() {
        ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := tp.Shutdown(ctxShutdown); err != nil {
            log.Printf("TracerProvider 종료 실패: %v\n", err)
        }
    }()

    // 트레이서를 얻어옴 (Falco 이벤트마다 Start/End 호출)
    tracer := otel.Tracer("falco-otlp-exporter")

    // ── 4) 이벤트를 JSON 파일에 기록할 디렉터리 준비 ──
    baseDir := "/home/shlee/Desktop/falco-sigma-pipeline/exporter/events"
    if err := os.MkdirAll(baseDir, 0755); err != nil {
        log.Fatalf("로그 디렉터리 생성 실패: %v\n", err)
    }
    eventFile := filepath.Join(baseDir, "events.jsonl")
    f, err := os.OpenFile(eventFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("이벤트 파일 열기 실패: %v\n", err)
    }
    defer f.Close()

    // ── 5) 종료 신호 처리(Ctrl+C 등) ──
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    log.Println("🔄 Falco 이벤트 구독 및 OTLP(Tracing) 송신 대기 중...")

    // ── 6) 고루틴: Falco 이벤트 수신 → 파일 기록 + OTLP(Tracing) 전송 ──
    go func() {
        for {
            res, err := falcoStream.Recv()
            if err != nil {
                if err == io.EOF {
                    log.Println("Falco 스트림이 종료되었습니다.")
                    return
                }
                log.Printf("Falco 스트림 수신 오류: %v\n", err)
                return
            }

            // (가) Falco 이벤트를 JSON으로 직렬화하여 파일에 한 줄씩 기록
            rawJSON, err := json.Marshal(res)
            if err != nil {
                log.Printf("JSON 직렬화 실패: %v\n", err)
                continue
            }
            if _, err := f.WriteString(string(rawJSON) + "\n"); err != nil {
                log.Printf("파일 쓰기 오류: %v\n", err)
            }
            f.Sync()
            log.Println("✅ Falco 이벤트가 파일에 기록됨")

            // (나) OTLP(Tracing) 스팬으로 전송
            var parsed map[string]interface{}
            if err := json.Unmarshal(rawJSON, &parsed); err != nil {
                log.Printf("JSON 파싱 실패: %v\n", err)
                continue
            }

            // Falco 이벤트에서 주요 필드를 속성(attributes)으로 추출
            attrs := []attribute.KeyValue{
                attribute.String("falco.rule", fmt.Sprintf("%v", parsed["rule"])),
                attribute.String("falco.priority", fmt.Sprintf("%v", parsed["priority"])),
                attribute.String("falco.source", fmt.Sprintf("%v", parsed["source"])),
                attribute.String("falco.output", fmt.Sprintf("%v", parsed["output"])),
            }

	    if of, ok := parsed["output_fields"].(map[string]interface{}); ok {
		    for k, v := range of {
			    switch val := v.(type) {
			    case string:
				attrs = append(attrs, attribute.String(k, val))
				if k == "proc.name" {
					attrs = append(attrs, attribute.String("Image", val))
				}
				if k == "evt.arg.filename" {
					attrs = append(attrs, attribute.String("TargetFilename", val))
				}
			    case float64:
				attrs = append(attrs, attribute.Int(k, int(val)))
        		    default:
            			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", val)))
			    }	
		    }
	    }

            // ↓ 여기서 sdktrace.WithAttributes 가 아니라 trace.WithAttributes 를 사용해야 합니다.
            ctxSpan := context.Background()
            _, span := tracer.Start(ctxSpan, "falco.event",
                trace.WithAttributes(attrs...),
            )
            span.End()

            log.Println("✅ OTLP(Tracing) 스팬이 Sigma Connector로 전송됨")
        }
    }()

    <-sigCh
    log.Println("종료 신호 수신, Falco Exporter 종료 중...")
}

// initTracerProvider: OTLP(Tracing) 전송용 TracerProvider 생성
func initTracerProvider(endpoint string) (*sdktrace.TracerProvider, error) {
    ctx := context.Background()

    // 1) OTLP Tracing 익스포터 생성
    exporter, err := otlptracegrpc.New(ctx,
        otlptracegrpc.WithEndpoint(endpoint),
	otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, fmt.Errorf("OTLP Tracing exporter 생성 실패: %w", err)
    }

    // 2) 서비스 리소스 정보 설정 (예: 서비스 이름)
    res, err := resource.New(ctx,
        resource.WithAttributes(
            semconv.ServiceNameKey.String("falco-otlp-exporter"),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("리소스 생성 실패: %w", err)
    }

    // 3) TracerProvider 초기화: BatchSpanProcessor와 Resource 옵션 설정
    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter,
            sdktrace.WithMaxExportBatchSize(512),
            sdktrace.WithBatchTimeout(200*time.Millisecond),
        ),
        sdktrace.WithResource(res),
    )

    // 4) 전역 TracerProvider로 등록
    otel.SetTracerProvider(tp)

    return tp, nil
}

