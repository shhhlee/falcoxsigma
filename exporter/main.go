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
    "strings"
    "syscall"
    "time"

    // Falco Modern BPF Go client
    "github.com/falcosecurity/client-go/pkg/api/outputs"
    "github.com/falcosecurity/client-go/pkg/client"

    // OpenTelemetry Tracing API/SDK + OTLP exporter
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
    "go.opentelemetry.io/otel/trace"
)

func main() {
    // 1) Falco socket 구독 설정
    falcoSocket := "unix:///run/falco/falco.sock"
    ctxDial, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    falcoClient, err := client.NewForConfig(ctxDial, &client.Config{UnixSocketPath: falcoSocket})
    if err != nil {
        log.Fatalf("Falco client 연결 실패: %v", err)
    }
    defer falcoClient.Close()

    // 2) OTLP endpoint
    otlpEndpoint := "localhost:55680"
    tp, err := initTracerProvider(otlpEndpoint)
    if err != nil {
        log.Fatalf("TracerProvider 초기화 실패: %v", err)
    }
    defer func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := tp.Shutdown(ctx); err != nil {
            log.Printf("TracerProvider 종료 실패: %v", err)
        }
    }()

    tracer := otel.Tracer("falco-otlp-exporter")

    // 3) JSONL 파일 준비
    baseDir := "/home/shlee/Desktop/falcoxsigma/exporter/events"
    os.MkdirAll(baseDir, 0755)
    f, err := os.OpenFile(filepath.Join(baseDir, "events.jsonl"),
        os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("이벤트 파일 열기 실패: %v", err)
    }
    defer f.Close()

    // 4) 종료 신호 처리
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)


    log.Println("▶▶ 이벤트 수신 시작")
    if err := falcoClient.OutputsWatch(context.Background(),
    	func(res *outputs.Response) error {
		log.Printf("[DEBUG exporter] Watch event: rule=%s, output_fields=%v\n",res.Rule, res.OutputFields)
		handleFalcoEvent(res, tracer, f)
		return nil
	},
	time.Second*5,
    ); err != nil {
	    log.Fatalf("OutputsWatch error: %v", err)
    }
    <-sigCh
    log.Println("종료 신호 수신, Exporter 중단")
    os.Exit(0)
}

func flushQueued(client outputs.ServiceClient, tracer trace.Tracer, f *os.File) error {
    stream, err := client.Get(context.Background(), &outputs.Request{})
    if err != nil {
        return err
    }
    for {
        res, err := stream.Recv()
        if err == io.EOF {
            log.Println("Get() 큐 플러시 완료")
            return nil
        }
        if err != nil {
            return err
        }
        handleFalcoEvent(res, tracer, f)
    }
}

func handleFalcoEvent(res *outputs.Response, tracer trace.Tracer, f *os.File) {
    raw, _ := json.Marshal(res)
    f.WriteString(string(raw) + "\n")
    f.Sync()
    log.Println("✅ 이벤트 파일에 기록됨")

    var parsed map[string]interface{}
    if err := json.Unmarshal(raw, &parsed); err != nil {
        log.Printf("JSON 파싱 실패: %v", err)
        return
    }

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
            if k == "fd.name" {
                attrs = append(attrs, attribute.String("TargetFilename", fmt.Sprintf("%v", v)))
            }
            if k == "proc.cmdline" {
                parts := strings.Fields(fmt.Sprintf("%v", v))
                if len(parts) > 0 {
                    attrs = append(attrs, attribute.String("Image", parts[0]))
                }
            }
        }
    }

    _, span := tracer.Start(context.Background(), "falco.event",
        trace.WithAttributes(attrs...),
    )
    span.End()
    log.Println("✅ OTLP Span 전송됨")
}

func initTracerProvider(endpoint string) (*sdktrace.TracerProvider, error) {
    ctx := context.Background()
    exporter, err := otlptracegrpc.New(ctx,
        otlptracegrpc.WithEndpoint(endpoint),
        otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, fmt.Errorf("Exporter 생성 실패: %w", err)
    }
    res, err := resource.New(ctx,
        resource.WithAttributes(semconv.ServiceNameKey.String("falco-otlp-exporter")),
    )
    if err != nil {
        return nil, fmt.Errorf("Resource 생성 실패: %w", err)
    }
    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter,
            sdktrace.WithMaxExportBatchSize(512),
            sdktrace.WithBatchTimeout(200*time.Millisecond),
        ),
        sdktrace.WithResource(res),
    )
    otel.SetTracerProvider(tp)
    return tp, nil
}

