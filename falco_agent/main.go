package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.22.0"
	"go.opentelemetry.io/otel/trace"
)

/* Option */
var (
	falcoSock   = flag.String("falco-sock", "unix:///run/falco/falco.sock", "Falco gRPC 소켓")
	otelEP      = flag.String("otel-endpoint", "localhost:4317", "OTLP Collector 주소")
	serviceName = flag.String("service-name", "falco-exporter", "OTEL 서비스 이름")
)

func main() {
	flag.Parse()

	/* Falco Modern-BPF 클라이언트 연결 */
	ctxDial, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fCli, err := client.NewForConfig(ctxDial, &client.Config{UnixSocketPath: *falcoSock})
	check(err, "Falco client 연결 실패")
	defer fCli.Close()

	/* OTLP TracerProvider */
	tp, tracer := initTracerProvider(*otelEP, *serviceName)
	defer shutdown(tp)

	/* 종료 시그널 */
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Println("▶▶ 이벤트 수신 시작")
	/* OutputsWatch 실시간 구독 */
	go func() {
		if err := fCli.OutputsWatch(context.Background(),
			func(res *outputs.Response) error {
				handleEvent(res, tracer, tp)
				return nil
			}, 5*time.Second,
		); err != nil {
			log.Fatalf("OutputsWatch 오류: %v", err)
		}
	}()

	<-stop
	log.Println("종료 신호 수신, Exporter 종료")
}

/* ───────────── 이벤트 → JSONL + OTLP Span ──────────────── */
func handleEvent(res *outputs.Response, tracer trace.Tracer, tp *sdktrace.TracerProvider) {

	/* Attribute 매핑 */
	var attrs []attribute.KeyValue

	switch fields := any(res.OutputFields).(type) {
	case map[string]string:
		for k, s := range fields {
			attrs = append(attrs, attribute.String(k, s))
		}
	case map[string]interface{}:
		for k, v := range fields {
			if s, ok := v.(string); ok {
				attrs = append(attrs, attribute.String(k, s))
			}
		}
	}

	/* Span 생성 → Collector 전송 */
	ctx, span := tracer.Start(context.Background(), "falco.event", trace.WithAttributes(attrs...))
	span.End()
	if err := tp.ForceFlush(ctx); err != nil {
		log.Printf("❌ Span 전송 실패")
	} else {
		log.Printf("✅ Span 전송")
	}
}

func initTracerProvider(endpoint, svc string) (*sdktrace.TracerProvider, trace.Tracer) {
	ctx := context.Background()
	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	check(err, "OTLP exporter 생성 실패")

	res, _ := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceNameKey.String(svc),
	))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp, otel.Tracer(svc)
}

func shutdown(tp *sdktrace.TracerProvider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tp.Shutdown(ctx)
}

func check(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
