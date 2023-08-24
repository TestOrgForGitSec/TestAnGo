package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/cloudbees-compliance/chlog-go/log"
	service "github.com/cloudbees-compliance/chplugin-go/v0.4.0/servicev0_4_0"
	plugin "github.com/cloudbees-compliance/chplugin-service-go/plugin"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
)

func main() {

	InitConfig()
	netListener := GetNetListener(config.Config.GetString("server.address"), config.Config.GetUint("server.port"))
	gRPCServer := getGrpcServer(config.Config.GetInt("grpc.maxrecvsize"), config.Config.GetInt("service.workerpool.size"), config.Config.GetInt("heartbeat.timer"))

	// start the server
	if err := gRPCServer.Serve(netListener); err != nil {
		log.Panic().Err(err).Msg("failed to serve")
	}
}

func InitConfig() {
	config.InitConfig()
	trackingInfo := map[string]string{"Service": "AnchorePlugin"}
	log.Init(config.Config, trackingInfo)
}

func getGrpcServer(maxrecvSize, workerpoolSize, heartbeatTimer int) *grpc.Server {
	gRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxrecvSize),
		grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
		grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
	)

	chPluginService := plugin.CHPluginServiceBuilder(
		NewAnchoreScanner(),
		workerpoolSize,
		int64(heartbeatTimer),
	)
	service.RegisterCHPluginServiceServer(gRPCServer, chPluginService)
	log.Info().Msgf("Starting: %s", time.Now().Format(time.RFC3339))
	return gRPCServer
}

func GetNetListener(host string, port uint) net.Listener {
	log.Info().Msgf("Binding gRPC server on %s:%d", host, port)
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Panic().Err(err).Msg("failed to listen")
	}
	return lis
}
