package config

import (
	"strings"

	"github.com/spf13/viper"
)

var Config *viper.Viper

func InitConfig() {
	Config = viper.New()
	Config.SetEnvPrefix("ch")
	Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	Config.AutomaticEnv()

	Config.SetDefault("server.address", "127.0.0.1")
	Config.SetDefault("server.port", 5001)
	Config.SetDefault("anchorectl.exe", "anchorectl")

	Config.SetDefault("service.workerpool.size", 3)
	Config.SetDefault("heartbeat.timer", 45)

	// 1GB max. recv size on grpc by default
	Config.SetDefault("grpc.maxrecvsize", 1024*1024*1024)

	Config.SetDefault("db.log.level", "debug")
	Config.SetDefault("log.colour", false)
	Config.SetDefault("log.callerinfo", false)
	Config.SetDefault("log.level", "debug")
	Config.SetDefault("log.useconsolewriter", false)
	Config.SetDefault("log.unixtime", false)
}
