// Command ncc-registry 起一个内网托管节点。
//
// 配置全部来自环境变量（NCCR_*），都有可用默认值 —— 裸跑就是一个能用的单节点：
//
//	NCCR_PORT=8282 ./ncc-registry
//	NCCR_ROLE=worker NCCR_MASTER_URL=http://office-master:8282 ./ncc-registry
//
// 想把同一套能力嵌进自己的进程，用 httpapi.NewServer（见 README 的 "Using it as a Go library"）。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/fusedmodel/ncc-registry/config"
	"github.com/fusedmodel/ncc-registry/httpapi"
	"github.com/fusedmodel/ncc-registry/storage"
	"github.com/fusedmodel/ncc-registry/store"
)

func main() {
	// gin 的模式由宿主决定：库自己不设，免得替嵌入方做决定；二进制这边要安静。
	gin.SetMode(gin.ReleaseMode)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("配置有误: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	blob, err := storage.NewLocal(cfg.BlobDir, cfg.PublicURL)
	if err != nil {
		log.Fatalf("初始化制品存储失败: %v", err)
	}

	srv, handler := httpapi.NewServer(cfg, st, blob)
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
		// 挡住「连上就不发请求」的连接；内容体大小由各接口自己限制。
		ReadHeaderTimeout: 10 * time.Second,
	}

	banner(cfg)

	// 优雅退出：SIGINT / SIGTERM 时先让在途请求收尾，再收后台循环（defer srv.Close）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("监听 %s 失败: %v", cfg.Addr, err)
		}
	}()

	<-ctx.Done()
	log.Printf("收到退出信号，正在收尾…")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("在途请求未能干净收尾: %v", err)
	}
	log.Printf("已退出")
}

// banner 打印一张启动卡：这台机器是谁、监听在哪、数据落在哪、控制台怎么进。
//
// 这里**不打印管理员凭据** —— 首个账号注册时由 httpapi 打印一次，那是既有的接口行为，
// 二进制不该替它重复实现。
func banner(cfg *config.Config) {
	where := ""
	if cfg.NodeRegion != "" {
		where = " region=" + cfg.NodeRegion
	}
	log.Printf("ncc-registry · role=%s node=%s%s id=%s", cfg.Role, cfg.NodeName, where, cfg.NodeID)
	if cfg.Role == config.RoleWorker {
		log.Printf("  边缘托管点：注册到 master %s（每 %s 心跳一次）", cfg.MasterURL, cfg.HeartbeatEvery)
	} else {
		log.Printf("  权威节点：账号 / 制品 / 节点目录都以本节点为准")
	}
	log.Printf("  监听     %s（对外地址 %s）", cfg.Addr, cfg.PublicURL)
	log.Printf("  数据目录 %s", cfg.DataDir)
	log.Printf("  数据库   %s", cfg.DBPath)
	log.Printf("  字节目录 %s", cfg.BlobDir)
	if cfg.Console {
		log.Printf("  控制台   %s/  （本节点第一个注册的账号自动成为管理员）", cfg.PublicURL)
	}
}
