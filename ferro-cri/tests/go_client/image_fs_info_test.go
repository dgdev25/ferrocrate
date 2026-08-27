package go_client

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestImageFsInfoDecodesWithGoGRPCClient(t *testing.T) {
	t.Parallel()
	runtime := t.TempDir()
	socket := filepath.Join(runtime, "cri.sock")
	binary := os.Getenv("FERRO_CRI_BINARY")
	if binary == "" {
		binary = filepath.Join("..", "..", "..", "target", "debug", "ferro-cri")
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "FERROCRATE_HOME="+runtime, "FERROCRATE_CRI_SOCKET="+socket)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ferro-cri: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return net.Dial("unix", socket)
		}),
	)
	if err != nil {
		t.Fatalf("dial ferro-cri: %v", err)
	}
	defer conn.Close()

	response, err := runtimeapi.NewImageServiceClient(conn).ImageFsInfo(ctx, &runtimeapi.ImageFsInfoRequest{})
	if err != nil {
		t.Fatalf("ImageFsInfo must decode with google.golang.org/grpc: %v", err)
	}
	if len(response.ImageFilesystems) != 1 {
		t.Fatalf("got %d image filesystems, want 1", len(response.ImageFilesystems))
	}
	if response.ImageFilesystems[0].FsId == nil || response.ImageFilesystems[0].FsId.Mountpoint == "" {
		t.Fatalf("missing filesystem identifier: %#v", response.ImageFilesystems[0])
	}
}
