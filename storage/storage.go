// Package storage 制品字节的存放与读取。
//
// 内网节点的默认形态是本地磁盘（一个数据目录即备份单元）；接口留出来是为了
// 后续接对象存储（Ceph RGW / MinIO）时不动上层代码。
package storage

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Storage 字节存储抽象。
type Storage interface {
	// Put 写入字节，返回可对外访问的地址。
	Put(name string, data []byte) (string, error)
	// Open 读取字节（用于本节点下载与 master 代理 worker 的字节流）。
	Open(name string) (io.ReadCloser, int64, error)
	// Delete 删除字节。
	Delete(name string) error
	// PublicURL 计算某个已存对象的对外地址。
	PublicURL(name string) string
}

// Local 本地磁盘驱动：字节落在 <dir>/<name>，经 <base>/blobs/<name> 公开。
type Local struct {
	dir  string
	base string
}

// NewLocal 创建本地驱动。
func NewLocal(dir, publicBase string) (*Local, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Local{dir: dir, base: strings.TrimRight(publicBase, "/")}, nil
}

// safeName 防目录穿越：只允许“干净的相对路径”。
//
// 对象名是**斜杠分隔**的标识：它会进 URL（PublicURL），也会在 master / worker
// 之间原样传递（clusterwrite）。所以一律按 path 而不是 filepath 处理 ——
// filepath.Clean 在 Windows 上会把 "/a" 变成 "\a"，TrimPrefix 再剥不掉那个
// 反斜杠，于是 PublicURL 产出 "…/blobs/\a" 这种非法地址。
func safeName(name string) (string, error) {
	// 反斜杠与冒号只可能来自越权输入（Windows 上分别代表分隔符与盘符/ADS）。
	if name == "" || strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("非法对象名 %q", name)
	}
	clean := path.Clean("/" + name)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("非法对象名 %q", name)
	}
	return clean, nil
}

func (l *Local) path(name string) (string, error) {
	clean, err := safeName(name)
	if err != nil {
		return "", err
	}
	// 只有落盘这一步才换成宿主机的分隔符。
	return filepath.Join(l.dir, filepath.FromSlash(clean)), nil
}

// Put 落盘（原子写：先写临时文件再 rename）。
func (l *Local) Put(name string, data []byte) (string, error) {
	p, err := l.path(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", err
	}
	return l.PublicURL(name), nil
}

func (l *Local) Open(name string) (io.ReadCloser, int64, error) {
	p, err := l.path(name)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

func (l *Local) Delete(name string) error {
	p, err := l.path(name)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (l *Local) PublicURL(name string) string {
	clean, err := safeName(name)
	if err != nil {
		clean = name
	}
	return l.base + "/blobs/" + clean
}
