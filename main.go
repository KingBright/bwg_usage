package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

func bwgHandler(w http.ResponseWriter, r *http.Request) {
	veid := os.Getenv("VEID")
	apiKey := os.Getenv("API_KEY")
	if veid == "" || apiKey == "" {
		http.Error(w, "未配置VEID或API_KEY环境变量", http.StatusInternalServerError)
		return
	}
	apiUrl := "https://api.64clouds.com/v1/getServiceInfo?veid=" + veid + "&api_key=" + apiKey

	resp, err := http.Get(apiUrl)
	if err != nil {
		http.Error(w, "请求搬瓦工API失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	// 静态文件目录
	staticDir := "./static"
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	fullPath := filepath.Join(staticDir, filepath.Clean(path))
	// 防止路径穿越
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func main() {
	// 显式加载.env文件
	_ = godotenv.Load(".env")

	http.HandleFunc("/api/bwg", bwgHandler)
	http.HandleFunc("/", staticHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
